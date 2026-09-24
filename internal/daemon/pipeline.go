package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"banhammer/internal/action"
	"banhammer/internal/config"
	"banhammer/internal/metrics"
	"banhammer/internal/model"
	"banhammer/internal/rule"
	"banhammer/internal/source"
	"banhammer/internal/window"
)

// matchEvent is one line that matched, on its way from a worker to the
// aggregator. pattern is the rule that fired, carried through to the ban record
// for the {matched} action variable; it is a compile-time constant string, so
// passing it costs no allocation on the hot path.
type matchEvent struct {
	monitor string
	ip      netip.Addr
	pattern string
}

// enqueue offers ev to the worker queue, dropping the oldest queued event when
// the queue is full (PROJECT.md §6: a log burst must cost accuracy, not memory).
//
// queueMu is held for reading across the send because Run closes d.queue during
// shutdown and a send on a closed channel panics — a plain atomic flag cannot
// close that window, since the flag can be observed as open and the close can
// then happen before the send. Every branch below is non-blocking (the send has
// a default case), so a reader never holds the lock for long and closeQueue
// cannot be starved.
func (d *Daemon) enqueue(ctx context.Context, ev model.Event) bool {
	d.queueMu.RLock()
	defer d.queueMu.RUnlock()
	if d.queueClosed {
		return false
	}
	for {
		select {
		case <-ctx.Done():
			return false
		case d.queue <- ev:
			return true
		default:
			// Queue is saturated: drop the oldest event to prevent OOM
			select {
			case dropped, ok := <-d.queue:
				if ok {
					d.metrics.IncLinesDropped(dropped.Monitor)
				}
			default:
			}
		}
	}
}

// closeQueue shuts the worker queue down so that ranging workers terminate. It
// is idempotent so that a Run that returns early cannot be followed by a
// double-close panic.
func (d *Daemon) closeQueue() {
	d.queueMu.Lock()
	defer d.queueMu.Unlock()
	if d.queueClosed {
		return
	}
	d.queueClosed = true
	close(d.queue)
}

func (d *Daemon) worker() {
	defer d.workerWg.Done()
	for ev := range d.queue {
		d.processEvent(ev)
	}
}

func (d *Daemon) processEvent(ev model.Event) {
	set := d.getRuleSet(ev.Monitor)
	if set == nil {
		d.metrics.IncLinesRead(ev.Monitor)
		return
	}
	res, outcome := set.Match(ev.Raw)
	d.metrics.IncLinesRead(ev.Monitor)
	switch outcome {
	case rule.OutcomeMatch:
		d.metrics.IncMatches(ev.Monitor)
		d.matchCh <- matchEvent{monitor: ev.Monitor, ip: res.IP, pattern: res.Pattern}
	case rule.OutcomeDecodeError:
		d.metrics.IncDecodeErrors(ev.Monitor)
	}
}

func (d *Daemon) aggregator() {
	defer d.aggWg.Done()

	sweepTicker := time.NewTicker(d.sweepInterval)
	defer sweepTicker.Stop()

	for {
		select {
		case m, ok := <-d.matchCh:
			if !ok {
				// Match channel drained on shutdown; perform final sweep
				d.sweepTrackers()
				return
			}
			tr, ok := d.trackers[m.monitor]
			if !ok {
				mon := d.getMonitor(m.monitor)
				if mon == nil {
					// The monitor was removed by a reload between the worker
					// matching this line and us handling it.
					continue
				}
				tr = window.New(mon.Threshold, mon.Window, mon.MaxTracked, d.now)
				d.trackers[m.monitor] = tr
				d.metrics.InitMonitor(m.monitor)
			}
			count, triggered := tr.Hit(m.ip)
			if triggered {
				// Further hits from a banned address change nothing, so stop
				// paying for its counter until it comes back.
				tr.Forget(m.ip)
				d.banManager.Offend(m.monitor, m.ip, count, m.pattern)
			}
			d.metrics.SetTrackedIPs(m.monitor, int64(tr.Len()))

		case <-sweepTicker.C:
			d.sweepTrackers()

		case <-d.sweepReqCh:
			d.sweepTrackers()

		case cfg := <-d.reloadAggCh:
			d.applyTrackerConfig(cfg)
		}
	}
}

// sweepTrackers drops window entries that have aged out, on every monitor.
func (d *Daemon) sweepTrackers() {
	for name, tr := range d.trackers {
		tr.Sweep()
		d.metrics.SetTrackedIPs(name, int64(tr.Len()))
	}
}

// applyTrackerConfig reconciles the trackers with a reloaded config.
//
// A tracker is only rebuilt when its sizing actually changed, because rebuilding
// discards every in-flight counter: reloading a config that only touches, say,
// an allowlist would otherwise hand every half-way-to-banned attacker a clean
// slate. Trackers for monitors the reload removed are dropped outright.
func (d *Daemon) applyTrackerConfig(cfg *config.Config) {
	for name, tr := range d.trackers {
		m, ok := cfg.Monitors[name]
		if !ok {
			delete(d.trackers, name)
			d.metrics.SetTrackedIPs(name, 0)
			continue
		}
		if !tr.SameShape(m.Threshold, m.Window, m.MaxTracked) {
			d.trackers[name] = window.New(m.Threshold, m.Window, m.MaxTracked, d.now)
			d.metrics.SetTrackedIPs(name, 0)
		}
	}
	// Monitors added by the reload get their tracker lazily, on first match.
}

func (d *Daemon) runSource(ctx context.Context, src source.Source) {
	defer d.srcWg.Done()
	srcCh := make(chan model.Event, 64)

	var runWg sync.WaitGroup
	runWg.Add(1)
	go func() {
		defer runWg.Done()
		if err := src.Run(ctx, srcCh); err != nil && !errors.Is(err, context.Canceled) {
			d.log.Error("source run error", "source", src.Name(), "err", err)
		}
		close(srcCh)
	}()

	for {
		select {
		case <-ctx.Done():
			runWg.Wait()
			for ev := range srcCh {
				d.enqueue(context.Background(), ev)
			}
			return
		case ev, ok := <-srcCh:
			if !ok {
				runWg.Wait()
				return
			}
			d.enqueue(ctx, ev)
		}
	}
}

func (d *Daemon) createSource(m *config.Monitor) (source.Source, error) {
	switch {
	case m.File != "":
		return source.NewTail(m.Name, m.File, m.StartAt, d.store, d.log)
	case m.Listen != "":
		return source.NewListener(m.Name, m.Listen, m.StripSyslog, d.log)
	case m.Stdin:
		return source.NewStdin(m.Name, d.stdin, d.log)
	default:
		return nil, fmt.Errorf("monitor %q has no source configured", m.Name)
	}
}

func (d *Daemon) saveOffsets() error {
	offsets := make(map[string]model.Checkpoint)
	for _, src := range d.sources {
		for _, cp := range src.Checkpoints() {
			if cp.Path != "" {
				offsets[cp.Path] = cp
			}
		}
	}
	if len(offsets) == 0 {
		return nil
	}
	return d.store.SaveOffsets(offsets)
}

func toActionSpec(s config.ActionSpec, dryRun bool) action.Spec {
	name := s.Name
	if name == "" {
		name = "iptables"
	}
	chain := s.Chain
	if chain == "" {
		chain = action.DefaultChain
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return action.Spec{
		Name:        name,
		Chain:       chain,
		Start:       s.Start,
		Ban:         s.Ban,
		Unban:       s.Unban,
		Stop:        s.Stop,
		Shell:       s.Shell,
		Timeout:     timeout,
		DryRun:      dryRun,
		FlushOnExit: s.FlushOnExit,
	}
}

func createBackend(cfg *config.Config, r action.Runner, log *slog.Logger, dryRun bool) (action.Backend, error) {
	defaultSpec := toActionSpec(cfg.Defaults.Action, dryRun)
	defaultBackend, err := action.New(defaultSpec, r, log)
	if err != nil {
		return nil, fmt.Errorf("create default action backend %q: %w", defaultSpec.Name, err)
	}

	bySpec := map[action.Spec]action.Backend{
		defaultSpec: defaultBackend,
	}
	monitorBackends := make(map[string]action.Backend)
	for name, m := range cfg.Monitors {
		if m.Action.Name != "" || m.Action.Chain != "" || m.Action.Ban != "" {
			mSpec := toActionSpec(m.Action, dryRun)
			if mSpec != defaultSpec {
				mb, ok := bySpec[mSpec]
				if !ok {
					var err error
					mb, err = action.New(mSpec, r, log)
					if err != nil {
						return nil, fmt.Errorf("create action backend for monitor %q: %w", name, err)
					}
					bySpec[mSpec] = mb
				}
				monitorBackends[name] = mb
			}
		}
	}

	if len(monitorBackends) == 0 {
		return defaultBackend, nil
	}

	return &routerBackend{
		defaultBackend:  defaultBackend,
		monitorBackends: monitorBackends,
	}, nil
}

type routerBackend struct {
	defaultBackend  action.Backend
	monitorBackends map[string]action.Backend
}

func (r *routerBackend) Name() string {
	return r.defaultBackend.Name()
}

func (r *routerBackend) Start(ctx context.Context) error {
	seen := make(map[action.Backend]struct{})
	if err := r.defaultBackend.Start(ctx); err != nil {
		return err
	}
	seen[r.defaultBackend] = struct{}{}
	for _, b := range r.monitorBackends {
		if _, ok := seen[b]; !ok {
			if err := b.Start(ctx); err != nil {
				return err
			}
			seen[b] = struct{}{}
		}
	}
	return nil
}

func (r *routerBackend) Ban(ctx context.Context, b model.Ban) error {
	backend := r.defaultBackend
	if mb, ok := r.monitorBackends[b.Monitor]; ok {
		backend = mb
	}
	return backend.Ban(ctx, b)
}

func (r *routerBackend) Unban(ctx context.Context, b model.Ban) error {
	backend := r.defaultBackend
	if mb, ok := r.monitorBackends[b.Monitor]; ok {
		backend = mb
	}
	return backend.Unban(ctx, b)
}

func (r *routerBackend) Stop(ctx context.Context) error {
	var errs []error
	seen := make(map[action.Backend]struct{})
	if err := r.defaultBackend.Stop(ctx); err != nil {
		errs = append(errs, err)
	}
	seen[r.defaultBackend] = struct{}{}
	for _, b := range r.monitorBackends {
		if _, ok := seen[b]; !ok {
			if err := b.Stop(ctx); err != nil {
				errs = append(errs, err)
			}
			seen[b] = struct{}{}
		}
	}
	return errors.Join(errs...)
}

type metricsBackend struct {
	backend action.Backend
	metrics *metrics.Registry
}

func (b *metricsBackend) Name() string {
	return b.backend.Name()
}

func (b *metricsBackend) Start(ctx context.Context) error {
	err := b.backend.Start(ctx)
	if err != nil {
		b.metrics.IncActionErrors(b.backend.Name())
	}
	return err
}

func (b *metricsBackend) Ban(ctx context.Context, ban model.Ban) error {
	err := b.backend.Ban(ctx, ban)
	if err != nil {
		b.metrics.IncActionErrors(b.backend.Name())
	}
	return err
}

func (b *metricsBackend) Unban(ctx context.Context, ban model.Ban) error {
	err := b.backend.Unban(ctx, ban)
	if err != nil {
		b.metrics.IncActionErrors(b.backend.Name())
	}
	return err
}

func (b *metricsBackend) Stop(ctx context.Context) error {
	err := b.backend.Stop(ctx)
	if err != nil {
		b.metrics.IncActionErrors(b.backend.Name())
	}
	return err
}

// metricsBackend's counters are all that the firewall layer contributes; the
// ban counters themselves are pulled from the ban manager by
// Daemon.syncBanMetrics, because only the manager can tell a new ban from a
// ban that was merely re-applied at startup.
