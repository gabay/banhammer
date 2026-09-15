// Package daemon orchestrates the intrusion prevention pipeline, connecting
// sources, decoders, rule matchers, sliding-window aggregators, ban decisions,
// firewall executors, durable storage, and control plane IPC.
//
// # Architecture
//
// The daemon implements a multi-stage concurrency pipeline (PROJECT.md §3):
//
//   1. Sources: 1 goroutine per input (file tail, socket listener, stdin).
//      Emits model.Event records into the bounded queue.
//   2. Queue: A bounded channel with drop-oldest semantics on overflow to ensure
//      an adversarial log flood never causes unbounded memory consumption.
//   3. Workers: A pool of stateless goroutines (min(4, GOMAXPROCS)) that decode,
//      match regex/JSON rules, extract offending IP addresses, and emit matches.
//   4. Aggregator: Exactly one single-threaded goroutine owning sliding-window
//      hit trackers per monitor. Free of lock contention by construction.
//      Triggers ban evaluations when an offender crosses threshold hits.
//   5. Ban Manager & Action Executor: State machine maintaining the ban table,
//      escalation policies, allowlists, and an unban min-heap with a single timer,
//      delegating firewall mutations to a serialized executor with retries.
//   6. Storage: Durable atomic persistence of bans and read checkpoints.
//   7. Control & Metrics: Unix domain socket IPC control plane and optional
//      Prometheus metrics HTTP server.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"banhammer/internal/action"
	"banhammer/internal/ban"
	"banhammer/internal/config"
	"banhammer/internal/control"
	"banhammer/internal/metrics"
	"banhammer/internal/model"
	"banhammer/internal/rule"
	"banhammer/internal/source"
	"banhammer/internal/store"
	"banhammer/internal/window"
)

// Daemon coordinates log ingestion, pattern matching, threshold tracking,
// firewall enforcement, state persistence, and control-plane IPC.
type Daemon struct {
	cfgMu      sync.RWMutex
	cfg        *config.Config
	configPath string

	log        *slog.Logger
	now        func() time.Time
	runner     action.Runner
	stdin      io.Reader
	dryRun     bool
	queueSize  int
	numWorkers int

	controlSocket    string
	controlSocketSet bool

	offsetInterval time.Duration
	sweepInterval  time.Duration
	interfaces     ban.InterfaceLister

	store      *store.Store
	storeOwned bool

	metrics    *metrics.Registry
	backend    action.Backend
	executor   *action.Executor
	banManager *ban.Manager

	rulesMu sync.RWMutex
	rules   map[string]*rule.Set

	sources  []source.Source
	trackers map[string]*window.Tracker

	queue      chan model.Event
	matchCh    chan matchEvent
	sweepReqCh  chan struct{}
	reloadAggCh chan *config.Config

	controlServer *control.Server
	metricsServer *metrics.Server

	running   atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	reloadMu  sync.Mutex

	aggWg    sync.WaitGroup
	workerWg sync.WaitGroup
	srcWg    sync.WaitGroup
}

// New constructs and initializes a Daemon instance from the provided configuration.
//
// It bootstraps the persistence store, restores existing unexpired bans, compiles
// monitor rules, initializes sliding-window hit trackers, and configures action backends.
func New(cfg *config.Config, opts ...Option) (*Daemon, error) {
	if cfg == nil {
		return nil, errors.New("daemon: config cannot be nil")
	}

	d := &Daemon{
		cfg:            cfg,
		log:            slog.Default(),
		now:            time.Now,
		stdin:          os.Stdin,
		queueSize:      cfg.QueueSize,
		numWorkers:     min(4, max(1, runtime.GOMAXPROCS(0))),
		offsetInterval: 5 * time.Second,
		sweepInterval:  10 * time.Second,
		sweepReqCh:     make(chan struct{}, 1),
		reloadAggCh:    make(chan *config.Config, 8),
	}

	for _, opt := range opts {
		opt(d)
	}

	if d.queueSize <= 0 {
		d.queueSize = 8192
	}
	if d.numWorkers <= 0 {
		d.numWorkers = min(4, max(1, runtime.GOMAXPROCS(0)))
	}
	if !d.controlSocketSet {
		d.controlSocket = defaultControlSocketPath(cfg.StateDir)
	}

	// 1. Storage initialization
	if d.store == nil {
		stateDir := cfg.StateDir
		if stateDir == "" {
			stateDir = "/var/lib/banhammer"
		}
		s, err := store.OpenWith(stateDir, store.Options{
			Log: d.log,
			Now: d.now,
		})
		if err != nil {
			return nil, fmt.Errorf("daemon: open store: %w", err)
		}
		d.store = s
		d.storeOwned = true
	}

	// 2. Metrics registry
	d.metrics = metrics.New(metrics.WithClock(d.now))
	for name := range cfg.Monitors {
		d.metrics.InitMonitor(name)
	}
	backendName := cfg.Defaults.Action.Name
	if backendName == "" {
		backendName = "iptables"
	}
	d.metrics.InitBackend(backendName)

	// 3. Action backend and Executor
	backend, err := createBackend(cfg, d.runner, d.log, d.dryRun)
	if err != nil {
		d.cleanupStoreOnFailure()
		return nil, fmt.Errorf("daemon: create action backend: %w", err)
	}
	d.backend = &metricsBackend{backend: backend, metrics: d.metrics}
	d.executor = action.NewExecutor(d.backend, d.log)

	// 4. Ban Manager
	enforcer := &metricsEnforcer{
		enforcer: d.executor,
		metrics:  d.metrics,
	}
	d.banManager = ban.NewManager(ban.Options{
		Allowlist:  cfg.Allowlist,
		AllowLocal: cfg.AllowLocal,
		Enforcer:   enforcer,
		Persister:  d.store,
		Now:        d.now,
		Log:        d.log,
		Interfaces: d.interfaces,
	})

	// Set default fallback policy
	d.banManager.SetPolicy("", ban.Policy{
		Bantime:     cfg.Defaults.Bantime,
		BantimeMax:  cfg.Defaults.BantimeMax,
		FindHistory: cfg.Defaults.FindHistory,
		Factor:      cfg.Defaults.BantimeFactor,
		OnRepeat:    cfg.Defaults.OnRepeat,
	})
	// Set per-monitor policies
	for name, m := range cfg.Monitors {
		d.banManager.SetPolicy(name, ban.Policy{
			Bantime:     m.Bantime,
			BantimeMax:  m.BantimeMax,
			FindHistory: m.FindHistory,
			Factor:      m.BantimeFactor,
			OnRepeat:    m.OnRepeat,
		})
	}

	// 5. Restore persisted bans
	savedBans, err := d.store.LoadBans()
	if err != nil {
		d.cleanupStoreOnFailure()
		return nil, fmt.Errorf("daemon: load bans from store: %w", err)
	}
	if err := d.banManager.Restore(savedBans); err != nil {
		d.cleanupStoreOnFailure()
		return nil, fmt.Errorf("daemon: restore bans: %w", err)
	}

	// 6. Compile rule sets for all monitors
	d.rules = make(map[string]*rule.Set, len(cfg.Monitors))
	for name, m := range cfg.Monitors {
		spec := rule.Spec{
			Format:       m.Format,
			Line:         m.Match.Line,
			Fields:       m.Match.Fields,
			IgnoreLine:   m.Ignore.Line,
			IgnoreFields: m.Ignore.Fields,
			IPField:      m.IPField,
			Contains:     m.Contains,
		}
		set, err := rule.Compile(spec)
		if err != nil {
			d.cleanupStoreOnFailure()
			return nil, fmt.Errorf("daemon: compile rules for monitor %q: %w", name, err)
		}
		d.rules[name] = set
	}

	// 7. Initialize sources
	d.sources = make([]source.Source, 0, len(cfg.Monitors))
	for _, name := range cfg.MonitorNames() {
		m := cfg.Monitors[name]
		src, err := d.createSource(m)
		if err != nil {
			d.cleanupStoreOnFailure()
			return nil, fmt.Errorf("daemon: create source for monitor %q: %w", name, err)
		}
		d.sources = append(d.sources, src)
	}

	// 8. Sliding-window hit trackers for the Aggregator
	d.trackers = make(map[string]*window.Tracker, len(cfg.Monitors))
	for name, m := range cfg.Monitors {
		d.trackers[name] = window.New(m.Threshold, m.Window, m.MaxTracked, d.now)
	}

	// 9. Pipeline communication channels
	d.queue = make(chan model.Event, d.queueSize)
	d.matchCh = make(chan matchEvent, d.queueSize)

	// 10. Control IPC server (if enabled)
	if d.controlSocket != "" {
		ctrlSrv, err := control.NewServer(d.controlSocket, d.Service(), d.log)
		if err != nil {
			d.cleanupStoreOnFailure()
			return nil, fmt.Errorf("daemon: create control server: %w", err)
		}
		d.controlServer = ctrlSrv
	}

	// 11. Prometheus metrics HTTP server (if configured)
	if cfg.Metrics.Listen != "" {
		d.metricsServer = metrics.NewServer(cfg.Metrics.Listen, d.metrics, d.log)
	}

	return d, nil
}

func (d *Daemon) cleanupStoreOnFailure() {
	if d.storeOwned && d.store != nil {
		_ = d.store.Close()
	}
}

// defaultControlSocketPath returns the standard socket location.
func defaultControlSocketPath(stateDir string) string {
	if os.Geteuid() == 0 {
		return "/run/banhammer.sock"
	}
	if stateDir == "" {
		stateDir = "/var/lib/banhammer"
	}
	return filepath.Join(stateDir, "control.sock")
}

// Run executes the full daemon pipeline until ctx is cancelled.
//
// It starts the action backend, fires worker pools, runs the single-threaded
// aggregator, ingests log sources, starts the control and metrics servers,
// and periodically saves checkpoints.
//
// On cancellation, it conducts a clean shutdown: sources stop, the event queue
// and workers drain, the aggregator completes remaining matches, offsets are
// persisted, and all background services terminate cleanly without goroutine leaks.
func (d *Daemon) Run(ctx context.Context) error {
	if !d.running.CompareAndSwap(false, true) {
		return errors.New("daemon: already running")
	}
	defer d.running.Store(false)

	// 1. Prepare action backend (idempotent chain/table creation)
	if err := d.backend.Start(ctx); err != nil {
		return fmt.Errorf("daemon: start action backend: %w", err)
	}

	execCtx, execCancel := context.WithCancel(context.Background())
	defer execCancel()
	banCtx, banCancel := context.WithCancel(context.Background())
	defer banCancel()
	ctrlCtx, ctrlCancel := context.WithCancel(context.Background())
	defer ctrlCancel()
	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()
	srcCtx, srcCancel := context.WithCancel(context.Background())
	defer srcCancel()

	// 2. Start Action Executor
	var execWg sync.WaitGroup
	execWg.Add(1)
	go func() {
		defer execWg.Done()
		_ = d.executor.Run(execCtx)
	}()

	// 3. Start Ban Manager expiry loop
	var banWg sync.WaitGroup
	banWg.Add(1)
	go func() {
		defer banWg.Done()
		_ = d.banManager.Run(banCtx)
	}()

	// 4. Start Aggregator
	d.aggWg.Add(1)
	go func() {
		d.aggregator()
	}()

	// 5. Start Worker Pool
	for i := 0; i < d.numWorkers; i++ {
		d.workerWg.Add(1)
		go func() {
			d.worker()
		}()
	}

	// 6. Start Log Sources
	for _, src := range d.sources {
		d.srcWg.Add(1)
		go d.runSource(srcCtx, src)
	}

	// 7. Start Control IPC Server
	if d.controlServer != nil {
		go func() {
			if err := d.controlServer.Run(ctrlCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, control.ErrClosed) {
				d.log.Error("control server error", "err", err)
			}
		}()
	}

	// 8. Start Metrics HTTP Server
	if d.metricsServer != nil {
		go func() {
			if err := d.metricsServer.Run(metricsCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, metrics.ErrServerClosed) {
				d.log.Error("metrics server error", "err", err)
			}
		}()
	}

	// 9. Periodic Checkpoint Saving
	offsetTicker := time.NewTicker(d.offsetInterval)
	defer offsetTicker.Stop()

	// Main supervisory wait loop
waitLoop:
	for {
		select {
		case <-ctx.Done():
			break waitLoop
		case <-offsetTicker.C:
			_ = d.saveOffsets()
		}
	}

	d.log.Info("daemon shutting down gracefully")

	// Phase 1: Stop input sources
	srcCancel()
	d.srcWg.Wait()

	// Phase 2: Close event queue and drain workers
	close(d.queue)
	d.workerWg.Wait()

	// Phase 3: Close match channel and drain aggregator
	close(d.matchCh)
	d.aggWg.Wait()

	// Phase 4: Persist final offsets and flush store
	_ = d.saveOffsets()
	_ = d.store.Flush()

	// Phase 5: Stop control and metrics servers
	ctrlCancel()
	metricsCancel()
	if d.controlServer != nil {
		_ = d.controlServer.Close()
	}
	if d.metricsServer != nil {
		_ = d.metricsServer.Close()
	}

	// Phase 6: Stop ban manager
	banCancel()
	banWg.Wait()

	// Phase 7: Stop action executor (drains remaining enqueued bans)
	execCancel()
	execWg.Wait()

	// Phase 8: Teardown action backend
	_ = d.backend.Stop(context.Background())

	// Phase 9: Close store and release locks
	_ = d.Close()

	d.log.Info("daemon shutdown complete")
	return nil
}

// Close releases daemon resources including the state store and servers.
func (d *Daemon) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		if d.controlServer != nil {
			_ = d.controlServer.Close()
		}
		if d.metricsServer != nil {
			_ = d.metricsServer.Close()
		}
		if d.store != nil {
			err = d.store.Close()
		}
	})
	return err
}

// Metrics returns the in-memory metric registry used across daemon stages.
func (d *Daemon) Metrics() *metrics.Registry {
	return d.metrics
}

// Service returns an implementation of control.Service suitable for IPC handling.
func (d *Daemon) Service() control.Service {
	return &daemonService{d: d}
}

// ControlReady returns a channel that is closed once the control socket is bound.
func (d *Daemon) ControlReady() <-chan struct{} {
	if d.controlServer != nil {
		return d.controlServer.Ready()
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// MetricsReady returns a channel that is closed once the metrics HTTP server is listening.
func (d *Daemon) MetricsReady() <-chan struct{} {
	if d.metricsServer != nil {
		return d.metricsServer.Ready()
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Sweep signals the single-threaded Aggregator to perform an immediate sweep
// of expired sliding-window entries.
func (d *Daemon) Sweep() {
	select {
	case d.sweepReqCh <- struct{}{}:
	default:
	}
}

// Enqueue inserts ev into the bounded event queue using drop-oldest overflow policy.
// It reports whether the event was enqueued (true) or context was cancelled (false).
func (d *Daemon) Enqueue(ev model.Event) bool {
	return d.enqueue(context.Background(), ev)
}

// Status captures a complete operational snapshot of the daemon.
func (d *Daemon) Status() (control.StatusResponse, error) {
	monitors := d.getMonitorStatuses()
	bans := d.banManager.Snapshot()
	if bans == nil {
		bans = []model.Ban{}
	}
	return control.StatusResponse{
		Uptime:   d.metrics.Uptime(),
		Monitors: monitors,
		Bans:     bans,
		Stats:    d.metrics.Stats(),
	}, nil
}

// Ban manually enforces an immediate ban on ip under monitor for duration d.
func (d *Daemon) Ban(ip netip.Addr, monitor string, dur time.Duration) error {
	return d.banManager.Ban(ip, monitor, dur)
}

// Unban removes an active ban for ip, immediately lifting firewall rules.
func (d *Daemon) Unban(ip netip.Addr) error {
	return d.banManager.Unban(ip)
}

// UnbanAll removes all currently active bans across all monitors.
func (d *Daemon) UnbanAll() error {
	return d.banManager.UnbanAll()
}

// Reload reloads monitor matching rules, policies, and settings dynamically.
//
// If newCfg is nil, it reloads from the previously configured config file path.
func (d *Daemon) Reload(newCfg *config.Config) error {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()

	if newCfg == nil {
		if d.configPath == "" {
			return errors.New("daemon: cannot reload: no configuration path configured")
		}
		var err error
		newCfg, err = config.Load(d.configPath)
		if err != nil {
			return fmt.Errorf("daemon: reload config from %q: %w", d.configPath, err)
		}
	}

	// Compile rules for all monitors in newCfg
	newRules := make(map[string]*rule.Set, len(newCfg.Monitors))
	for name, m := range newCfg.Monitors {
		spec := rule.Spec{
			Format:       m.Format,
			Line:         m.Match.Line,
			Fields:       m.Match.Fields,
			IgnoreLine:   m.Ignore.Line,
			IgnoreFields: m.Ignore.Fields,
			IPField:      m.IPField,
			Contains:     m.Contains,
		}
		set, err := rule.Compile(spec)
		if err != nil {
			return fmt.Errorf("daemon: compile rules for monitor %q: %w", name, err)
		}
		newRules[name] = set
	}

	// Update policies on banManager
	d.banManager.SetPolicy("", ban.Policy{
		Bantime:     newCfg.Defaults.Bantime,
		BantimeMax:  newCfg.Defaults.BantimeMax,
		FindHistory: newCfg.Defaults.FindHistory,
		Factor:      newCfg.Defaults.BantimeFactor,
		OnRepeat:    newCfg.Defaults.OnRepeat,
	})
	for name, m := range newCfg.Monitors {
		d.banManager.SetPolicy(name, ban.Policy{
			Bantime:     m.Bantime,
			BantimeMax:  m.BantimeMax,
			FindHistory: m.FindHistory,
			Factor:      m.BantimeFactor,
			OnRepeat:    m.OnRepeat,
		})
		d.metrics.InitMonitor(name)
	}

	// Atomically swap compiled rules
	d.rulesMu.Lock()
	d.rules = newRules
	d.rulesMu.Unlock()

	// Atomically swap effective config
	d.cfgMu.Lock()
	d.cfg = newCfg
	d.cfgMu.Unlock()

	// Update Aggregator trackers
	if !d.running.Load() {
		for name, m := range newCfg.Monitors {
			d.trackers[name] = window.New(m.Threshold, m.Window, m.MaxTracked, d.now)
		}
	} else {
		select {
		case d.reloadAggCh <- newCfg:
		default:
		}
	}

	d.log.Info("configuration reloaded successfully")
	return nil
}

func (d *Daemon) getMonitorStatuses() []control.MonitorStatus {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()

	names := d.cfg.MonitorNames()
	statuses := make([]control.MonitorStatus, 0, len(names))
	for _, name := range names {
		mon := d.cfg.Monitors[name]
		monType := "file"
		target := mon.File
		if mon.Listen != "" {
			monType = "listen"
			target = mon.Listen
		} else if mon.Stdin {
			monType = "stdin"
			target = "stdin"
		}
		statuses = append(statuses, control.MonitorStatus{
			Name:       name,
			Type:       monType,
			Target:     target,
			TrackedIPs: int(d.metrics.TrackedIPs(name)),
		})
	}
	return statuses
}

func (d *Daemon) getMonitor(name string) *config.Monitor {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg.Monitors[name]
}

func (d *Daemon) getRuleSet(name string) *rule.Set {
	d.rulesMu.RLock()
	defer d.rulesMu.RUnlock()
	return d.rules[name]
}

// daemonService adapts Daemon to the control.Service interface.
type daemonService struct {
	d *Daemon
}

func (s *daemonService) Status() (control.StatusResponse, error) {
	return s.d.Status()
}

func (s *daemonService) Ban(ip netip.Addr, monitor string, d time.Duration) error {
	return s.d.Ban(ip, monitor, d)
}

func (s *daemonService) Unban(ip netip.Addr) error {
	return s.d.Unban(ip)
}

func (s *daemonService) UnbanAll() error {
	return s.d.UnbanAll()
}

func (s *daemonService) Reload() error {
	return s.d.Reload(nil)
}
