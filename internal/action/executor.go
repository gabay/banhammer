package action

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"banhammer/internal/model"
)

// Executor defaults. The queue is large enough to absorb a burst of bans from
// a log flood; beyond that we drop rather than block, because a stalled
// firewall must never back-pressure the log reader.
const (
	defaultQueueSize = 4096
	defaultAttempts  = 3
	defaultBackoff   = 200 * time.Millisecond
	defaultOpTimeout = 30 * time.Second
	defaultDrain     = 5 * time.Second
	dropLogInterval  = time.Second
)

// Stats is a snapshot of executor counters.
type Stats struct {
	Applied uint64 // operations that eventually succeeded
	Failed  uint64 // operations that exhausted their retries
	Queued  int    // operations waiting right now
	Dropped uint64 // operations discarded because the queue was full
	Retries uint64 // individual command attempts that failed and were retried
}

// ExecutorOptions tunes an Executor. The zero value is the production
// configuration; tests use it to shrink timeouts and to inject a sleep.
//
// It exists because NewExecutor takes no configuration, and the retry and
// timeout behaviour must be testable without spending real wall time. Nothing
// here is reachable from the YAML config: queue_size sizes the daemon's *event*
// queue, not this one, and the daemon always constructs the executor with the
// defaults below.
type ExecutorOptions struct {
	QueueSize int           // default defaultQueueSize
	Attempts  int           // total tries per operation; default 3
	Backoff   time.Duration // first retry delay, doubled each time; default 200ms

	// OpTimeout bounds one whole operation — every command in a Spec plus the
	// retries between them — and so is deliberately larger than the 10s
	// per-command limit PROJECT.md §4.6 places on Spec.Timeout. Default 30s.
	OpTimeout time.Duration

	Drain time.Duration // how long shutdown may spend on queued work; default 5s

	// Sleep waits for d or until ctx is done, reporting false if it was cut
	// short. Tests replace it so backoff costs no wall time.
	Sleep func(ctx context.Context, d time.Duration) bool
}

func (o *ExecutorOptions) applyDefaults() {
	if o.QueueSize <= 0 {
		o.QueueSize = defaultQueueSize
	}
	if o.Attempts <= 0 {
		o.Attempts = defaultAttempts
	}
	if o.Backoff <= 0 {
		o.Backoff = defaultBackoff
	}
	if o.OpTimeout <= 0 {
		o.OpTimeout = defaultOpTimeout
	}
	if o.Drain <= 0 {
		o.Drain = defaultDrain
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

type opKind int

const (
	opBan opKind = iota
	opUnban
)

func (k opKind) String() string {
	if k == opUnban {
		return "unban"
	}
	return "ban"
}

type op struct {
	kind opKind
	ban  model.Ban
}

// Executor serialises every firewall mutation onto one goroutine, because
// iptables is not concurrency-safe, and retries failures without ever blocking
// the caller: Ban and Unban are enqueues that either fit in the queue or are
// counted as drops.
type Executor struct {
	b    Backend
	log  *slog.Logger
	opts ExecutorOptions

	q chan op

	// closed is flipped once Run returns so late enqueues are dropped instead
	// of filling a queue nobody drains.
	closed atomic.Bool

	applied, failed, dropped, retries atomic.Uint64
	lastDropLog                       atomic.Int64 // unix nanos, rate-limits the drop warning

	once sync.Once
}

// NewExecutor returns an Executor with production defaults.
func NewExecutor(b Backend, log *slog.Logger) *Executor {
	return NewExecutorWithOptions(b, ExecutorOptions{}, log)
}

// NewExecutorWithOptions is NewExecutor with the knobs exposed, for the daemon
// (queue_size) and for tests (timeouts, injected sleep).
func NewExecutorWithOptions(b Backend, opts ExecutorOptions, log *slog.Logger) *Executor {
	if log == nil {
		log = slog.Default()
	}
	opts.applyDefaults()
	return &Executor{
		b:    b,
		log:  log.With("component", "action-executor"),
		opts: opts,
		q:    make(chan op, opts.QueueSize),
	}
}

// Ban enqueues a ban. It never blocks: if the queue is full the operation is
// dropped and counted, because delaying the log pipeline is worse than missing
// one ban (the offender will trip the threshold again).
func (e *Executor) Ban(b model.Ban) { e.enqueue(op{kind: opBan, ban: b}) }

// Unban enqueues an unban with the same non-blocking semantics. A dropped
// unban self-heals: the ban manager re-issues it on the next sweep, and the
// kernel-side timeout of the ipset/nft backends is a second safety net.
func (e *Executor) Unban(b model.Ban) { e.enqueue(op{kind: opUnban, ban: b}) }

func (e *Executor) enqueue(o op) {
	if e.closed.Load() {
		e.drop(o, "executor stopped")
		return
	}
	select {
	case e.q <- o:
	default:
		e.drop(o, "queue full")
	}
}

func (e *Executor) drop(o op, why string) {
	e.dropped.Add(1)
	// One log line per dropped op would itself be a flood; warn at most once a
	// second and let the counter carry the magnitude.
	now := time.Now().UnixNano()
	last := e.lastDropLog.Load()
	if now-last >= int64(dropLogInterval) && e.lastDropLog.CompareAndSwap(last, now) {
		e.log.Warn("dropping firewall operation",
			"reason", why, "op", o.kind.String(), "ip", o.ban.IP, "dropped_total", e.dropped.Load())
	}
}

// Run drains the queue until ctx is cancelled. It must be called exactly once,
// in its own goroutine, and returns nil on cancellation.
func (e *Executor) Run(ctx context.Context) error {
	started := false
	e.once.Do(func() { started = true })
	if !started {
		return errors.New("action: Executor.Run called twice")
	}
	for {
		select {
		case <-ctx.Done():
			e.shutdown(ctx, nil)
			return nil
		case o := <-e.q:
			if ctx.Err() != nil {
				// Cancellation won the race with this receive. Running the op
				// on the dead context would fail it for no reason, so let the
				// drain path deal with it.
				e.shutdown(ctx, &o)
				return nil
			}
			e.apply(ctx, o)
		}
	}
}

// shutdown finishes the work already queued, starting with pending if the
// caller already dequeued one. The parent context is cancelled by then, so the
// drain runs on a detached one with its own deadline — otherwise every pending
// command would fail instantly on a dead context, and an unban we already
// promised would be lost.
func (e *Executor) shutdown(ctx context.Context, pending *op) {
	e.closed.Store(true)
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.opts.Drain)
	defer cancel()
	if pending != nil {
		e.apply(dctx, *pending)
	}
	for {
		select {
		case o := <-e.q:
			if dctx.Err() != nil {
				e.drop(o, "drain deadline exceeded")
				continue
			}
			e.apply(dctx, o)
		default:
			// closed is already set, so nothing new can arrive; an empty queue
			// means the drain is done.
			e.log.Debug("executor drained", "applied", e.applied.Load(), "failed", e.failed.Load())
			return
		}
	}
}

// apply runs one operation with a deadline and bounded retries. A failing
// operation is abandoned after Attempts tries so that it cannot stall the ones
// behind it.
func (e *Executor) apply(ctx context.Context, o op) {
	backoff := e.opts.Backoff
	for attempt := 1; ; attempt++ {
		opCtx, cancel := context.WithTimeout(ctx, e.opts.OpTimeout)
		err := e.do(opCtx, o)
		cancel()

		if err == nil {
			e.applied.Add(1)
			e.log.Debug("applied", "op", o.kind.String(), "ip", o.ban.IP, "attempt", attempt)
			return
		}
		if attempt >= e.opts.Attempts {
			e.failed.Add(1)
			e.log.Error("firewall operation failed, giving up",
				"op", o.kind.String(), "ip", o.ban.IP, "attempts", attempt, "err", err)
			return
		}
		e.retries.Add(1)
		e.log.Warn("firewall operation failed, retrying",
			"op", o.kind.String(), "ip", o.ban.IP, "attempt", attempt, "err", err)
		if !e.opts.Sleep(ctx, backoff) {
			// Context died mid-backoff: stop burning attempts on a shutdown.
			e.failed.Add(1)
			e.log.Error("firewall operation abandoned during shutdown",
				"op", o.kind.String(), "ip", o.ban.IP, "err", err)
			return
		}
		backoff *= 2
	}
}

func (e *Executor) do(ctx context.Context, o op) error {
	if o.kind == opUnban {
		return e.b.Unban(ctx, o.ban)
	}
	return e.b.Ban(ctx, o.ban)
}

// Stats returns a snapshot of the counters. Queued is the instantaneous queue
// depth, so it is inherently racy and only meant for `banhammer status`.
func (e *Executor) Stats() Stats {
	return Stats{
		Applied: e.applied.Load(),
		Failed:  e.failed.Load(),
		Queued:  len(e.q),
		Dropped: e.dropped.Load(),
		Retries: e.retries.Load(),
	}
}
