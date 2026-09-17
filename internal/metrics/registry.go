// Package metrics provides in-memory operational metrics collection and a
// Prometheus HTTP exposition endpoint for the banhammer daemon.
//
// # Why Custom In-Memory Metrics
//
// Banhammer processes incoming log streams under adversarial conditions (such as
// high-volume credential stuffing attacks). Ingestion and matching routines
// execute on the hot path where lock contention or garbage collection overhead
// must be minimized. Rather than importing heavyweight third-party SDKs,
// this package implements zero-dependency, lock-free atomic counters and gauges
// that emit standard Prometheus exposition text (RFC-compliant version 0.0.4).
//
// # Thread Safety and Performance
//
// All metric operations (increments, gauge stores, and snapshot extractions)
// utilize lock-free atomic primitives (sync/atomic.Int64) combined with
// read-optimized concurrent maps (sync.Map). This ensures that worker
// goroutines recording log lines or rule matches never block each other, even
// under extreme multi-core saturation.
package metrics

import (
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"banhammer/internal/control"
)

// DefaultPrefix namespaces every metric name. Prometheus convention is a
// per-application namespace, and bare names like "matches" would collide the
// moment banhammer shares a scrape target with anything else.
const DefaultPrefix = "banhammer_"

// labeledMetric encapsulates a family of metric values partitioned by a single label key.
//
// It stores counters/gauges in a sync.Map keyed by label value (e.g. monitor name or backend),
// mapping to heap-allocated atomic.Int64 cells. This structure provides lock-free, zero-allocation
// reads and updates on established keys.
type labeledMetric struct {
	labelKey string
	values   sync.Map // map[string]*atomic.Int64
}

func newLabeledMetric(labelKey string) *labeledMetric {
	return &labeledMetric{labelKey: labelKey}
}

func (m *labeledMetric) inc(label string) {
	m.add(label, 1)
}

func (m *labeledMetric) add(label string, delta int64) {
	if delta == 0 {
		return
	}
	if v, ok := m.values.Load(label); ok {
		v.(*atomic.Int64).Add(delta)
		return
	}
	val := &atomic.Int64{}
	actual, _ := m.values.LoadOrStore(label, val)
	actual.(*atomic.Int64).Add(delta)
}

func (m *labeledMetric) set(label string, val int64) {
	if v, ok := m.values.Load(label); ok {
		v.(*atomic.Int64).Store(val)
		return
	}
	cell := &atomic.Int64{}
	cell.Store(val)
	actual, _ := m.values.LoadOrStore(label, cell)
	actual.(*atomic.Int64).Store(val)
}

func (m *labeledMetric) get(label string) int64 {
	if v, ok := m.values.Load(label); ok {
		return v.(*atomic.Int64).Load()
	}
	return 0
}

func (m *labeledMetric) total() int64 {
	var sum int64
	m.values.Range(func(_, value any) bool {
		sum += value.(*atomic.Int64).Load()
		return true
	})
	return sum
}

func (m *labeledMetric) init(label string) {
	if _, ok := m.values.Load(label); !ok {
		cell := &atomic.Int64{}
		m.values.LoadOrStore(label, cell)
	}
}

func (m *labeledMetric) reset() {
	m.values.Range(func(_, value any) bool {
		value.(*atomic.Int64).Store(0)
		return true
	})
}

type labelSample struct {
	label string
	value int64
}

func (m *labeledMetric) samples() []labelSample {
	var s []labelSample
	m.values.Range(func(key, value any) bool {
		s = append(s, labelSample{
			label: key.(string),
			value: value.(*atomic.Int64).Load(),
		})
		return true
	})
	slices.SortFunc(s, func(a, b labelSample) int {
		return strings.Compare(a.label, b.label)
	})
	return s
}

// Registry maintains the set of daemon metric collectors and coordinates
// atomic updates, aggregate statistics calculation, and Prometheus text rendering.
//
// A single Registry instance is shared across log ingestion workers, the sliding
// window aggregator, the ban manager, and the control server.
type Registry struct {
	linesRead    *labeledMetric
	linesDropped *labeledMetric
	matches      *labeledMetric
	bans         *labeledMetric
	unbans       *labeledMetric
	actionErrors *labeledMetric
	decodeErrors *labeledMetric
	trackedIPs   *labeledMetric
	activeBans   *labeledMetric

	clock     func() time.Time
	startTime time.Time
	prefix    string

	// collectFn is an optional hook run immediately before the registry is
	// read, so values owned by another component can be pulled in at scrape
	// time rather than pushed on every change. See Collect.
	collectFn func()

	mu sync.RWMutex
}

// Option configures Registry behavior during initialization.
type Option func(*Registry)

// WithClock overrides the default system clock (time.Now) with a custom time provider.
//
// This enables hermetic unit testing of uptime gauges and duration calculations
// without requiring real-time sleeps in tests.
func WithClock(now func() time.Time) Option {
	return func(r *Registry) {
		r.clock = now
	}
}

// WithStartTime establishes an explicit reference timestamp for the daemon
// start time, so uptime can be measured from process start rather than from
// registry construction.
func WithStartTime(t time.Time) Option {
	return func(r *Registry) {
		r.startTime = t
	}
}

// WithPrefix overrides the namespace prepended to every Prometheus metric name.
//
// It defaults to DefaultPrefix; pass "" to emit bare names. An invalid prefix
// (one that would produce a name Prometheus cannot parse) is ignored, because a
// metrics endpoint that a scraper rejects wholesale is worse than one with the
// default namespace.
func WithPrefix(prefix string) Option {
	return func(r *Registry) {
		if prefix != "" && !validPrefix.MatchString(prefix) {
			return
		}
		r.prefix = prefix
	}
}

// validPrefix matches the part of a Prometheus metric name a prefix may
// contribute: the full name must match [a-zA-Z_:][a-zA-Z0-9_:]*, and the
// prefix is its head.
var validPrefix = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// NewRegistry allocates and initializes a fresh metrics Registry with all standard
// banhammer collectors ready for use.
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		linesRead:    newLabeledMetric("monitor"),
		linesDropped: newLabeledMetric("monitor"),
		matches:      newLabeledMetric("monitor"),
		bans:         newLabeledMetric("monitor"),
		unbans:       newLabeledMetric("monitor"),
		actionErrors: newLabeledMetric("backend"),
		decodeErrors: newLabeledMetric("monitor"),
		trackedIPs:   newLabeledMetric("monitor"),
		activeBans:   newLabeledMetric("monitor"),
		clock:        time.Now,
		prefix:       DefaultPrefix,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.startTime.IsZero() {
		r.startTime = r.clock()
	}
	return r
}

// New is a concise constructor alias for NewRegistry following standard Go conventions.
func New(opts ...Option) *Registry {
	return NewRegistry(opts...)
}

// Collect registers a hook to run immediately before the registry is read by
// WritePrometheus or Stats.
//
// It exists so that metrics whose source of truth lives elsewhere — the
// per-monitor ban counters, which only the ban manager can compute correctly —
// are refreshed on read instead of being pushed on every state change. The hook
// must not call back into the registry's read paths.
func (r *Registry) Collect(f func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectFn = f
}

// collect runs the registered hook, if any, without holding the lock across the
// call.
func (r *Registry) collect() {
	r.mu.RLock()
	f := r.collectFn
	r.mu.RUnlock()
	if f != nil {
		f()
	}
}

func (r *Registry) getPrefix() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.prefix
}

func normalizeDroppedMonitor(monitor string) string {
	if monitor == "" {
		return "global"
	}
	return monitor
}

func normalizeBackend(backend string) string {
	if backend == "" {
		return "unknown"
	}
	return backend
}

// IncLinesRead increments the lines_read counter by 1 for the specified monitor.
func (r *Registry) IncLinesRead(monitor string) {
	r.linesRead.inc(monitor)
}

// IncLinesDropped increments the lines_dropped counter by 1.
//
// If monitor is empty, it is attributed to the "global" queue drop counter.
func (r *Registry) IncLinesDropped(monitor string) {
	r.linesDropped.inc(normalizeDroppedMonitor(monitor))
}

// AddLinesDropped adds delta to the lines_dropped counter for monitor.
func (r *Registry) AddLinesDropped(monitor string, delta int64) {
	if delta > 0 {
		r.linesDropped.add(normalizeDroppedMonitor(monitor), delta)
	}
}

// IncMatches increments the matches counter by 1 for the specified monitor.
func (r *Registry) IncMatches(monitor string) {
	r.matches.inc(monitor)
}

// SetBans records the total number of bans issued for monitor.
//
// Bans are set rather than incremented because the ban manager, not the
// pipeline, is the authority on what counts as a new ban: a ban re-applied to
// the firewall at startup is not one.
func (r *Registry) SetBans(monitor string, total int64) {
	r.bans.set(monitor, total)
}

// SetUnbans records the total number of bans lifted for monitor, by expiry or
// by hand. Set rather than incremented, for the reason given on SetBans.
func (r *Registry) SetUnbans(monitor string, total int64) {
	r.unbans.set(monitor, total)
}

// IncActionErrors increments the action_errors counter by 1 for the specified backend.
func (r *Registry) IncActionErrors(backend string) {
	r.actionErrors.inc(normalizeBackend(backend))
}

// IncDecodeErrors increments the decode_errors counter by 1 for the specified monitor.
func (r *Registry) IncDecodeErrors(monitor string) {
	r.decodeErrors.inc(monitor)
}

// SetTrackedIPs updates the gauge recording the count of actively tracked IPs for monitor.
func (r *Registry) SetTrackedIPs(monitor string, count int64) {
	r.trackedIPs.set(monitor, count)
}

// SetActiveBans updates the gauge recording the current active firewall bans for monitor.
func (r *Registry) SetActiveBans(monitor string, count int64) {
	r.activeBans.set(monitor, count)
}

// LinesRead returns the total number of lines read recorded for monitor.
func (r *Registry) LinesRead(monitor string) int64 {
	return r.linesRead.get(monitor)
}

// LinesDropped returns the total number of lines dropped for monitor (or global if empty).
func (r *Registry) LinesDropped(monitor string) int64 {
	return r.linesDropped.get(normalizeDroppedMonitor(monitor))
}

// Matches returns the total number of rule matches recorded for monitor.
func (r *Registry) Matches(monitor string) int64 {
	return r.matches.get(monitor)
}

// Bans returns the total number of bans imposed under monitor.
//
// Like every read of a collected metric it refreshes from the Collect hook
// first, so a caller never sees a value staler than the ban manager's.
func (r *Registry) Bans(monitor string) int64 {
	r.collect()
	return r.bans.get(monitor)
}

// Unbans returns the total number of unbans completed under monitor. It
// refreshes from the Collect hook first; see Bans.
func (r *Registry) Unbans(monitor string) int64 {
	r.collect()
	return r.unbans.get(monitor)
}

// ActionErrors returns the total number of firewall errors recorded for backend.
func (r *Registry) ActionErrors(backend string) int64 {
	return r.actionErrors.get(normalizeBackend(backend))
}

// DecodeErrors returns the total number of decode errors recorded for monitor.
func (r *Registry) DecodeErrors(monitor string) int64 {
	return r.decodeErrors.get(monitor)
}

// TrackedIPs returns the current tracked IP gauge value for monitor.
func (r *Registry) TrackedIPs(monitor string) int64 {
	return r.trackedIPs.get(monitor)
}

// ActiveBans returns the current active bans gauge value for monitor. It
// refreshes from the Collect hook first; see Bans.
func (r *Registry) ActiveBans(monitor string) int64 {
	r.collect()
	return r.activeBans.get(monitor)
}

// TotalLinesRead returns the aggregate count of log lines read across all monitors.
func (r *Registry) TotalLinesRead() int64 {
	return r.linesRead.total()
}

// TotalLinesDropped returns the aggregate count of log lines dropped across all sources.
func (r *Registry) TotalLinesDropped() int64 {
	return r.linesDropped.total()
}

// TotalMatches returns the aggregate count of pattern matches across all monitors.
func (r *Registry) TotalMatches() int64 {
	return r.matches.total()
}

// TotalBans returns the aggregate count of bans executed across all monitors.
// It refreshes from the Collect hook first; see Bans.
func (r *Registry) TotalBans() int64 {
	r.collect()
	return r.bans.total()
}

// TotalUnbans returns the aggregate count of unbans executed across all
// monitors. It refreshes from the Collect hook first; see Bans.
func (r *Registry) TotalUnbans() int64 {
	r.collect()
	return r.unbans.total()
}

// TotalActionErrors returns the aggregate count of firewall errors across all backends.
func (r *Registry) TotalActionErrors() int64 {
	return r.actionErrors.total()
}

// TotalDecodeErrors returns the aggregate count of decode errors across all monitors.
func (r *Registry) TotalDecodeErrors() int64 {
	return r.decodeErrors.total()
}

// TotalTrackedIPs returns the aggregate count of currently tracked IPs across all monitors.
func (r *Registry) TotalTrackedIPs() int64 {
	return r.trackedIPs.total()
}

// TotalActiveBans returns the aggregate count of active bans across all
// monitors. It refreshes from the Collect hook first; see Bans.
func (r *Registry) TotalActiveBans() int64 {
	r.collect()
	return r.activeBans.total()
}

// Uptime returns the duration elapsed since the Registry was created (or its start time).
func (r *Registry) Uptime() time.Duration {
	r.mu.RLock()
	nowFn := r.clock
	start := r.startTime
	r.mu.RUnlock()
	if nowFn == nil {
		nowFn = time.Now
	}
	return nowFn().Sub(start)
}

// UptimeSeconds returns the uptime represented as floating-point seconds.
func (r *Registry) UptimeSeconds() float64 {
	return r.Uptime().Seconds()
}

// Stats returns cumulative operational totals aggregated across all monitors
// and backends for consumption by the control socket IPC status endpoint.
//
// It reads the metric cells directly rather than going through the Total*
// accessors: those collect on every call, and one status response should run
// the collect hook exactly once, over a single consistent snapshot.
func (r *Registry) Stats() control.Stats {
	r.collect()
	return control.Stats{
		LinesRead:    r.linesRead.total(),
		LinesDropped: r.linesDropped.total(),
		Matches:      r.matches.total(),
		BansTotal:    r.bans.total(),
		UnbansTotal:  r.unbans.total(),
		ActionErrors: r.actionErrors.total(),
		DecodeErrors: r.decodeErrors.total(),
		TrackedIPs:   r.trackedIPs.total(),
		ActiveBans:   r.activeBans.total(),
	}
}

// InitMonitor pre-populates zero-valued metric entries for the specified monitor.
//
// This ensures that Prometheus scrapes report known configured monitors with 0
// values even before any log lines have been processed.
func (r *Registry) InitMonitor(monitor string) {
	r.linesRead.init(monitor)
	r.linesDropped.init(monitor)
	r.matches.init(monitor)
	r.bans.init(monitor)
	r.unbans.init(monitor)
	r.decodeErrors.init(monitor)
	r.trackedIPs.init(monitor)
	r.activeBans.init(monitor)
}

// InitBackend pre-populates a zero-valued error counter for the specified action backend.
func (r *Registry) InitBackend(backend string) {
	r.actionErrors.init(normalizeBackend(backend))
}

// Reset resets all counter and gauge values in the registry to zero.
//
// This is primarily used between unit test stages to restore a clean slate.
func (r *Registry) Reset() {
	r.linesRead.reset()
	r.linesDropped.reset()
	r.matches.reset()
	r.bans.reset()
	r.unbans.reset()
	r.actionErrors.reset()
	r.decodeErrors.reset()
	r.trackedIPs.reset()
	r.activeBans.reset()
}
