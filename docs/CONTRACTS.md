# Banhammer — Package Contracts

**This file is normative.** Packages are built in parallel by separate agents, so these
signatures are the integration boundary. If you believe a signature is wrong, say so in your
report — do **not** silently change it, and do **not** edit a package you were not assigned.

See [PROJECT.md](../PROJECT.md) for the design rationale.

## Ground rules

* Module `banhammer`, Go 1.26. Deps allowed: `fsnotify`, `cobra`, `yaml.v3`, `golang.org/x/sys`. Nothing else without asking.
* `internal/model` is the only shared type package and imports nothing from banhammer.
* Every package gets table-driven tests. **No test may sleep for real time** — take a clock/now
  function as a parameter and drive it manually.
* `go build ./... && go vet ./... && go test ./...` must pass before you report done.
* Errors are wrapped with `%w` and context. Logging via `log/slog` only; libraries take a
  `*slog.Logger` rather than using the default one.
* Public identifiers get doc comments. Comment *why*, not *what*.

## internal/model (DONE — do not edit)

```go
type Event struct { Monitor string; Raw []byte; Recv time.Time }
type Checkpoint struct { Path string; Dev, Inode uint64; Offset int64 }
func (c Checkpoint) SameFile(other Checkpoint) bool
type Ban struct { IP netip.Addr; Monitor string; At, Until time.Time; Count, Offense int }
func (b Ban) Expired(now time.Time) bool
func (b Ban) Family() Family
type Family int // IPv4, IPv6; String() -> "inet"/"inet6"
```

## internal/config

```go
func Load(path string) (*Config, error)   // parse + apply defaults + validate
func (c *Config) String() string          // effective config, for `banhammer check`

type Config struct {
    StateDir   string              // default /var/lib/banhammer
    LogFormat  string              // text|json, default text
    AllowLocal bool                // default true
    Allowlist  []netip.Prefix
    Metrics    struct{ Listen string }
    QueueSize  int                 // default 8192
    Defaults   Settings
    Monitors   map[string]*Monitor // key = monitor name
}

// Settings are the knobs that may appear under `defaults:` or on a monitor.
type Settings struct {
    Threshold     int           // default 5
    Window        time.Duration // default 10m
    Bantime       time.Duration // default 1h
    BantimeFactor float64       // default 1 (no escalation)
    BantimeMax    time.Duration // default 168h
    FindHistory   time.Duration // default 24h
    MaxTracked    int           // default 100000
    StartAt       string        // checkpoint|end|beginning, default checkpoint
    OnRepeat      string        // ignore|extend, default ignore
    Action        ActionSpec
}

type Monitor struct {
    Name        string   // filled from the map key
    File        string   // path or glob      } exactly one of these
    Listen      string   // scheme://host:port } three must be set
    Stdin       bool     //                    }
    Format      string   // text|json, default text
    StripSyslog bool
    Match       Patterns
    Ignore      Patterns
    IPField     string   // JSON dotted path; mutually exclusive with an <IP> group in Match
    Contains    string   // optional literal prefilter override
    Settings             // embedded; fully resolved against Defaults by Load
}

// Patterns is the polymorphic `match:`/`ignore:` value. YAML may be a string, a
// list of strings (OR over the raw line), or a map of field->regex (AND).
type Patterns struct {
    Line   []string
    Fields map[string]string
}
func (p Patterns) Empty() bool

type ActionSpec struct {
    Name    string        // iptables|ipset|nft|dryrun|cmd; default iptables
    Start   string        // cmd templates; presence of Ban implies Name=="cmd"
    Ban     string
    Unban   string
    Stop    string
    Shell   bool
    Timeout time.Duration // default 10s
}
```

Requirements:
* Durations accept Go duration strings (`10m`, `24h`).
* **Strict parsing**: unknown YAML keys are an error (`yaml.Decoder.KnownFields(true)`), and the
  message must name the offending key and line. This is the anti-footgun feature — test it.
* Validation errors are accumulated and reported together, prefixed `monitor "sshd": ...`.
* Validate: exactly one source; `ip_field` requires `format: json`; a monitor must be able to
  produce an IP (either `ip_field` or an `<IP>`/`<HOST>`/`(?P<ip>...)` group in every `match`
  pattern); `threshold >= 1`; `window > 0`; regexes compile (use `rule.Compile`); `listen` scheme
  is one of udp/tcp/unix; field-map `match` requires `format: json`.
* `allow_local` and `allowlist` parse to `[]netip.Prefix`; bare IPs become /32 or /128.

## internal/decode

```go
// Fields walks raw once and writes the requested dotted paths into dst
// (cleared first). Missing paths are simply absent from dst.
// Values are rendered as their JSON text: strings unquoted, numbers/bools verbatim.
func Fields(raw []byte, paths []string, dst map[string]string) error
```
Dotted paths address nested objects (`request.remote_ip`) and array indices (`headers.0`).
Keep allocations near zero on the hot path; no `map[string]any`. Must not panic on malformed
input — return an error. Include a fuzz test.

## internal/rule

```go
type Spec struct {
    Format   string            // text|json
    Line     []string          // OR
    Fields   map[string]string // AND
    IgnoreLine   []string
    IgnoreFields map[string]string
    IPField  string
    Contains string
}

func Compile(s Spec) (*Set, error)
func (s *Set) Match(raw []byte) (Result, Outcome)
func (s *Set) NeedsIPField() bool

type Result struct { IP netip.Addr; Pattern string } // Pattern = the rule that hit, for {matched}
type Outcome int // OutcomeNoMatch, OutcomeMatch, OutcomeIgnored, OutcomeDecodeError, OutcomeNoIP
```

Requirements:
* **`<IP>` / `<HOST>` macro** expands to a named group `(?P<ip>...)` matching IPv4 dotted-quad and
  IPv6 (compressed, bracketed, and v4-mapped). `<HOST>` additionally matches DNS names; a
  non-address host is reported as `OutcomeNoIP` for now (resolution is out of scope).
  Expansion happens on the pattern text before `regexp.Compile`. A pattern may instead supply its
  own `(?P<ip>...)`. More than one IP group is a compile error.
* Extracted text is parsed with `netip.ParseAddr`; `Unmap()` v4-in-v6 so `::ffff:1.2.3.4` and
  `1.2.3.4` are the same key. Zone-suffixed addresses are rejected.
* **Prefilter**: derive a required literal from each pattern (`regexp/syntax`: prefix or a
  required literal factor), or use `Spec.Contains`. `Match` runs `bytes.Contains` before the
  regex. Correctness first — a pattern with no usable literal just skips the prefilter. Test that
  the prefilter never changes the verdict (fuzz/differential test against a no-prefilter set).
* Ignore rules are evaluated only after a match hits, and produce `OutcomeIgnored`.
* JSON mode uses `decode.Fields` with the union of `Fields` keys, ignore keys and `IPField`.
* Benchmark the non-matching path; it should be allocation-free.

## internal/window

```go
func New(threshold int, window time.Duration, maxTracked int, now func() time.Time) *Tracker

// Hit records one offense and reports whether the threshold was reached within
// the window. On true, the counter is reset so a persistent attacker triggers
// once per threshold rather than on every subsequent line.
func (t *Tracker) Hit(ip netip.Addr) (count int, triggered bool)
func (t *Tracker) Sweep()      // drop entries older than the window
func (t *Tracker) Len() int
func (t *Tracker) Forget(ip netip.Addr)
```
Ring buffer of `uint32` second-offsets from a daemon epoch, capacity == threshold; memory per IP
must be O(threshold), not O(hits). `maxTracked` enforces an LRU cap. `threshold == 1` must
trigger immediately. Not goroutine-safe by design (the aggregator owns it) — say so in the doc
comment.

## internal/source

```go
type Source interface {
    Name() string    // monitor name
    Run(ctx context.Context, out chan<- model.Event) error  // returns nil on ctx cancel
    Checkpoints() []model.Checkpoint                        // nil if not seekable
}

type CheckpointLookup interface{ Lookup(path string) (model.Checkpoint, bool) }

func NewTail(monitor, pattern, startAt string, cp CheckpointLookup, log *slog.Logger) (Source, error)
func NewListener(monitor, addr string, stripSyslog bool, log *slog.Logger) (Source, error)
func NewStdin(monitor string, r io.Reader, log *slog.Logger) (Source, error)
```
* Tail: fsnotify on the file and its parent dir; rotation via `SameFile`; truncation
  (`size < offset`) rewinds to 0; globs rescanned every 10s for new files; `startAt`
  checkpoint|end|beginning; missing file is not fatal.
* Max line 64 KiB; longer lines are truncated and counted, not dropped.
* Listener: `udp://`, `tcp://`, `unix://`; newline framing; `stripSyslog` peels
  `<PRI>timestamp host tag:`; cap 64 concurrent TCP conns.
* `Run` must be cancellable promptly; no goroutine leaks (`goleak`-style manual check in tests).

## internal/action

```go
type Spec struct {
    Name    string        // iptables|ipset|nft|cmd|dryrun
    Start, Ban, Unban, Stop string
    Shell   bool
    Timeout time.Duration
    DryRun  bool          // global --dry-run wraps any backend
}

type Backend interface {
    Name() string
    Start(ctx context.Context) error
    Ban(ctx context.Context, b model.Ban) error
    Unban(ctx context.Context, b model.Ban) error
    Stop(ctx context.Context) error
}

func New(spec Spec, r Runner, log *slog.Logger) (Backend, error)

// Runner executes an external command; tests substitute a recorder.
type Runner interface { Run(ctx context.Context, argv []string, shell bool) ([]byte, error) }
func NewExecRunner() Runner

// Executor serializes all firewall mutations (iptables is not concurrency-safe)
// and retries failures without blocking the pipeline.
func NewExecutor(b Backend, log *slog.Logger) *Executor
func (e *Executor) Run(ctx context.Context) error  // run in its own goroutine
func (e *Executor) Ban(b model.Ban)                // non-blocking enqueue
func (e *Executor) Unban(b model.Ban)
func (e *Executor) Stats() Stats                   // applied, failed, queued
```
* **iptables backend (the default, must support IPv6 from the start).**
  `Start`: create chain `BANHAMMER` in `filter` and insert `-I INPUT -j BANHAMMER` if absent —
  idempotent, and done for **both** `iptables` and `ip6tables`.
  `Ban`: `-I BANHAMMER -s <ip> -j DROP`; `Unban`: the same with `-D`. Binary chosen by
  `b.Family()`. Unban of an already-absent rule is not an error.
* `ipset`/`nft` backends per PROJECT.md §4.6, with v4 and v6 sets.
* `cmd`: templates with `{ip} {monitor} {count} {bantime} {family} {matched}`. Default is
  **no shell**: split with a proper tokenizer (respecting quotes) and `exec` directly.
  `{ip}` is rendered from the parsed `netip.Addr`, never from raw log text.
* Retry ×3 with backoff; per-command timeout from `Spec.Timeout`.
* Table-driven tests with a fake `Runner` asserting **exact argv**. No test may touch a real firewall.

## internal/store

```go
func Open(dir string) (*Store, error)     // mkdir -p, take a lockfile
func (s *Store) LoadBans() ([]model.Ban, error)
func (s *Store) SaveBans(bans []model.Ban) error       // atomic, debounced <=1/s
func (s *Store) LoadOffsets() (map[string]model.Checkpoint, error)
func (s *Store) SaveOffsets(map[string]model.Checkpoint) error
func (s *Store) Lookup(path string) (model.Checkpoint, bool)  // implements source.CheckpointLookup
func (s *Store) Flush() error             // force pending writes; call on shutdown
func (s *Store) Close() error
```
Atomic writes (tmp + `fsync` + rename). A corrupt or truncated state file must not stop the
daemon: log, rename it aside as `.corrupt`, and start fresh. Test that.

## internal/ban

```go
type Policy struct {
    Bantime, BantimeMax, FindHistory time.Duration
    Factor   float64
    OnRepeat string // ignore|extend
}

type Enforcer interface { Ban(model.Ban); Unban(model.Ban) }   // action.Executor
type Persister interface { SaveBans([]model.Ban) error }       // store.Store

type Options struct {
    Allowlist  []netip.Prefix
    AllowLocal bool
    Enforcer   Enforcer
    Persister  Persister
    Now        func() time.Time
    Log        *slog.Logger
}

func NewManager(o Options) *Manager
func (m *Manager) SetPolicy(monitor string, p Policy)
func (m *Manager) Restore(bans []model.Ban) error  // re-apply live bans, drop expired
func (m *Manager) Run(ctx context.Context) error   // owns the unban heap + a single timer
func (m *Manager) Offend(monitor string, ip netip.Addr, count int)  // threshold reached
func (m *Manager) Ban(ip netip.Addr, monitor string, d time.Duration) error // manual
func (m *Manager) Unban(ip netip.Addr) error
func (m *Manager) UnbanAll() error
func (m *Manager) Allowed(ip netip.Addr) bool      // allowlist check
func (m *Manager) Snapshot() []model.Ban
```
* **One** min-heap ordered by `Until` plus **one** `time.Timer` re-armed at the head. Never one
  timer per ban. Tests must inject `Now` and an injectable timer so they run instantly.
* Allowlist is checked before anything else; `AllowLocal` adds loopback plus the host's own
  interface addresses (inject the interface lister so tests are hermetic).
* Escalation: nth offense within `FindHistory` gets `min(Bantime*Factor^(n-1), BantimeMax)`.
* An already-banned IP re-offending: extend `Until` only when `OnRepeat == "extend"`.
