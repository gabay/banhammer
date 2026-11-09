// Package config loads, defaults and validates Banhammer's single YAML
// configuration file.
//
// Two properties drive the design. First, parsing is strict: an unknown key is
// a hard error naming the key, its line and the most likely intended spelling,
// because a silently ignored typo in a security tool means a monitor that
// quietly never fires. Second, problems are accumulated rather than reported
// one per run, so `banhammer check` can list everything wrong with a file in a
// single pass.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"
)

// Default values applied to any setting the file leaves unset. They are the
// values documented in config.example.yaml; keep the two in step.
const (
	defaultStateDir      = "/var/lib/banhammer"
	defaultLogFormat     = "text"
	defaultQueueSize     = 8192
	defaultFormat        = "text"
	defaultThreshold     = 5
	defaultWindow        = 10 * time.Minute
	defaultBantime       = time.Hour
	defaultBantimeFactor = 2
	defaultBantimeMax    = 168 * time.Hour
	defaultFindHistory   = 168 * time.Hour
	defaultMaxTracked    = 100000
	defaultStartAt       = "checkpoint"
	defaultOnRepeat      = "ignore"
	defaultAction        = "iptables"
	defaultActionChain   = "INPUT"
	defaultActionTimeout = 10 * time.Second
	// commandAction is the backend name implied by inline command templates.
	commandAction = "cmd"

	// DefaultWebListen is where the status page binds when `web.enabled` is
	// set without a `listen`. Loopback, not 0.0.0.0: the page lists every
	// banned address and every watched log path, which is reconnaissance for
	// anyone who can reach it. Exposing it is a decision the operator makes by
	// writing an address down.
	DefaultWebListen = "127.0.0.1:7890"
	// DefaultWebRetention is how far back the ban ledger behind the status
	// page remembers. Thirty days is the longest window the page reports.
	DefaultWebRetention = 30 * 24 * time.Hour
)

// maxQueueSize is the largest queue_size accepted.
//
// The queue is one channel allocated up front, so an over-enthusiastic value
// is not a slow degradation but an immediate out-of-memory at startup — after
// `banhammer check` has already said the file is fine. §6 promises memory is
// bounded by config; that only holds if the config itself is bounded.
const maxQueueSize = 1 << 20

// Config is the fully resolved configuration: every field is populated, and
// every monitor's Settings have already been merged with Defaults.
type Config struct {
	StateDir   string // default /var/lib/banhammer
	LogFormat  string // text|json, default text
	AllowLocal bool   // default true
	Allowlist  []netip.Prefix
	Metrics    Metrics
	Web        Web
	QueueSize  int                 // default 8192
	Defaults   Settings            // the effective defaults, after built-ins
	Monitors   map[string]*Monitor // key = monitor name
}

// Metrics is the optional Prometheus endpoint. It is a named type, not an
// anonymous struct, so that a caller building a Config in code (tests and
// benchmarks do) can name the thing it is assigning.
type Metrics struct {
	Listen string // host:port; empty disables the endpoint
}

// Web is the optional read-only status page.
//
// Unlike Metrics it has an explicit Enabled switch rather than "set listen to
// turn it on": the page has a well-known default port, and the point of a
// default port is that turning the feature on should not require choosing one.
type Web struct {
	Enabled   bool
	Listen    string        // host:port; default DefaultWebListen
	GeoIP     string        // path to a country database; empty disables geography
	Retention time.Duration // how long ban events are kept for statistics; default 30d
	// LogLines keeps the log line that triggered each ban, for display.
	// Default true; off is for operators whose logs carry things (usernames,
	// URLs) they would rather not have on a dashboard or in history.json.
	LogLines bool
}

// Settings are the knobs that may appear under `defaults:` or on a monitor.
type Settings struct {
	Threshold     int           // default 5
	Window        time.Duration // default 10m
	Bantime       time.Duration // default 1h
	BantimeFactor float64       // default 2 (doubles bantime per repeat offense)
	BantimeMax    time.Duration // default 168h
	FindHistory   time.Duration // default 168h
	MaxTracked    int           // default 100000
	StartAt       string        // checkpoint|end|beginning, default checkpoint
	OnRepeat      string        // ignore|extend, default ignore
	Action        ActionSpec
}

// Monitor is one log source plus the rules applied to it.
type Monitor struct {
	Name        string // filled from the map key
	File        string // path or glob      } exactly one of these
	Listen      string // scheme://host:port } three must be set
	Stdin       bool   //                    }
	Format      string // text|json, default text
	StripSyslog bool
	Match       Patterns
	Ignore      Patterns
	IPField     string // JSON dotted path; mutually exclusive with an <IP> group in Match
	Contains    string // optional literal prefilter override
	Settings           // embedded; fully resolved against Defaults by Load
}

// ActionSpec selects and parameterises the firewall backend.
type ActionSpec struct {
	Name    string // iptables|ipset|nft|dryrun|cmd; default iptables
	Chain   string // firewall chain or netfilter hook; default INPUT
	Start   string // cmd templates; presence of Ban implies Name=="cmd"
	Ban     string
	Unban   string
	Stop    string
	Shell   bool
	Timeout time.Duration // default 10s
	// FlushOnExit tears down the chain/table/sets this backend created (and
	// every rule in them) when the daemon stops cleanly. Default false: bans
	// survive a restart, matching the persisted state. Ignored by the cmd
	// backend, which already gives the operator a `stop` template for this.
	FlushOnExit bool
}

// LoadError reports every problem found in a configuration file at once.
//
// It implements Unwrap() []error, so errors.Is and errors.As see through to the
// individual problems.
type LoadError struct {
	Path string // the file the problems came from; may be empty
	Errs []error
}

// Error renders one problem per line, indented, under a summary header.
func (e *LoadError) Error() string {
	var b []byte
	if e.Path != "" {
		b = append(b, e.Path...)
		b = append(b, ": "...)
	}
	noun := "problems"
	if len(e.Errs) == 1 {
		noun = "problem"
	}
	b = append(b, fmt.Sprintf("%d %s", len(e.Errs), noun)...)
	for _, err := range e.Errs {
		b = append(b, "\n  - "...)
		b = append(b, err.Error()...)
	}
	return string(b)
}

// Unwrap exposes the individual problems to the errors package.
func (e *LoadError) Unwrap() []error { return e.Errs }

// Load reads path, applies defaults and validates the result.
//
// On failure the returned error is a *LoadError listing every problem found.
//
// A block whose YAML lost a value — a wrong shape, a duration that did not
// parse — is validated no further: the value is missing, so anything else said
// about it would be invented. An unknown key costs nothing, so its block is
// still validated. Either way the rest of the file is validated, so one
// mistake costs one round-trip, not one per mistake.
func Load(path string) (*Config, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return parse(src, path)
}

// parse is Load without the filesystem, so tests (and any future non-file
// source) can exercise the whole pipeline on a byte slice.
func parse(src []byte, path string) (*Config, error) {
	raw, parseProblems := decode(src)
	if raw == nil {
		// The parser lost its place; nothing downstream can be trusted.
		return nil, &LoadError{Path: path, Errs: problemErrors(parseProblems)}
	}

	cfg := resolve(raw)
	problems := validate(cfg, raw)
	if len(parseProblems) == 0 {
		if len(problems) == 0 {
			return cfg, nil
		}
		errs := make([]error, 0, len(problems))
		for _, p := range problems {
			errs = append(errs, p.error())
		}
		return nil, &LoadError{Path: path, Errs: errs}
	}

	errs := make([]error, 0, len(parseProblems)+len(problems))
	errs = append(errs, problemErrors(parseProblems)...)
	undecoded := lostBlocks(src, parseProblems)
	for _, p := range problems {
		if undecoded[p.origin] {
			continue
		}
		errs = append(errs, p.error())
	}
	return nil, &LoadError{Path: path, Errs: errs}
}

// problemErrors is the decode problems as plain errors, for the report.
func problemErrors(ps []parseProblem) []error {
	errs := make([]error, 0, len(ps))
	for _, p := range ps {
		errs = append(errs, p.err)
	}
	return errs
}

// lostBlocks is the set of blocks whose values did not survive decoding, and
// which must therefore not be validated.
func lostBlocks(src []byte, ps []parseProblem) map[origin]bool {
	lost := make(map[origin]bool, len(ps))
	owners := newLineOwners(src)
	for _, p := range ps {
		if !p.valuesLost {
			continue
		}
		line, ok := errorLine(p.err)
		if !ok {
			// The problem is about the file rather than about a block (a
			// stray second document is the only one). It has no line to
			// attribute, and line 0 would resolve to the global scope and
			// silence every global check.
			continue
		}
		lost[owners.owner(line)] = true
	}
	return lost
}

// errorLinePrefix matches the "line 12: " a decode problem about a particular
// place in the file carries.
var errorLinePrefix = regexp.MustCompile(`^line (\d+): `)

// errorLine extracts the source line a decode problem refers to. It reports
// false for a problem about the whole file, which belongs to no block: there
// is no such thing as line 0, and pretending otherwise attributes the problem
// to the top level.
func errorLine(err error) (int, bool) {
	m := errorLinePrefix.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	n, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return 0, false
	}
	return n, true
}

// builtinDefaults is the configuration of a file that sets nothing at all.
func builtinDefaults() Settings {
	return Settings{
		Threshold:     defaultThreshold,
		Window:        defaultWindow,
		Bantime:       defaultBantime,
		BantimeFactor: defaultBantimeFactor,
		BantimeMax:    defaultBantimeMax,
		FindHistory:   defaultFindHistory,
		MaxTracked:    defaultMaxTracked,
		StartAt:       defaultStartAt,
		OnRepeat:      defaultOnRepeat,
		Action: ActionSpec{
			Name:    defaultAction,
			Chain:   defaultActionChain,
			Timeout: defaultActionTimeout,
		},
	}
}

// resolve turns the raw document into the effective configuration. It never
// fails: anything nonsensical is left in place for validate to report with
// context.
func resolve(raw *rawConfig) *Config {
	c := &Config{
		StateDir:   defaultStateDir,
		LogFormat:  defaultLogFormat,
		AllowLocal: true,
		QueueSize:  defaultQueueSize,
		Defaults:   builtinDefaults(),
		Monitors:   make(map[string]*Monitor, len(raw.Monitors)),
	}
	setIf(&c.StateDir, raw.StateDir)
	setIf(&c.LogFormat, raw.LogFormat)
	setIf(&c.AllowLocal, raw.AllowLocal)
	setNum(&c.QueueSize, raw.QueueSize)
	if raw.Metrics != nil {
		setIf(&c.Metrics.Listen, raw.Metrics.Listen)
	}
	c.Web = Web{Listen: DefaultWebListen, Retention: DefaultWebRetention, LogLines: true}
	if raw.Web != nil {
		setIf(&c.Web.Enabled, raw.Web.Enabled)
		setIf(&c.Web.Listen, raw.Web.Listen)
		setIf(&c.Web.GeoIP, raw.Web.GeoIP)
		setDur(&c.Web.Retention, raw.Web.Retention)
		setIf(&c.Web.LogLines, raw.Web.LogLines)
	}
	if len(raw.Allowlist) > 0 {
		c.Allowlist = make([]netip.Prefix, 0, len(raw.Allowlist))
		for _, p := range raw.Allowlist {
			c.Allowlist = append(c.Allowlist, p.Prefix)
		}
	}

	applySettings(&c.Defaults, raw.Defaults)

	for name, rm := range raw.Monitors {
		m := &Monitor{
			Name:     name,
			Format:   defaultFormat,
			Settings: c.Defaults,
		}
		if rm == nil { // `sshd:` with an empty body
			c.Monitors[name] = m
			continue
		}
		setIf(&m.File, rm.File)
		setIf(&m.Listen, rm.Listen)
		setIf(&m.Stdin, rm.Stdin)
		setIf(&m.Format, rm.Format)
		setIf(&m.StripSyslog, rm.StripSyslog)
		setIf(&m.IPField, rm.IPField)
		setIf(&m.Contains, rm.Contains)
		m.Match = rm.Match
		m.Ignore = rm.Ignore
		applySettings(&m.Settings, &rm.rawSettings)
		c.Monitors[name] = m
	}
	return c
}

// applySettings overlays the keys r actually set onto dst.
func applySettings(dst *Settings, r *rawSettings) {
	if r == nil {
		return
	}
	setNum(&dst.Threshold, r.Threshold)
	setDur(&dst.Window, r.Window)
	setDur(&dst.Bantime, r.Bantime)
	setNum(&dst.BantimeFactor, r.BantimeFactor)
	setDur(&dst.BantimeMax, r.BantimeMax)
	setDur(&dst.FindHistory, r.FindHistory)
	setNum(&dst.MaxTracked, r.MaxTracked)
	setIf(&dst.StartAt, r.StartAt)
	setIf(&dst.OnRepeat, r.OnRepeat)
	if r.Action != nil {
		// Named backend parameters (name, chain, timeout) are inherited from
		// dst.Action unless overridden; command templates are never inherited
		// across actions so a monitor switching backends doesn't inherit stale
		// shell commands.
		dst.Action = r.Action.resolve(dst.Action)
	}
}

func setIf[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

func setDur(dst *time.Duration, src *duration) {
	if src != nil {
		*dst = src.get()
	}
}

// setNum copies one of the strict numeric wrappers onto its plain counterpart.
func setNum[S ~int | ~float64, D int | float64](dst *D, src *S) {
	if src != nil {
		*dst = D(*src)
	}
}

// resolve fills in an action's effective settings using base as defaults.
// When neither a backend name nor command templates are given (e.g.
// `action: {chain: DOCKER-USER}`), the monitor inherits the base backend
// (including any command templates and timeout); when a backend name or
// templates are specified, chain is inherited from base while timeout resets
// to defaultActionTimeout unless explicitly set.
func (a *rawAction) resolve(base ActionSpec) ActionSpec {
	spec := ActionSpec{
		Name:    defaultAction,
		Chain:   defaultActionChain,
		Timeout: defaultActionTimeout,
	}
	if a.Name == nil && !a.hasTemplates() {
		spec = base
		if spec.Name == "" {
			spec.Name = defaultAction
		}
		if spec.Chain == "" {
			spec.Chain = defaultActionChain
		}
		if spec.Timeout <= 0 {
			spec.Timeout = defaultActionTimeout
		}
	} else if base.Chain != "" {
		spec.Chain = base.Chain
	}
	setIf(&spec.Name, a.Name)
	setIf(&spec.Chain, a.Chain)
	setIf(&spec.Start, a.Start)
	setIf(&spec.Ban, a.Ban)
	setIf(&spec.Unban, a.Unban)
	setIf(&spec.Stop, a.Stop)
	setIf(&spec.Shell, a.Shell)
	setDur(&spec.Timeout, a.Timeout)
	setIf(&spec.FlushOnExit, a.FlushOnExit)
	if a.Name == nil && a.hasTemplates() {
		spec.Name = commandAction
	}
	return spec
}

// hasTemplates reports whether any command template was given. Timeout and
// shell are excluded: they tune a named backend just as well as a cmd one.
func (a *rawAction) hasTemplates() bool {
	return a.Start != nil || a.Ban != nil || a.Unban != nil || a.Stop != nil
}

// MonitorNames returns the monitor names in sorted order, which is the order
// the CLI should use whenever it lists them.
func (c *Config) MonitorNames() []string {
	names := make([]string, 0, len(c.Monitors))
	for name := range c.Monitors {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
