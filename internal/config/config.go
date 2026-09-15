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
	defaultBantimeFactor = 1
	defaultBantimeMax    = 168 * time.Hour
	defaultFindHistory   = 24 * time.Hour
	defaultMaxTracked    = 100000
	defaultStartAt       = "checkpoint"
	defaultOnRepeat      = "ignore"
	defaultAction        = "iptables"
	defaultActionTimeout = 10 * time.Second
	// commandAction is the backend name implied by inline command templates.
	commandAction = "cmd"
)

// Config is the fully resolved configuration: every field is populated, and
// every monitor's Settings have already been merged with Defaults.
type Config struct {
	StateDir   string // default /var/lib/banhammer
	LogFormat  string // text|json, default text
	AllowLocal bool   // default true
	Allowlist  []netip.Prefix
	Metrics    struct{ Listen string }
	QueueSize  int                 // default 8192
	Defaults   Settings            // the effective defaults, after built-ins
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
	Start   string // cmd templates; presence of Ban implies Name=="cmd"
	Ban     string
	Unban   string
	Stop    string
	Shell   bool
	Timeout time.Duration // default 10s
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
// A block whose YAML failed to decode is validated no further: its values are
// missing, so anything else said about it would be invented. The rest of the
// file is still validated, so one typo costs one round-trip, not one per
// mistake.
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
	raw, parseErrs := decode(src)
	if raw == nil {
		// The parser lost its place; nothing downstream can be trusted.
		return nil, &LoadError{Path: path, Errs: parseErrs}
	}

	cfg := resolve(raw)
	problems := validate(cfg, raw)
	if len(parseErrs) == 0 {
		if len(problems) == 0 {
			return cfg, nil
		}
		errs := make([]error, 0, len(problems))
		for _, p := range problems {
			errs = append(errs, p.error())
		}
		return nil, &LoadError{Path: path, Errs: errs}
	}

	owners := newLineOwners(src)
	undecoded := make(map[origin]bool, len(parseErrs))
	for _, err := range parseErrs {
		undecoded[owners.owner(errorLine(err))] = true
	}
	errs := make([]error, 0, len(parseErrs)+len(problems))
	errs = append(errs, parseErrs...)
	for _, p := range problems {
		if undecoded[p.origin] {
			continue
		}
		errs = append(errs, p.error())
	}
	return nil, &LoadError{Path: path, Errs: errs}
}

// errorLinePrefix matches the "line 12: " every decode problem carries.
var errorLinePrefix = regexp.MustCompile(`^line (\d+): `)

// errorLine extracts the source line a decode problem refers to, or 0 for the
// whole-file problems (a stray second document, say), which are attributed to
// the top level.
func errorLine(err error) int {
	m := errorLinePrefix.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	n, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return 0
	}
	return n
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
		Action:        ActionSpec{Name: defaultAction, Timeout: defaultActionTimeout},
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
		// An action is replaced wholesale rather than merged field by field.
		// Merging would combine `defaults: {action: iptables}` with a monitor's
		// command templates into a contradiction; "the monitor owns its action"
		// is the rule a reader can hold in their head.
		dst.Action = r.Action.resolve()
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

// resolve fills in an action's own defaults. Command templates imply the "cmd"
// backend, so `action: {ban: ..., unban: ...}` needs no name.
func (a *rawAction) resolve() ActionSpec {
	spec := ActionSpec{Name: defaultAction, Timeout: defaultActionTimeout}
	setIf(&spec.Name, a.Name)
	setIf(&spec.Start, a.Start)
	setIf(&spec.Ban, a.Ban)
	setIf(&spec.Unban, a.Unban)
	setIf(&spec.Stop, a.Stop)
	setIf(&spec.Shell, a.Shell)
	setDur(&spec.Timeout, a.Timeout)
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
