package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"banhammer/internal/rule"
)

// Enumerations the file may use. Kept as slices so error messages can list the
// accepted values rather than leaving the user to guess.
var (
	// validFormats covers both the global log_format and a monitor's format:
	// they have always been the same two words, and two lists would only be a
	// chance for them to stop being so.
	validFormats  = []string{"text", "json"}
	validStartAt  = []string{"checkpoint", "end", "beginning"}
	validOnRepeat = []string{"ignore", "extend"}
	validActions  = []string{"iptables", "ipset", "nft", "dryrun", "cmd"}
	validNFTHooks = []string{"input", "forward", "output", "prerouting", "postrouting"}
	validSchemes  = []string{"udp", "tcp", "unix"}
)

// validChainRe constrains iptables/ipset chain names and nft hook names to
// safe identifiers (iptables chains allow up to 28 characters of ASCII letters,
// digits, underscores, and hyphens).
var validChainRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)

// monitorNameRe keeps monitor names to characters that are safe to interpolate
// into a {monitor} command template and to use as a state-file key.
//
// '.' and '-' are barred from the first position, where they would make a
// hidden state file or a name that reads as a command-line flag; '_' is not,
// because it does neither and the error message has always said underscores
// are fine.
var monitorNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// ipGroupRe spots a hand-written IP capture group, the alternative to the <IP>
// macro. Both spellings are accepted: Go 1.22 added (?<name>...) alongside the
// older (?P<name>...), and rule.Compile honours both. The name is lower case
// because that is the one name rule treats as the address.
var ipGroupRe = regexp.MustCompile(`\(\?P?<ip>`)

// groupNameRe matches the whole of a capture group's name, e.g. `(?P<ip>`.
// rule's scanner consumes these before it looks for macros; this package has
// to skip them for the same reason.
var groupNameRe = regexp.MustCompile(`\(\?P?<\w*>`)

// macroAsGroupNameRe spots a macro used where a group name belongs, as in
// `(?P<IP>[0-9.]+)` — a plausible reading of the docs that captures nothing.
var macroAsGroupNameRe = regexp.MustCompile(`\(\?P?<(?i:ip|host)>`)

// problem is a validation failure plus the block it belongs to.
type problem struct {
	origin origin
	err    error
}

// error renders the problem with its block prefix.
func (p problem) error() error {
	if pre := p.origin.prefix(); pre != "" {
		return fmt.Errorf("%s%w", pre, p.err)
	}
	return p.err
}

// validate reports everything wrong with the resolved configuration.
//
// Problems are ordered — globals, then defaults, then monitors by name — so the
// output of `banhammer check` is stable and diffable.
func validate(c *Config, raw *rawConfig) []problem {
	var problems []problem
	add := func(o origin, errs ...error) {
		for _, err := range errs {
			problems = append(problems, problem{origin: o, err: err})
		}
	}

	if c.StateDir == "" {
		add(globalOrigin(), errors.New("state_dir must not be empty"))
	}
	if !slices.Contains(validFormats, c.LogFormat) {
		add(globalOrigin(), fmt.Errorf("log_format must be one of %s, got %q", list(validFormats), c.LogFormat))
	}
	switch {
	case c.QueueSize < 1:
		add(globalOrigin(), fmt.Errorf("queue_size must be at least 1, got %d", c.QueueSize))
	case c.QueueSize > maxQueueSize:
		add(globalOrigin(), fmt.Errorf("queue_size must be at most %d, got %d: the queue is allocated in full at startup", maxQueueSize, c.QueueSize))
	}
	if c.Metrics.Listen != "" {
		if err := checkHostPort(c.Metrics.Listen); err != nil {
			add(globalOrigin(), fmt.Errorf("metrics.listen: %w", err))
		}
	}
	if len(c.Monitors) == 0 {
		add(globalOrigin(), errors.New("no monitors defined: nothing would be watched"))
	}
	add(globalOrigin(), checkSourceConflicts(c)...)

	var defaultAction *rawAction
	if raw.Defaults != nil {
		defaultAction = raw.Defaults.Action
	}
	add(defaultsOrigin(), checkSettings(c.Defaults, allSettings(), defaultAction)...)

	for _, name := range c.MonitorNames() {
		add(monitorOrigin(name), checkMonitor(c.Monitors[name], raw.Monitors[name])...)
	}
	return problems
}

// checkSourceConflicts reports monitors that would fight over one input.
//
// Both clashes are global rather than per-monitor: neither monitor is wrong on
// its own, and blaming one of the two would be a coin toss.
func checkSourceConflicts(c *Config) []error {
	var errs []error

	// Only one monitor can own the process's stdin; a second would read the
	// other's leftovers at best.
	var readers []string
	byListen := make(map[string][]string, len(c.Monitors))
	for _, name := range c.MonitorNames() {
		m := c.Monitors[name]
		if m.Stdin {
			readers = append(readers, strconv.Quote(name))
		}
		if m.Listen != "" {
			byListen[m.Listen] = append(byListen[m.Listen], strconv.Quote(name))
		}
	}
	if len(readers) > 1 {
		errs = append(errs, fmt.Errorf("monitors %s all read stdin, but there is only one stdin", list(readers)))
	}
	// Two monitors on one address fail at bind time instead, which is a
	// startup crash rather than a `banhammer check` complaint — and by then
	// the operator is watching a service that will not come up.
	for _, addr := range slices.Sorted(maps.Keys(byListen)) {
		if names := byListen[addr]; len(names) > 1 {
			errs = append(errs, fmt.Errorf("monitors %s all listen on %q, but only one of them can bind it", list(names), addr))
		}
	}
	return errs
}

// checkMonitor validates one monitor's own keys and the settings it overrode.
//
// Settings it merely inherited are skipped: a bad `defaults: threshold: 0` is
// one problem with the defaults block, not one problem per monitor.
func checkMonitor(m *Monitor, rm *rawMonitor) []error {
	var errs []error

	if !monitorNameRe.MatchString(m.Name) {
		errs = append(errs, errors.New("invalid name: use letters, digits, '.', '-' and '_', starting with a letter, digit or '_'"))
	}
	errs = append(errs, checkMonitorSource(m, rm)...)

	// Both halves report whether the spec is still worth handing to
	// rule.Compile: compiling an incoherent one would report the same problem
	// twice, in rule's words and in ours.
	shapeErrs, shapeOK := checkMonitorFormat(m)
	errs = append(errs, shapeErrs...)
	errs = append(errs, checkPatternText(m.Match, "match")...)
	errs = append(errs, checkPatternText(m.Ignore, "ignore")...)
	errs = append(errs, checkContains(rm)...)

	addrErrs, addrOK := checkAddressSource(m)
	errs = append(errs, addrErrs...)

	if shapeOK && addrOK {
		errs = append(errs, compileErrors(m)...)
	}
	return append(errs, checkMonitorSettings(m, rm)...)
}

// checkMonitorSource enforces exactly one input, and that it is usable.
func checkMonitorSource(m *Monitor, rm *rawMonitor) []error {
	var errs []error

	// `file: ""` and `file: "   "` are the same mistake, so they get the same
	// message: a written-but-empty key is a half-finished edit, not a monitor
	// that forgot to say where it reads from.
	fileSet := m.File != "" || (rm != nil && rm.File != nil)
	var sources []string
	if fileSet {
		sources = append(sources, "file")
		if strings.TrimSpace(m.File) == "" {
			errs = append(errs, errors.New("file is blank: give a path or a glob"))
		}
	}
	if m.Listen != "" {
		sources = append(sources, "listen")
	}
	if m.Stdin {
		sources = append(sources, "stdin")
	}
	switch len(sources) {
	case 0:
		errs = append(errs, errors.New("no source: set exactly one of file, listen or stdin"))
	case 1:
		// ok
	default:
		errs = append(errs, fmt.Errorf("sources %s are mutually exclusive: set exactly one", list(sources)))
	}

	if m.Listen != "" {
		if err := checkListen(m.Listen); err != nil {
			errs = append(errs, fmt.Errorf("listen: %w", err))
		}
	}
	return errs
}

// checkMonitorFormat checks the keys that only mean anything for one format,
// and reports whether the combination still describes a compilable rule.
func checkMonitorFormat(m *Monitor) (errs []error, ok bool) {
	ok = true
	isJSON := m.Format == "json"
	if !slices.Contains(validFormats, m.Format) {
		errs = append(errs, fmt.Errorf("format must be one of %s, got %q", list(validFormats), m.Format))
		ok = false
	}
	if m.IPField != "" && !isJSON {
		errs = append(errs, errors.New("ip_field requires format: json"))
		ok = false
	}
	if len(m.Match.Fields) > 0 && !isJSON {
		errs = append(errs, errors.New("a field map in match requires format: json"))
		ok = false
	}
	if len(m.Ignore.Fields) > 0 && !isJSON {
		errs = append(errs, errors.New("a field map in ignore requires format: json"))
		ok = false
	}
	return errs, ok
}

// checkContains rejects a `contains:` key that was written but left empty.
//
// rule treats an empty prefilter as "no prefilter", so the key would do
// nothing at all — and a filter that is silently not applied is exactly the
// surprise this package exists to prevent. Whitespace is left alone: a literal
// space is a legitimate thing to require in a line.
func checkContains(rm *rawMonitor) []error {
	if rm == nil || rm.Contains == nil || *rm.Contains != "" {
		return nil
	}
	return []error{errors.New("contains is empty: give a literal substring to require, or drop the key")}
}

// checkAddressSource makes sure the monitor could ever produce an address to
// ban, and reports whether the answer was clear enough to compile.
//
// rule.Compile does not check this — a pattern with no IP group is legal, it
// just yields OutcomeNoIP at runtime — so the check lives here, where it can
// be phrased as advice.
func checkAddressSource(m *Monitor) (errs []error, ok bool) {
	switch {
	case m.Match.Empty():
		return []error{errors.New("no match patterns: the monitor could never fire")}, false

	case m.IPField != "":
		for _, p := range m.Match.Line {
			if hasIPGroup(p) {
				return []error{fmt.Errorf("ip_field and an <IP> group in match %q are mutually exclusive: pick one source for the address", p)}, false
			}
		}

	case len(m.Match.Fields) > 0:
		return []error{errors.New("a field map in match cannot capture an address: set ip_field")}, true

	default:
		for _, p := range m.Match.Line {
			// A blank pattern has already been reported by checkPatternText;
			// adding "and it has no <IP>" on top is just noise.
			if strings.TrimSpace(p) == "" || hasIPGroup(p) {
				continue
			}
			errs = append(errs, fmt.Errorf("match %q contains no <IP>, <HOST> or (?P<ip>...) group, so no address could be extracted%s", p, macroCaseHint(p)))
		}
	}
	return errs, true
}

// checkMonitorSettings validates the settings this monitor set for itself.
func checkMonitorSettings(m *Monitor, rm *rawMonitor) []error {
	var errs []error
	var set settingsMask
	var action *rawAction
	if rm != nil {
		set = rm.rawSettings.present()
		action = rm.rawSettings.Action
		// An action block that names no backend, sets no chain, and carries no
		// templates would silently replace an inherited cmd action with plain
		// iptables, since a monitor's action is taken as a whole rather than merged.
		if action != nil && action.Name == nil && action.Chain == nil && !action.hasTemplates() {
			errs = append(errs, errors.New("action: set a backend name, chain, or command templates; timeout/shell alone cannot override the inherited action"))
		}
	}
	return append(errs, checkSettings(m.Settings, set, action)...)
}

// compileErrors asks internal/rule to compile the monitor's patterns.
//
// rule is the authority on pattern validity: it owns <IP> expansion, the
// one-IP-group rule and the regex syntax itself. Re-implementing any of that
// here would drift, and a config that passes `banhammer check` but kills the
// daemon at startup is the worst possible outcome.
func compileErrors(m *Monitor) []error {
	_, err := rule.Compile(rule.Spec{
		Format:       m.Format,
		Line:         m.Match.Line,
		Fields:       m.Match.Fields,
		IgnoreLine:   m.Ignore.Line,
		IgnoreFields: m.Ignore.Fields,
		IPField:      m.IPField,
		Contains:     m.Contains,
	})
	if err == nil {
		return nil
	}
	return []error{errors.New(tidyRuleError(err))}
}

// tidyRuleError drops rule's package prefix; the message is already being
// printed under `monitor "sshd":`.
func tidyRuleError(err error) string {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, "rule: "); ok {
		return rest
	}
	if rest, ok := strings.CutPrefix(msg, "ignore: rule: "); ok {
		return "ignore: " + rest
	}
	return msg
}

// macroCaseHint catches the two commonest near-misses: the macro written in
// lower case, which is just an ordinary bit of regex, and the macro written as
// a capture-group name, which rule reads as a name and never fills in.
func macroCaseHint(pattern string) string {
	switch {
	case macroAsGroupNameRe.MatchString(pattern):
		return " (a name in (?P<...>) is a name, not the macro: write the group as (?P<ip>...))"
	case strings.Contains(pattern, "<ip>") || strings.Contains(pattern, "<host>"):
		return " (the macro is spelled in capitals: <IP>)"
	}
	return ""
}

// checkPatternText rejects patterns that are present but empty, which match
// every line and would ban the world.
func checkPatternText(p Patterns, key string) []error {
	var errs []error
	for _, s := range p.Line {
		if strings.TrimSpace(s) == "" {
			errs = append(errs, fmt.Errorf("%s contains an empty pattern, which would match every line", key))
		}
	}
	for _, field := range slices.Sorted(maps.Keys(p.Fields)) {
		if strings.TrimSpace(p.Fields[field]) == "" {
			errs = append(errs, fmt.Errorf("%s pattern for field %q is empty, which would match every value", key, field))
		}
	}
	return errs
}

func hasIPGroup(pattern string) bool {
	if ipGroupRe.MatchString(pattern) {
		return true
	}
	// rule reads the '<' that opens a capture-group name as a name, not as a
	// macro, so `(?P<IP>...)` captures nothing this package can ban. Blanking
	// the names before looking for macros keeps the two in step; spotting the
	// difference by eye is what let a monitor that could never fire through
	// `banhammer check`.
	bare := groupNameRe.ReplaceAllString(pattern, "")
	return strings.Contains(bare, "<IP>") || strings.Contains(bare, "<HOST>")
}

// settingsMask records which settings a block set explicitly, so that a value
// is validated where it was written.
type settingsMask struct {
	threshold, window, bantime, bantimeFactor, bantimeMax bool
	findHistory, maxTracked, startAt, onRepeat, action    bool
}

func allSettings() settingsMask {
	return settingsMask{
		threshold: true, window: true, bantime: true, bantimeFactor: true, bantimeMax: true,
		findHistory: true, maxTracked: true, startAt: true, onRepeat: true, action: true,
	}
}

// present reports which settings this block set explicitly. The caller must
// hold a real block; an absent one is allSettings()'s or the zero mask's job.
func (r *rawSettings) present() settingsMask {
	return settingsMask{
		threshold:     r.Threshold != nil,
		window:        r.Window != nil,
		bantime:       r.Bantime != nil,
		bantimeFactor: r.BantimeFactor != nil,
		bantimeMax:    r.BantimeMax != nil,
		findHistory:   r.FindHistory != nil,
		maxTracked:    r.MaxTracked != nil,
		startAt:       r.StartAt != nil,
		onRepeat:      r.OnRepeat != nil,
		action:        r.Action != nil,
	}
}

func checkSettings(s Settings, set settingsMask, ra *rawAction) []error {
	var errs []error
	if set.threshold && s.Threshold < 1 {
		errs = append(errs, fmt.Errorf("threshold must be at least 1, got %d", s.Threshold))
	}
	if set.window && s.Window <= 0 {
		errs = append(errs, fmt.Errorf("window must be greater than zero, got %s", fmtDur(s.Window)))
	}
	if set.bantime && s.Bantime <= 0 {
		errs = append(errs, fmt.Errorf("bantime must be greater than zero, got %s", fmtDur(s.Bantime)))
	}
	if set.bantimeFactor && s.BantimeFactor < 1 {
		errs = append(errs, fmt.Errorf("bantime_factor must be at least 1 (1 means no escalation), got %g", s.BantimeFactor))
	}
	if set.bantimeMax && s.BantimeMax <= 0 {
		errs = append(errs, fmt.Errorf("bantime_max must be greater than zero, got %s", fmtDur(s.BantimeMax)))
	}
	if (set.bantime || set.bantimeMax) && s.Bantime > 0 && s.BantimeMax > 0 && s.BantimeMax < s.Bantime {
		errs = append(errs, fmt.Errorf("bantime_max (%s) is shorter than bantime (%s)", fmtDur(s.BantimeMax), fmtDur(s.Bantime)))
	}
	if set.findHistory && s.FindHistory <= 0 {
		errs = append(errs, fmt.Errorf("find_history must be greater than zero, got %s", fmtDur(s.FindHistory)))
	}
	if set.maxTracked && s.MaxTracked < 1 {
		errs = append(errs, fmt.Errorf("max_tracked must be at least 1, got %d", s.MaxTracked))
	}
	if set.startAt && !slices.Contains(validStartAt, s.StartAt) {
		errs = append(errs, fmt.Errorf("start_at must be one of %s, got %q", list(validStartAt), s.StartAt))
	}
	if set.onRepeat && !slices.Contains(validOnRepeat, s.OnRepeat) {
		errs = append(errs, fmt.Errorf("on_repeat must be one of %s, got %q", list(validOnRepeat), s.OnRepeat))
	}
	if set.action {
		errs = append(errs, checkAction(s.Action, ra)...)
	}
	return errs
}

func checkAction(a ActionSpec, ra *rawAction) []error {
	var errs []error
	if !slices.Contains(validActions, a.Name) {
		errs = append(errs, fmt.Errorf("action %q is not one of %s", a.Name, list(validActions)))
	}
	if ra != nil && ra.Chain != nil && strings.TrimSpace(*ra.Chain) == "" {
		errs = append(errs, errors.New("action chain cannot be empty"))
	} else if a.Chain != "" && !validChainRe.MatchString(a.Chain) {
		errs = append(errs, fmt.Errorf("action chain %q must be 1..28 letters, digits, underscores or hyphens", a.Chain))
	} else if a.Name == "nft" && a.Chain != "" && !slices.Contains(validNFTHooks, strings.ToLower(a.Chain)) {
		errs = append(errs, fmt.Errorf("action %q attaches to a netfilter hook (%s), not an iptables chain like %q; use action \"iptables\" or \"ipset\" to attach to %q", a.Name, list(validNFTHooks), a.Chain, a.Chain))
	}
	if a.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("action timeout must be greater than zero, got %s", fmtDur(a.Timeout)))
	}
	switch {
	case a.Ban != "" && a.Unban == "":
		errs = append(errs, errors.New("action has a ban template but no unban template: bans would never be lifted"))
	case a.Unban != "" && a.Ban == "":
		errs = append(errs, errors.New("action has an unban template but no ban template"))
	}
	if a.Name == commandAction && a.Ban == "" {
		errs = append(errs, fmt.Errorf("action %q requires ban and unban command templates", commandAction))
	}
	// A named backend plus command templates is ambiguous: the templates would
	// be silently dropped, which is the failure mode this package exists to
	// avoid.
	if ra != nil && ra.Name != nil && *ra.Name != commandAction && ra.hasTemplates() {
		errs = append(errs, fmt.Errorf("action %q cannot be combined with command templates; drop the name to use %q", a.Name, commandAction))
	}
	return errs
}

// checkListen validates a monitor's listen address, which the source package
// will later hand to net.Listen/net.ListenPacket.
func checkListen(addr string) error {
	scheme, rest, ok := strings.Cut(addr, "://")
	if !ok {
		return fmt.Errorf("%q needs a scheme, e.g. udp://0.0.0.0:5140", addr)
	}
	if !slices.Contains(validSchemes, scheme) {
		return fmt.Errorf("scheme %q must be one of %s", scheme, list(validSchemes))
	}
	if scheme == "unix" {
		if rest == "" {
			return errors.New("unix:// needs a socket path")
		}
		return nil
	}
	return checkHostPort(rest)
}

func checkHostPort(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must be host:port", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q has an invalid port %q", addr, port)
	}
	return nil
}

// list renders accepted values for an error message.
func list(ss []string) string { return strings.Join(ss, ", ") }
