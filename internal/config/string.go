package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// labelWidth lines up values into a column. Wide enough for the longest key
// ("bantime_factor:") plus a space.
const labelWidth = 16

// String renders the fully resolved configuration: what Banhammer will actually
// do, defaults and all.
//
// This is the output of `banhammer check`, and its audience is someone asking
// "why is my monitor not firing?", so it favours completeness and a stable
// ordering over brevity. It is not valid YAML and is not meant to be re-parsed.
func (c *Config) String() string {
	if c == nil {
		return ""
	}
	var b strings.Builder

	kv(&b, 0, "state_dir", c.StateDir)
	kv(&b, 0, "log_format", c.LogFormat)
	kv(&b, 0, "queue_size", fmt.Sprintf("%d", c.QueueSize))
	kv(&b, 0, "allow_local", fmt.Sprintf("%t", c.AllowLocal))
	if len(c.Allowlist) == 0 {
		kv(&b, 0, "allowlist", "(empty)")
	} else {
		prefixes := make([]string, len(c.Allowlist))
		for i, p := range c.Allowlist {
			prefixes[i] = p.String()
		}
		kv(&b, 0, "allowlist", strings.Join(prefixes, ", "))
	}
	if c.Metrics.Listen == "" {
		kv(&b, 0, "metrics", "(disabled)")
	} else {
		kv(&b, 0, "metrics", c.Metrics.Listen)
	}

	b.WriteString("\ndefaults:\n")
	writeSettings(&b, 1, c.Defaults)

	for _, name := range c.MonitorNames() {
		m := c.Monitors[name]
		fmt.Fprintf(&b, "\nmonitor %q:\n", name)
		kv(&b, 1, "source", sourceOf(m))
		kv(&b, 1, "format", m.Format)
		if m.StripSyslog {
			kv(&b, 1, "strip_syslog", "true")
		}
		writeMulti(&b, 1, "match", patternLines(m.Match))
		if !m.Ignore.Empty() {
			writeMulti(&b, 1, "ignore", patternLines(m.Ignore))
		}
		if m.IPField != "" {
			kv(&b, 1, "ip_field", m.IPField)
		}
		if m.Contains != "" {
			kv(&b, 1, "contains", fmt.Sprintf("%q", m.Contains))
		}
		writeSettings(&b, 1, m.Settings)
	}
	return b.String()
}

// sourceOf describes where a monitor reads from, in one line.
func sourceOf(m *Monitor) string {
	switch {
	case m.File != "":
		return "file " + m.File
	case m.Listen != "":
		return "listen " + m.Listen
	case m.Stdin:
		return "stdin"
	default:
		return "(none)"
	}
}

func writeSettings(b *strings.Builder, indent int, s Settings) {
	kv(b, indent, "threshold", fmt.Sprintf("%d hits in %s", s.Threshold, fmtDur(s.Window)))
	kv(b, indent, "bantime", fmt.Sprintf("%s (factor %g, max %s)", fmtDur(s.Bantime), s.BantimeFactor, fmtDur(s.BantimeMax)))
	kv(b, indent, "find_history", fmtDur(s.FindHistory))
	kv(b, indent, "max_tracked", fmt.Sprintf("%d", s.MaxTracked))
	kv(b, indent, "start_at", s.StartAt)
	kv(b, indent, "on_repeat", s.OnRepeat)
	writeMulti(b, indent, "action", actionLines(s.Action))
}

// actionLines renders the backend and, for cmd, the templates that will be run.
func actionLines(a ActionSpec) []string {
	var parts []string
	if a.Chain != "" && a.Chain != defaultActionChain {
		parts = append(parts, "chain "+a.Chain)
	}
	parts = append(parts, "timeout "+fmtDur(a.Timeout))
	if a.Shell {
		parts = append(parts, "via shell")
	}
	if a.FlushOnExit {
		parts = append(parts, "flush on exit")
	}
	head := fmt.Sprintf("%s (%s)", a.Name, strings.Join(parts, ", "))
	lines := []string{head}
	for _, t := range []struct{ name, tmpl string }{
		{"start", a.Start}, {"ban", a.Ban}, {"unban", a.Unban}, {"stop", a.Stop},
	} {
		if t.tmpl != "" {
			lines = append(lines, fmt.Sprintf("%s = %q", t.name, t.tmpl))
		}
	}
	return lines
}

// patternLines renders either the OR-list of line regexes or the AND-map of
// field regexes.
func patternLines(p Patterns) []string {
	if p.Empty() {
		return []string{"(none)"}
	}
	if len(p.Fields) > 0 {
		lines := make([]string, 0, len(p.Fields))
		for _, f := range slices.Sorted(maps.Keys(p.Fields)) {
			lines = append(lines, fmt.Sprintf("field %s =~ %q", f, p.Fields[f]))
		}
		return lines
	}
	lines := make([]string, 0, len(p.Line))
	for _, s := range p.Line {
		lines = append(lines, fmt.Sprintf("%q", s))
	}
	return lines
}

func kv(b *strings.Builder, indent int, key, val string) {
	writeMulti(b, indent, key, []string{val})
}

// writeMulti prints key: v0 and aligns any further values under v0, so a
// monitor with five patterns still reads as one block.
func writeMulti(b *strings.Builder, indent int, key string, vals []string) {
	pad := strings.Repeat("  ", indent)
	label := key + ":"
	for i, v := range vals {
		if i == 0 {
			fmt.Fprintf(b, "%s%-*s%s\n", pad, labelWidth, label, v)
			continue
		}
		fmt.Fprintf(b, "%s%-*s%s\n", pad, labelWidth, "", v)
	}
}

// fmtDur prints durations the way the config file spells them ("10m", not
// "10m0s"), so that check output can be pasted back into YAML.
func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "0s"
	case d < 0:
		return "-" + fmtDur(-d)
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	case d%time.Second == 0:
		return fmt.Sprintf("%ds", d/time.Second)
	default:
		return d.String()
	}
}
