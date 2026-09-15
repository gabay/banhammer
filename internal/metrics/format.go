package metrics

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type metricDef struct {
	name   string
	help   string
	typ    string
	metric *labeledMetric
}

// WritePrometheus serializes the current metric values into standard Prometheus
// exposition text format (version 0.0.4) and writes them to w.
//
// Metric families are emitted in deterministic canonical order. Within each family,
// label pairs are sorted lexicographically to ensure reproducible output for diffs
// and stable scrapers. Only metric families containing at least one recorded sample
// (or scalar metrics like uptime_seconds) are emitted.
func (r *Registry) WritePrometheus(w io.Writer) error {
	prefix := r.getPrefix()

	defs := []metricDef{
		{
			name:   "lines_read",
			help:   "Total number of log lines read from sources.",
			typ:    "counter",
			metric: r.linesRead,
		},
		{
			name:   "lines_dropped",
			help:   "Total number of log lines dropped due to queue saturation or buffer limits.",
			typ:    "counter",
			metric: r.linesDropped,
		},
		{
			name:   "matches",
			help:   "Total number of log lines matching monitor attack patterns.",
			typ:    "counter",
			metric: r.matches,
		},
		{
			name:   "bans",
			help:   "Total number of firewall ban actions executed.",
			typ:    "counter",
			metric: r.bans,
		},
		{
			name:   "unbans",
			help:   "Total number of firewall unban actions executed.",
			typ:    "counter",
			metric: r.unbans,
		},
		{
			name:   "action_errors",
			help:   "Total number of firewall action execution failures.",
			typ:    "counter",
			metric: r.actionErrors,
		},
		{
			name:   "decode_errors",
			help:   "Total number of log decoding or JSON parsing failures.",
			typ:    "counter",
			metric: r.decodeErrors,
		},
		{
			name:   "tracked_ips",
			help:   "Current number of unique offending IP addresses tracked in memory.",
			typ:    "gauge",
			metric: r.trackedIPs,
		},
		{
			name:   "active_bans",
			help:   "Current number of active firewall IP bans in effect.",
			typ:    "gauge",
			metric: r.activeBans,
		},
	}

	for _, def := range defs {
		samples := def.metric.samples()
		if len(samples) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "# HELP %s%s %s\n", prefix, def.name, escapeHelpText(def.help)); err != nil {
			return fmt.Errorf("metrics: write help for %s: %w", def.name, err)
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s%s %s\n", prefix, def.name, def.typ); err != nil {
			return fmt.Errorf("metrics: write type for %s: %w", def.name, err)
		}
		for _, s := range samples {
			if _, err := fmt.Fprintf(w, "%s%s{%s=\"%s\"} %d\n", prefix, def.name, def.metric.labelKey, escapeLabelValue(s.label), s.value); err != nil {
				return fmt.Errorf("metrics: write sample for %s: %w", def.name, err)
			}
		}
	}

	// uptime_seconds is a gauge that is always present.
	uptimeSecs := r.UptimeSeconds()
	if _, err := fmt.Fprintf(w, "# HELP %suptime_seconds %s\n", prefix, escapeHelpText("Total daemon uptime in seconds.")); err != nil {
		return fmt.Errorf("metrics: write help for uptime_seconds: %w", err)
	}
	if _, err := fmt.Fprintf(w, "# TYPE %suptime_seconds gauge\n", prefix); err != nil {
		return fmt.Errorf("metrics: write type for uptime_seconds: %w", err)
	}
	if _, err := fmt.Fprintf(w, "%suptime_seconds %s\n", prefix, strconv.FormatFloat(uptimeSecs, 'f', -1, 64)); err != nil {
		return fmt.Errorf("metrics: write sample for uptime_seconds: %w", err)
	}

	return nil
}

// FormatPrometheus renders all active registry metrics as a standard Prometheus text string.
func (r *Registry) FormatPrometheus() string {
	var b strings.Builder
	_ = r.WritePrometheus(&b)
	return b.String()
}

func escapeLabelValue(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func escapeHelpText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
