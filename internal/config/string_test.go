package config

import (
	"strings"
	"testing"
	"time"
)

// TestStringGolden pins the whole `banhammer check` rendering. It is the one
// place a human reads the resolved config, so churn here should be deliberate.
func TestStringGolden(t *testing.T) {
	t.Parallel()

	const src = `
state_dir: /srv/banhammer
log_format: json
allow_local: false
allowlist:
  - 10.0.0.0/8
  - 127.0.0.1
metrics:
  listen: 127.0.0.1:9777
queue_size: 64
defaults:
  threshold: 3
  window: 90s
monitors:
  caddy:
    file: /var/log/caddy/access.log
    format: json
    match:
      status: "^40[13]$"
      request.uri: "\\.env$"
    ignore:
      ua: "^GoodBot"
    ip_field: request.remote_ip
    contains: "40"
  remote:
    listen: udp://0.0.0.0:5140
    strip_syslog: true
    match: "rhost=<IP>"
    bantime: 24h
    bantime_factor: 2
    action:
      ban: "block {ip}"
      unban: "unblock {ip}"
      shell: true
      timeout: 5s
`
	const want = `state_dir:      /srv/banhammer
log_format:     json
queue_size:     64
allow_local:    false
allowlist:      10.0.0.0/8, 127.0.0.1/32
metrics:        127.0.0.1:9777

defaults:
  threshold:      3 hits in 90s
  bantime:        1h (factor 1, max 168h)
  find_history:   24h
  max_tracked:    100000
  start_at:       checkpoint
  on_repeat:      ignore
  action:         iptables (timeout 10s)

monitor "caddy":
  source:         file /var/log/caddy/access.log
  format:         json
  match:          field request.uri =~ "\\.env$"
                  field status =~ "^40[13]$"
  ignore:         field ua =~ "^GoodBot"
  ip_field:       request.remote_ip
  contains:       "40"
  threshold:      3 hits in 90s
  bantime:        1h (factor 1, max 168h)
  find_history:   24h
  max_tracked:    100000
  start_at:       checkpoint
  on_repeat:      ignore
  action:         iptables (timeout 10s)

monitor "remote":
  source:         listen udp://0.0.0.0:5140
  format:         text
  strip_syslog:   true
  match:          "rhost=<IP>"
  threshold:      3 hits in 90s
  bantime:        24h (factor 2, max 168h)
  find_history:   24h
  max_tracked:    100000
  start_at:       checkpoint
  on_repeat:      ignore
  action:         cmd (timeout 5s, via shell)
                  ban = "block {ip}"
                  unban = "unblock {ip}"
`
	got := mustParse(t, src).String()
	if got != want {
		t.Errorf("String() mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestStringIsStable guards the sorted ordering that makes the golden above
// meaningful: Go map iteration would otherwise shuffle monitors and fields.
func TestStringIsStable(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  c:
    stdin: true
    format: json
    ip_field: ip
    match:
      z: "1"
      a: "2"
      m: "3"
  a:
    file: /a
    match: "<IP>"
  b:
    file: /b
    match: "<IP>"
`
	first := mustParse(t, src).String()
	for range 20 {
		if got := mustParse(t, src).String(); got != first {
			t.Fatalf("String() is not deterministic:\n%s\nvs\n%s", got, first)
		}
	}
	if idxA, idxB, idxC := strings.Index(first, `"a"`), strings.Index(first, `"b"`), strings.Index(first, `"c"`); !(idxA < idxB && idxB < idxC) {
		t.Errorf("monitors are not in name order:\n%s", first)
	}
}

func TestStringNilAndEmpty(t *testing.T) {
	t.Parallel()

	var c *Config
	if got := c.String(); got != "" {
		t.Errorf("(*Config)(nil).String() = %q, want empty", got)
	}
	empty := (&Config{}).String()
	if !strings.Contains(empty, "allowlist:      (empty)") || !strings.Contains(empty, "metrics:        (disabled)") {
		t.Errorf("zero Config renders oddly:\n%s", empty)
	}
	if !strings.Contains(empty, "\ndefaults:\n") {
		t.Errorf("defaults section missing:\n%s", empty)
	}
}

func TestFmtDur(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{time.Second, "1s"},
		{90 * time.Second, "90s"},
		{10 * time.Minute, "10m"},
		{time.Hour, "1h"},
		{168 * time.Hour, "168h"},
		{90 * time.Minute, "90m"},
		{1500 * time.Millisecond, "1.5s"},
		{-5 * time.Minute, "-5m"},
	}
	for _, tc := range tests {
		if got := fmtDur(tc.in); got != tc.want {
			t.Errorf("fmtDur(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestStringShowsPatternsVerbatim: debugging "why doesn't my regex match?"
// depends on seeing exactly the characters the parser kept.
func TestStringShowsPatternsVerbatim(t *testing.T) {
	t.Parallel()

	c := mustParse(t, "monitors:\n  m:\n    stdin: true\n    match: '^<IP>\\s+\"GET'\n")
	if !strings.Contains(c.String(), `match:          "^<IP>\\s+\"GET"`) {
		t.Errorf("pattern not rendered verbatim:\n%s", c.String())
	}
}

func TestStringShowsCustomChain(t *testing.T) {
	t.Parallel()

	c := mustParse(t, "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    action:\n      chain: DOCKER-USER\n")
	if !strings.Contains(c.String(), `action:         iptables (chain DOCKER-USER, timeout 10s)`) {
		t.Errorf("custom chain not rendered:\n%s", c.String())
	}
}
