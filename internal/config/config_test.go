package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// exampleConfig is the repository's own config.example.yaml. If this ever fails
// to load, either the example or this parser is wrong; both are user-visible.
func exampleConfig(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("reading config.example.yaml: %v", err)
	}
	return src
}

func TestLoadExampleConfig(t *testing.T) {
	t.Parallel()

	c, err := parse(exampleConfig(t), "config.example.yaml")
	if err != nil {
		t.Fatalf("config.example.yaml must load cleanly:\n%v", err)
	}

	if got, want := c.StateDir, "/var/lib/banhammer"; got != want {
		t.Errorf("StateDir = %q, want %q", got, want)
	}
	if !c.AllowLocal {
		t.Error("AllowLocal = false, want true")
	}
	if got, want := len(c.Allowlist), 4; got != want {
		t.Fatalf("len(Allowlist) = %d, want %d", got, want)
	}
	// 127.0.0.1/8 is masked to the network it actually describes.
	if got, want := c.Allowlist[0].String(), "127.0.0.0/8"; got != want {
		t.Errorf("Allowlist[0] = %q, want %q", got, want)
	}
	if c.Metrics.Listen != "" {
		t.Errorf("Metrics.Listen = %q, want empty (the key is commented out)", c.Metrics.Listen)
	}

	want := []string{"caddy", "nginx-auth", "remote", "sshd", "sshd-strict"}
	got := c.MonitorNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("monitors = %v, want %v", got, want)
	}

	sshd := c.Monitors["sshd"]
	if sshd.File != "/var/log/auth.log" {
		t.Errorf("sshd.File = %q", sshd.File)
	}
	if len(sshd.Match.Line) != 1 || sshd.Match.Line[0] != "Failed password .* from <IP>" {
		t.Errorf("sshd.Match = %+v", sshd.Match)
	}
	if sshd.Threshold != 5 || sshd.Window != 10*time.Minute || sshd.Bantime != time.Hour {
		t.Errorf("sshd inherited settings = %+v, want the defaults block", sshd.Settings)
	}
	if sshd.Format != "text" {
		t.Errorf("sshd.Format = %q, want text", sshd.Format)
	}

	strict := c.Monitors["sshd-strict"]
	if len(strict.Match.Line) != 2 {
		t.Errorf("sshd-strict.Match.Line = %v, want 2 entries", strict.Match.Line)
	}
	if strict.Threshold != 3 || strict.Bantime != 24*time.Hour {
		t.Errorf("sshd-strict overrides not applied: %+v", strict.Settings)
	}
	if strict.Window != 10*time.Minute {
		t.Errorf("sshd-strict.Window = %s, want the inherited 10m", strict.Window)
	}

	caddy := c.Monitors["caddy"]
	if got, want := caddy.Match.Fields["status"], "^(401|403|404)$"; got != want {
		t.Errorf("caddy.Match.Fields[status] = %q, want %q", got, want)
	}
	if caddy.IPField != "request.remote_ip" {
		t.Errorf("caddy.IPField = %q", caddy.IPField)
	}

	remote := c.Monitors["remote"]
	if remote.Listen != "udp://0.0.0.0:5140" || !remote.StripSyslog {
		t.Errorf("remote source = %+v", remote)
	}
	// Templates without a name resolve to the cmd backend, and must not
	// inherit `defaults: action: iptables`.
	if remote.Action.Name != "cmd" {
		t.Errorf("remote.Action.Name = %q, want cmd", remote.Action.Name)
	}
	if !remote.Action.Shell {
		t.Error("remote.Action.Shell = false, want true")
	}
	if remote.Action.Timeout != 10*time.Second {
		t.Errorf("remote.Action.Timeout = %s, want the 10s default", remote.Action.Timeout)
	}
	if c.Monitors["sshd"].Action.Name != "iptables" {
		t.Errorf("sshd.Action.Name = %q, want iptables", c.Monitors["sshd"].Action.Name)
	}
}

func TestLoadFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "banhammer.yaml")
	src := "monitors:\n  sshd:\n    file: /var/log/auth.log\n    match: \"from <IP>\"\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Monitors["sshd"].Threshold != 5 {
		t.Errorf("Threshold = %d, want the built-in 5", c.Monitors["sshd"].Threshold)
	}

	if _, err := Load(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Fatal("Load of a missing file returned no error")
	} else if !strings.Contains(err.Error(), "nope.yaml") {
		t.Errorf("error %q does not name the missing file", err)
	}
}

// TestDefaultsAreBuiltIn pins the documented defaults; config.example.yaml
// claims they are the built-in ones, so a change here is a docs change too.
func TestDefaultsAreBuiltIn(t *testing.T) {
	t.Parallel()

	c := mustParse(t, "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n")
	if c.StateDir != "/var/lib/banhammer" || c.LogFormat != "text" || c.QueueSize != 8192 || !c.AllowLocal {
		t.Errorf("global defaults = %+v", c)
	}
	m := c.Monitors["m"]
	want := Settings{
		Threshold:     5,
		Window:        10 * time.Minute,
		Bantime:       time.Hour,
		BantimeFactor: 1,
		BantimeMax:    168 * time.Hour,
		FindHistory:   24 * time.Hour,
		MaxTracked:    100000,
		StartAt:       "checkpoint",
		OnRepeat:      "ignore",
		Action:        ActionSpec{Name: "iptables", Timeout: 10 * time.Second},
	}
	if m.Settings != want {
		t.Errorf("settings = %+v\nwant %+v", m.Settings, want)
	}
	if m.Format != "text" {
		t.Errorf("Format = %q, want text", m.Format)
	}
	if !m.Stdin {
		t.Error("Stdin = false")
	}
}

func TestDefaultsInheritanceAndOverride(t *testing.T) {
	t.Parallel()

	const src = `
defaults:
  threshold: 3
  window: 2m
  bantime: 30m
  bantime_factor: 2
  bantime_max: 48h
  find_history: 12h
  max_tracked: 10
  start_at: end
  on_repeat: extend
  action:
    name: nft
    timeout: 30s
monitors:
  inherits:
    file: /a
    match: "<IP>"
  overrides:
    file: /b
    match: "<IP>"
    threshold: 9
    window: 90s
    start_at: beginning
    action: dryrun
`
	c := mustParse(t, src)

	in := c.Monitors["inherits"].Settings
	if in != c.Defaults {
		t.Errorf("inherits = %+v\nwant defaults %+v", in, c.Defaults)
	}
	if in.Action.Name != "nft" || in.Action.Timeout != 30*time.Second {
		t.Errorf("inherited action = %+v", in.Action)
	}

	ov := c.Monitors["overrides"].Settings
	if ov.Threshold != 9 || ov.Window != 90*time.Second || ov.StartAt != "beginning" {
		t.Errorf("overrides not applied: %+v", ov)
	}
	if ov.Bantime != 30*time.Minute || ov.OnRepeat != "extend" || ov.MaxTracked != 10 {
		t.Errorf("non-overridden settings did not inherit: %+v", ov)
	}
	// A monitor's action replaces the defaults action outright; the 30s timeout
	// from defaults must not leak into it.
	if ov.Action.Name != "dryrun" || ov.Action.Timeout != 10*time.Second {
		t.Errorf("overridden action = %+v, want dryrun with the built-in timeout", ov.Action)
	}
}

// TestExplicitZeroIsNotUnset is the reason every raw field is a pointer.
func TestExplicitZeroIsNotUnset(t *testing.T) {
	t.Parallel()

	const src = `
monitors:
  m:
    file: /a
    match: "<IP>"
    threshold: 0
`
	_, err := parse([]byte(src), "t.yaml")
	if err == nil {
		t.Fatal("threshold: 0 was accepted; it must not silently become the default")
	}
	wantContains(t, err.Error(), `monitor "m": threshold must be at least 1, got 0`)
}

func TestAllowlistParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
		err  string
	}{
		{name: "bare v4 becomes /32", in: "127.0.0.1", want: []string{"127.0.0.1/32"}},
		{name: "bare v6 becomes /128", in: "::1", want: []string{"::1/128"}},
		{name: "cidr is masked", in: "10.1.2.3/8", want: []string{"10.0.0.0/8"}},
		{name: "v6 cidr", in: "2001:db8::/32", want: []string{"2001:db8::/32"}},
		{name: "garbage", in: "not-an-ip", err: `invalid IP or CIDR "not-an-ip"`},
		{name: "blank", in: `"  "`, err: "allowlist: empty entry"},
		{name: "bad mask", in: "10.0.0.0/99", err: `invalid CIDR "10.0.0.0/99"`},
		{name: "zone suffix", in: "fe80::1%eth0", err: "zone suffixes are not supported"},
		{name: "list entry", in: "[1, 2]", err: "expected an IP or CIDR"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "allowlist:\n  - " + tc.in + "\nmonitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n"
			c, err := parse([]byte(src), "t.yaml")
			if tc.err != "" {
				if err == nil {
					t.Fatalf("got no error, want one containing %q", tc.err)
				}
				wantContains(t, err.Error(), tc.err)
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var got []string
			for _, p := range c.Allowlist {
				got = append(got, p.String())
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("Allowlist = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDurationParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want time.Duration
		err  string
	}{
		{name: "minutes", in: "10m", want: 10 * time.Minute},
		{name: "hours", in: "24h", want: 24 * time.Hour},
		{name: "compound", in: "1h30m", want: 90 * time.Minute},
		{name: "seconds", in: "45s", want: 45 * time.Second},
		{name: "quoted", in: `"90s"`, want: 90 * time.Second},
		{name: "bare number", in: "60", err: `invalid duration "60": a unit is required, try "60s"`},
		{name: "nonsense", in: "soon", err: `invalid duration "soon"`},
		// yaml.v3 resolves a null scalar before a custom unmarshaler ever sees
		// it, so `window:` with no value reads as "unset" and inherits.
		{name: "empty means unset", in: "", want: 10 * time.Minute},
		{name: "list", in: "[1m]", err: "expected a duration"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n    window: " + tc.in + "\n"
			c, err := parse([]byte(src), "t.yaml")
			if tc.err != "" {
				if err == nil {
					t.Fatalf("got no error, want one containing %q", tc.err)
				}
				wantContains(t, err.Error(), tc.err)
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := c.Monitors["m"].Window; got != tc.want {
				t.Errorf("Window = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEmptyAndOddDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		err  string
	}{
		{name: "empty file", src: "", err: "no monitors defined"},
		{name: "comments only", src: "# nothing here\n", err: "no monitors defined"},
		{name: "empty monitors map", src: "monitors: {}\n", err: "no monitors defined"},
		{name: "monitor with no body", src: "monitors:\n  m:\n", err: `monitor "m": no source`},
		{name: "syntax error", src: "monitors:\n  m:\n   - a\n  : :\n", err: "invalid YAML"},
		{name: "two documents", src: "monitors:\n  m:\n    stdin: true\n    match: \"<IP>\"\n---\nmonitors: {}\n", err: "more than one YAML document"},
		{name: "top level list", src: "- a\n- b\n", err: "line 1: the top level must be a block of indented keys, got a list"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parse([]byte(tc.src), "t.yaml")
			if err == nil {
				t.Fatalf("got no error, want one containing %q", tc.err)
			}
			wantContains(t, err.Error(), tc.err)
		})
	}
}

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	c, err := parse([]byte(src), "t.yaml")
	if err != nil {
		t.Fatalf("parse:\n%v", err)
	}
	return c
}

func wantContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("output does not contain %q:\n%s", want, got)
	}
}
