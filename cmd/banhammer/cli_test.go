package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/model"
)

// mockService implements control.Service for testing control CLI commands.
//
// Every field is written on the control server's per-connection goroutine and
// read from the test goroutine, so all access is under mu.
type mockService struct {
	mu          sync.Mutex
	statusResp  control.StatusResponse
	statusErr   error
	bannedIP    netip.Addr
	bannedMon   string
	bannedDur   time.Duration
	unbannedIP  netip.Addr
	unbannedAll bool
	reloaded    bool
	banErr      error
	unbanErr    error
	unbanAllErr error
	reloadErr   error

	// monitorBantime stands in for a monitor's configured bantime: a real
	// daemon applies it when the client sends no duration, and the CLI is
	// supposed to report what was applied rather than what was typed.
	monitorBantime time.Duration
	// banAt is the instant the recorded ban was issued.
	banAt time.Time
}

func (m *mockService) Status() (control.StatusResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statusErr != nil {
		return control.StatusResponse{}, m.statusErr
	}
	resp := m.statusResp
	if m.bannedIP.IsValid() {
		applied := m.bannedDur
		if applied <= 0 {
			applied = m.monitorBantime
		}
		resp.Bans = append(slices.Clone(resp.Bans), model.Ban{
			IP:      m.bannedIP,
			Monitor: m.bannedMon,
			At:      m.banAt,
			Until:   m.banAt.Add(applied),
			Offense: 1,
		})
	}
	return resp, nil
}

func (m *mockService) Ban(ip netip.Addr, monitor string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.banErr != nil {
		return m.banErr
	}
	m.bannedIP = ip
	m.bannedMon = monitor
	m.bannedDur = d
	m.banAt = time.Now()
	return nil
}

func (m *mockService) Unban(ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unbanErr != nil {
		return m.unbanErr
	}
	m.unbannedIP = ip
	return nil
}

func (m *mockService) UnbanAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unbanAllErr != nil {
		return m.unbanAllErr
	}
	m.unbannedAll = true
	return nil
}

func (m *mockService) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reloadErr != nil {
		return m.reloadErr
	}
	m.reloaded = true
	return nil
}

// set mutates the mock under its lock.
func (m *mockService) set(f func(*mockService)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// startMockControlServer starts an in-process control.Server on a temporary socket.
func startMockControlServer(t *testing.T, svc control.Service) (string, func()) {
	t.Helper()
	// Not t.TempDir(): its path carries the test and subtest names and gets
	// close enough to the 108-byte sun_path limit to fail on a host with a
	// longer TMPDIR.
	dir, err := os.MkdirTemp("", "bh")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "test.sock")

	srv, err := control.NewServer(sockPath, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("failed to create mock control server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	select {
	case <-srv.Ready():
	case err := <-errCh:
		t.Fatalf("mock control server failed to start: %v", err)
	}

	cleanup := func() {
		cancel()
		_ = srv.Close()
	}
	return sockPath, cleanup
}

func executeCommand(args ...string) (string, string, error) {
	cmd := NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func executeCommandWithStdin(r io.Reader, args ...string) (string, string, error) {
	cmd := NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetIn(r)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCheckCommand(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		cfgContent := `
state_dir: /tmp/banhammer-test
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
`
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
			t.Fatal(err)
		}

		stdout, _, err := executeCommand("check", "-c", cfgPath)
		if err != nil {
			t.Fatalf("check failed unexpectedly: %v", err)
		}

		if !strings.Contains(stdout, "state_dir:") || !strings.Contains(stdout, "sshd") {
			t.Fatalf("expected config summary in output, got:\n%s", stdout)
		}
	})

	t.Run("InvalidConfig_UnknownKey", func(t *testing.T) {
		cfgContent := `
unknown_key: true
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
`
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
			t.Fatal(err)
		}

		_, _, err := executeCommand("check", "-c", cfgPath)
		if err == nil {
			t.Fatal("expected error for unknown key, got nil")
		}
	})

	t.Run("MissingConfigFlag", func(t *testing.T) {
		_, _, err := executeCommand("check")
		if err == nil {
			t.Fatal("expected error when -c flag is missing, got nil")
		}
	})

	t.Run("ConfigFromEnv", func(t *testing.T) {
		cfgContent := `
state_dir: /tmp/banhammer-test
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
`
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFIG", cfgPath)
		stdout, _, err := executeCommand("check")
		if err != nil {
			t.Fatalf("check failed unexpectedly with CONFIG env: %v", err)
		}
		if !strings.Contains(stdout, "sshd") {
			t.Fatalf("expected output to contain monitor sshd, got: %s", stdout)
		}
	})

	t.Run("FlagOverridesEnv", func(t *testing.T) {
		validCfg := `
state_dir: /tmp/banhammer-test
monitors:
  sshd:
    file: /var/log/auth.log
    match: "Failed password .* from <IP>"
`
		tmpDir := t.TempDir()
		validPath := filepath.Join(tmpDir, "valid.yaml")
		if err := os.WriteFile(validPath, []byte(validCfg), 0600); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFIG", "/path/to/nonexistent/from/env.yaml")
		stdout, _, err := executeCommand("check", "-c", validPath)
		if err != nil {
			t.Fatalf("expected flag to override invalid CONFIG env: %v", err)
		}
		if !strings.Contains(stdout, "sshd") {
			t.Fatalf("expected output to contain monitor sshd, got: %s", stdout)
		}
	})

	t.Run("NonexistentFile", func(t *testing.T) {
		_, _, err := executeCommand("check", "-c", "/path/to/nonexistent/config.yaml")
		if err == nil {
			t.Fatal("expected error for nonexistent config file, got nil")
		}
	})
}

func TestTestCommand(t *testing.T) {
	cfgContent := `
state_dir: /tmp/banhammer-test
monitors:
  sshd:
    file: /var/log/auth.log
    threshold: 3
    window: 10m
    match: "Failed password for .* from <IP>"
    ignore: "from 192.0.2.99"
  nginx_json:
    file: /var/log/nginx.json
    format: json
    threshold: 2
    window: 5m
    ip_field: "client.ip"
    match:
      event: "failed_login"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("TextMonitor_TimelineAndSummary", func(t *testing.T) {
		sampleLogs := `Failed password for root from 192.0.2.1 port 22
Accepted publickey for admin from 192.0.2.2 port 22
Failed password for user from 192.0.2.1 port 22
Failed password for guest from 192.0.2.1 port 22
Failed password for root from 192.0.2.99 port 22
Failed password for anon from 192.0.2.5 port 22
`
		samplePath := filepath.Join(tmpDir, "sample.log")
		if err := os.WriteFile(samplePath, []byte(sampleLogs), 0600); err != nil {
			t.Fatal(err)
		}

		stdout, _, err := executeCommand("test", "-c", cfgPath, "-m", "sshd", "-f", samplePath)
		if err != nil {
			t.Fatalf("test command failed: %v", err)
		}

		if !strings.Contains(stdout, "line 1: match  ip=192.0.2.1") {
			t.Errorf("missing line 1 match in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "line 2: no-match") {
			t.Errorf("missing line 2 no-match in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "line 4: match  ip=192.0.2.1") {
			t.Errorf("missing line 4 match in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "[BAN] 192.0.2.1 triggered (count=3)") {
			t.Errorf("missing [BAN] trigger line in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "line 5: ignored") {
			t.Errorf("missing line 5 ignored verdict in:\n%s", stdout)
		}

		if !strings.Contains(stdout, "Lines read:     6") {
			t.Errorf("incorrect lines read summary in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Lines matched:  4") {
			t.Errorf("incorrect lines matched summary in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Bans triggered: 1") {
			t.Errorf("incorrect bans triggered summary in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Distinct IPs:   2") {
			t.Errorf("incorrect distinct IPs summary in:\n%s", stdout)
		}
	})

	t.Run("StdinInput", func(t *testing.T) {
		input := "Failed password for root from 192.0.2.1 port 22\nFailed password for root from 192.0.2.1 port 22\n"
		stdout, _, err := executeCommandWithStdin(strings.NewReader(input), "test", "-c", cfgPath, "-m", "sshd", "-f", "-")
		if err != nil {
			t.Fatalf("test command via stdin failed: %v", err)
		}

		if !strings.Contains(stdout, "Lines read:     2") {
			t.Errorf("expected 2 lines read, got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Lines matched:  2") {
			t.Errorf("expected 2 lines matched, got:\n%s", stdout)
		}
	})

	t.Run("JSONMonitor_MatchAndDecodeError", func(t *testing.T) {
		jsonLogs := `{"event": "failed_login", "client": {"ip": "198.51.100.1"}}
{"event": "other_event", "client": {"ip": "198.51.100.2"}}
{"invalid_json"
{"event": "failed_login", "client": {"ip": "198.51.100.1"}}
`
		samplePath := filepath.Join(tmpDir, "sample.json")
		if err := os.WriteFile(samplePath, []byte(jsonLogs), 0600); err != nil {
			t.Fatal(err)
		}

		stdout, _, err := executeCommand("test", "-c", cfgPath, "-m", "nginx_json", "-f", samplePath)
		if err != nil {
			t.Fatalf("test command on JSON monitor failed: %v", err)
		}

		if !strings.Contains(stdout, "line 1: match  ip=198.51.100.1") {
			t.Errorf("missing line 1 match in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "line 2: no-match") {
			t.Errorf("missing line 2 no-match in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "line 3: error (decode error)") {
			t.Errorf("missing line 3 decode error in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "[BAN] 198.51.100.1 triggered (count=2)") {
			t.Errorf("missing [BAN] trigger for JSON monitor in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Bans triggered: 1") {
			t.Errorf("expected 1 ban triggered, got:\n%s", stdout)
		}
	})

	t.Run("AllowlistIsHonoured", func(t *testing.T) {
		// The simulator used to print [BAN] 127.0.0.1: it never consulted the
		// allowlist the daemon enforces.
		allowCfg := `
state_dir: /tmp/banhammer-test
allow_local: true
allowlist:
  - 198.51.100.0/24
monitors:
  sshd:
    file: /var/log/auth.log
    threshold: 2
    window: 10m
    match: "Failed password for .* from <IP>"
`
		allowCfgPath := filepath.Join(tmpDir, "allow.yaml")
		if err := os.WriteFile(allowCfgPath, []byte(allowCfg), 0600); err != nil {
			t.Fatal(err)
		}

		sample := `Failed password for root from 127.0.0.1 port 22
Failed password for root from 127.0.0.1 port 22
Failed password for root from 198.51.100.9 port 22
Failed password for root from 198.51.100.9 port 22
`
		samplePath := filepath.Join(tmpDir, "allow.log")
		if err := os.WriteFile(samplePath, []byte(sample), 0600); err != nil {
			t.Fatal(err)
		}

		stdout, _, err := executeCommand("test", "-c", allowCfgPath, "-m", "sshd", "-f", samplePath)
		if err != nil {
			t.Fatalf("test command failed: %v", err)
		}

		if strings.Contains(stdout, "[BAN]") {
			t.Errorf("allowlisted addresses were banned in:\n%s", stdout)
		}
		for _, want := range []string{"allowlisted  ip=127.0.0.1", "allowlisted  ip=198.51.100.9", "Allowlisted:    4", "Bans triggered: 0"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("missing %q in:\n%s", want, stdout)
			}
		}
	})

	t.Run("BanTimelineShowsExpiry", func(t *testing.T) {
		// §4.8 promises "a simulated timeline of bans"; a ban that never ends
		// is not a timeline. --rate drives the synthetic clock.
		expiryCfg := `
state_dir: /tmp/banhammer-test
allow_local: false
monitors:
  sshd:
    file: /var/log/auth.log
    threshold: 2
    window: 10m
    bantime: 5m
    match: "Failed password for .* from <IP>"
`
		expiryCfgPath := filepath.Join(tmpDir, "expiry.yaml")
		if err := os.WriteFile(expiryCfgPath, []byte(expiryCfg), 0600); err != nil {
			t.Fatal(err)
		}

		sample := `Failed password for root from 192.0.2.7 port 22
Failed password for root from 192.0.2.7 port 22
Accepted publickey for admin from 192.0.2.8 port 22
Accepted publickey for admin from 192.0.2.8 port 22
`
		samplePath := filepath.Join(tmpDir, "expiry.log")
		if err := os.WriteFile(samplePath, []byte(sample), 0600); err != nil {
			t.Fatal(err)
		}

		// At 1s/line the ban would still be live at EOF; at 4m/line it expires
		// during the run.
		stdout, _, err := executeCommand("test", "-c", expiryCfgPath, "-m", "sshd", "-f", samplePath, "--rate", "4m")
		if err != nil {
			t.Fatalf("test command failed: %v", err)
		}

		for _, want := range []string{
			"[BAN] 192.0.2.7 triggered (count=2) until 2026-01-01T00:13:00Z",
			"[UNBAN] 192.0.2.7 ban expired",
			"Bans expired:   1",
			"Still banned:   0",
			"log timestamps are not parsed",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("missing %q in:\n%s", want, stdout)
			}
		}

		// Timestamps must be the simulated ones, not wall clock.
		if !strings.Contains(stdout, "[2026-01-01T00:04:00Z] line 1: match") {
			t.Errorf("missing simulated timestamp on line 1 in:\n%s", stdout)
		}
	})

	t.Run("StillBannedAtEndIsReported", func(t *testing.T) {
		sample := `Failed password for root from 192.0.2.1 port 22
Failed password for user from 192.0.2.1 port 22
Failed password for guest from 192.0.2.1 port 22
`
		samplePath := filepath.Join(tmpDir, "still.log")
		if err := os.WriteFile(samplePath, []byte(sample), 0600); err != nil {
			t.Fatal(err)
		}

		stdout, _, err := executeCommand("test", "-c", cfgPath, "-m", "sshd", "-f", samplePath)
		if err != nil {
			t.Fatalf("test command failed: %v", err)
		}
		if !strings.Contains(stdout, "Still banned:   1") {
			t.Errorf("expected one live ban at EOF in:\n%s", stdout)
		}
		if !strings.Contains(stdout, "Still banned at end of simulation:") {
			t.Errorf("expected the live-ban listing in:\n%s", stdout)
		}
	})

	t.Run("InvalidRate", func(t *testing.T) {
		_, _, err := executeCommand("test", "-c", cfgPath, "-m", "sshd", "-f", "-", "--rate", "0s")
		if err == nil {
			t.Fatal("expected error for a non-positive --rate, got nil")
		}
	})

	t.Run("UnknownMonitor", func(t *testing.T) {
		_, _, err := executeCommand("test", "-c", cfgPath, "-m", "nonexistent_monitor", "-f", "-")
		if err == nil {
			t.Fatal("expected error for unknown monitor, got nil")
		}
	})

	t.Run("MissingFlags", func(t *testing.T) {
		_, _, err := executeCommand("test")
		if err == nil {
			t.Fatal("expected error when required flags are missing, got nil")
		}
	})
}

func TestStatusCommand(t *testing.T) {
	now := time.Now()
	bannedAt := now.Add(-10 * time.Minute)
	until := now.Add(50 * time.Minute)

	mock := &mockService{
		statusResp: control.StatusResponse{
			Uptime: 2 * time.Hour,
			Monitors: []control.MonitorStatus{
				{Name: "sshd", Type: "file", Target: "/var/log/auth.log", TrackedIPs: 14},
				{Name: "nginx", Type: "listen", Target: "tcp://127.0.0.1:8514", TrackedIPs: 0},
			},
			Bans: []model.Ban{
				{
					IP:      netip.MustParseAddr("192.0.2.10"),
					Monitor: "sshd",
					At:      bannedAt,
					Until:   until,
					Count:   5,
					Offense: 1,
				},
			},
			Stats: control.Stats{
				LinesRead:    10500,
				LinesDropped: 12,
				Matches:      42,
				BansTotal:    5,
				UnbansTotal:  4,
				ActionErrors: 0,
				DecodeErrors: 1,
				TrackedIPs:   27,
				ActiveBans:   1,
			},
		},
	}

	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("TextOutput", func(t *testing.T) {
		stdout, _, err := executeCommand("status", "--socket", sockPath)
		if err != nil {
			t.Fatalf("status command failed: %v", err)
		}

		expectedSnippets := []string{
			"Daemon Uptime:",
			"Lines Read:     10500",
			"Lines Dropped:  12",
			"Matches:        42",
			"Tracked IPs:    27",
			"Active Bans:    1",
			"Total Bans:     5",
			"Total Unbans:   4",
			"Action Errors:  0",
			"Decode Errors:  1",
			"sshd", "/var/log/auth.log", "14",
			"nginx", "tcp://127.0.0.1:8514",
			"192.0.2.10",
		}
		for _, snippet := range expectedSnippets {
			if !strings.Contains(stdout, snippet) {
				t.Errorf("expected status output to contain %q, but got:\n%s", snippet, stdout)
			}
		}
	})

	t.Run("JSONOutput", func(t *testing.T) {
		stdout, _, err := executeCommand("status", "--socket", sockPath, "--json")
		if err != nil {
			t.Fatalf("status --json failed: %v", err)
		}

		var parsed control.StatusResponse
		if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
			t.Fatalf("failed to parse json output %q: %v", stdout, err)
		}

		if parsed.Stats.LinesRead != 10500 {
			t.Errorf("expected 10500 lines read, got %d", parsed.Stats.LinesRead)
		}
		if len(parsed.Bans) != 1 || parsed.Bans[0].IP != netip.MustParseAddr("192.0.2.10") {
			t.Errorf("expected 1 active ban for 192.0.2.10, got %+v", parsed.Bans)
		}
	})

	t.Run("ConnectionError", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nonexistent.sock")
		_, _, err := executeCommand("status", "--socket", missing)
		if err == nil {
			t.Fatal("expected error connecting to nonexistent socket, got nil")
		}
		// A raw "dial unix ...: connect: no such file or directory" answers
		// the wrong question.
		if !strings.Contains(err.Error(), "does not appear to be running") {
			t.Errorf("error %q does not tell the operator the daemon is down", err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error %q does not name the socket it tried", err)
		}
	})
}

func TestBanCommand(t *testing.T) {
	// The mock stands in for a monitor with `bantime: 24h` configured.
	mock := &mockService{monitorBantime: 24 * time.Hour}
	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("ValidBan", func(t *testing.T) {
		stdout, _, err := executeCommand("ban", "198.51.100.42", "-m", "custom_monitor", "-t", "45m", "--socket", sockPath)
		if err != nil {
			t.Fatalf("ban command failed: %v", err)
		}

		expected := "banned 198.51.100.42 for 45m0s (monitor: custom_monitor"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if mock.bannedIP != netip.MustParseAddr("198.51.100.42") {
			t.Errorf("expected banned IP 198.51.100.42, got %s", mock.bannedIP)
		}
		if mock.bannedMon != "custom_monitor" {
			t.Errorf("expected monitor custom_monitor, got %s", mock.bannedMon)
		}
		if mock.bannedDur != 45*time.Minute {
			t.Errorf("expected duration 45m, got %s", mock.bannedDur)
		}
	})

	t.Run("NoTimeFlagUsesMonitorBantime", func(t *testing.T) {
		// --time used to default to a literal "1h", which made the documented
		// "0 means use the monitor's bantime" path unreachable and silently
		// overrode a configured bantime.
		stdout, _, err := executeCommand("ban", "2001:db8::1", "--socket", sockPath)
		if err != nil {
			t.Fatalf("ban with defaults failed: %v", err)
		}

		expected := "banned 2001:db8::1 for 24h0m0s (monitor: manual"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if mock.bannedIP != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("expected banned IP 2001:db8::1, got %s", mock.bannedIP)
		}
		if mock.bannedMon != "manual" {
			t.Errorf("expected monitor manual, got %s", mock.bannedMon)
		}
		if mock.bannedDur != 0 {
			t.Errorf("expected the daemon to receive no duration, got %s", mock.bannedDur)
		}
	})

	t.Run("InvalidIP", func(t *testing.T) {
		_, _, err := executeCommand("ban", "999.999.999.999", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error for invalid IP, got nil")
		}
	})

	t.Run("InvalidDuration", func(t *testing.T) {
		_, _, err := executeCommand("ban", "1.2.3.4", "-t", "not-a-duration", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error for invalid duration, got nil")
		}
	})

	t.Run("ZeroDurationRejected", func(t *testing.T) {
		// An explicit zero is a mistake, not a request for the default.
		_, _, err := executeCommand("ban", "1.2.3.4", "-t", "0s", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error for a zero duration, got nil")
		}
	})

	t.Run("MissingArg", func(t *testing.T) {
		_, _, err := executeCommand("ban", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when IP argument is omitted, got nil")
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		mock.set(func(m *mockService) { m.banErr = errors.New("underlying firewall error") })
		defer mock.set(func(m *mockService) { m.banErr = nil })

		_, _, err := executeCommand("ban", "1.2.3.4", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when server fails, got nil")
		}
	})
}

func TestUnbanCommand(t *testing.T) {
	mock := &mockService{}
	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("ValidSingleUnban", func(t *testing.T) {
		stdout, _, err := executeCommand("unban", "192.0.2.1", "--socket", sockPath)
		if err != nil {
			t.Fatalf("unban command failed: %v", err)
		}

		expected := "unbanned 192.0.2.1"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if mock.unbannedIP != netip.MustParseAddr("192.0.2.1") {
			t.Errorf("expected unbanned IP 192.0.2.1, got %s", mock.unbannedIP)
		}
	})

	t.Run("UnbanAll", func(t *testing.T) {
		stdout, _, err := executeCommand("unban", "--all", "--socket", sockPath)
		if err != nil {
			t.Fatalf("unban --all failed: %v", err)
		}

		expected := "unbanned all IPs"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if !mock.unbannedAll {
			t.Error("expected unbannedAll to be true")
		}
	})

	t.Run("UnbanAllWithIPError", func(t *testing.T) {
		_, _, err := executeCommand("unban", "--all", "192.0.2.1", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when combining --all with an IP address, got nil")
		}
	})

	t.Run("MissingArgs", func(t *testing.T) {
		_, _, err := executeCommand("unban", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when no args and no --all, got nil")
		}
	})

	t.Run("InvalidIP", func(t *testing.T) {
		_, _, err := executeCommand("unban", "invalid-ip", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error for invalid IP, got nil")
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		mock.set(func(m *mockService) { m.unbanErr = errors.New("ban not found") })
		defer mock.set(func(m *mockService) { m.unbanErr = nil })

		_, _, err := executeCommand("unban", "1.2.3.4", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when server fails, got nil")
		}
	})
}

func TestReloadCommand(t *testing.T) {
	mock := &mockService{}
	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("Success", func(t *testing.T) {
		stdout, _, err := executeCommand("reload", "--socket", sockPath)
		if err != nil {
			t.Fatalf("reload command failed: %v", err)
		}

		expected := "daemon configuration reloaded"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if !mock.reloaded {
			t.Error("expected reloaded to be true on mock service")
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		mock.set(func(m *mockService) { m.reloadErr = errors.New("reload failed") })
		defer mock.set(func(m *mockService) { m.reloadErr = nil })

		_, _, err := executeCommand("reload", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error on reload server error, got nil")
		}
	})
}

func TestRunCommand(t *testing.T) {
	tmpDir := t.TempDir()
	cfgContent := `
state_dir: ` + tmpDir + `/state
defaults:
  action: dryrun
monitors:
  sshd:
    stdin: true
    threshold: 5
    match: "Failed password .* from <IP>"
`
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("InvalidLogLevel", func(t *testing.T) {
		_, _, err := executeCommand("run", "-c", cfgPath, "--log-level", "invalid")
		if err == nil {
			t.Fatal("expected error for invalid log level, got nil")
		}
	})

	t.Run("InvalidLogFormat", func(t *testing.T) {
		_, _, err := executeCommand("run", "-c", cfgPath, "--log-format", "xml")
		if err == nil {
			t.Fatal("expected error for invalid log format, got nil")
		}
	})

	t.Run("PreCancelledContext", func(t *testing.T) {
		cmd := NewRootCmd()
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately
		cmd.SetContext(ctx)

		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs([]string{"run", "-c", cfgPath, "--dry-run", "--state-dir", filepath.Join(tmpDir, "state2"), "--socket", filepath.Join(tmpDir, "ctrl.sock")})

		err := cmd.Execute()
		if err != nil {
			t.Fatalf("run with pre-cancelled context failed unexpectedly: %v", err)
		}
	})
}

func TestSocketAndConfigResolution(t *testing.T) {
	t.Run("ExplicitSocketTakesPrecedence", func(t *testing.T) {
		res, err := resolveSocketPath("/custom/socket.sock", "/some/config.yaml")
		if err != nil {
			t.Fatalf("resolveSocketPath failed: %v", err)
		}
		if res != "/custom/socket.sock" {
			t.Errorf("expected /custom/socket.sock, got %s", res)
		}
	})

	t.Run("ConfigDeterminesSocketPath", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("as root the socket path is fixed at /run/banhammer/control.sock")
		}
		tmpDir := t.TempDir()
		cfgContent := `state_dir: ` + tmpDir + `
monitors:
  dummy:
    stdin: true
    match: "<IP>"
`
		cfgPath := filepath.Join(tmpDir, "test_config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
			t.Fatal(err)
		}

		res, err := resolveSocketPath("", cfgPath)
		if err != nil {
			t.Fatalf("resolveSocketPath failed: %v", err)
		}
		expected := filepath.Join(tmpDir, "control.sock")
		if res != expected {
			t.Errorf("expected %s, got %s", expected, res)
		}
	})

	t.Run("BrokenExplicitConfigFailsLoudly", func(t *testing.T) {
		// Falling through to the default search path would point
		// `banhammer unban --all -c broken.yaml` at a different daemon.
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "broken.yaml")
		if err := os.WriteFile(cfgPath, []byte("monitors: [this is not a mapping\n"), 0600); err != nil {
			t.Fatal(err)
		}

		if _, err := resolveSocketPath("", cfgPath); err == nil {
			t.Fatal("expected an error for an unparseable -c, got nil")
		}

		if _, err := resolveSocketPath("", filepath.Join(tmpDir, "absent.yaml")); err == nil {
			t.Fatal("expected an error for a missing -c, got nil")
		}
	})

	t.Run("DefaultSocketPath", func(t *testing.T) {
		got := defaultControlSocketPath("/custom/state")
		want := filepath.Join("/custom/state", "control.sock")
		if os.Geteuid() == 0 {
			// Root ignores state_dir: the packaged unit only gets a writable
			// /run/banhammer.
			want = "/run/banhammer/control.sock"
		}
		if got != want {
			t.Errorf("expected %s, got %s", want, got)
		}
	})
}

// TestDefaultSocketPathMatchesDaemon pins the CLI's idea of the control socket
// to the daemon's.
//
// daemon.defaultControlSocketPath is unexported, so the agreement cannot be
// asserted by calling it; the two are held together by nothing but a comment
// on each side. Reading the source is crude, but it fails when somebody moves
// one of them, which is the whole point — a silent disagreement means every
// management command talks to a socket nobody is listening on.
func TestDefaultSocketPathMatchesDaemon(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "daemon", "daemon.go"))
	if err != nil {
		t.Fatalf("cannot read the daemon source: %v", err)
	}

	rootPath := `"/run/banhammer/control.sock"`
	if !strings.Contains(string(src), rootPath) {
		t.Errorf("daemon.go no longer contains %s; cmd/banhammer must follow it", rootPath)
	}
	if got := defaultControlSocketPath(""); os.Geteuid() == 0 && got != "/run/banhammer/control.sock" {
		t.Errorf("CLI root socket path = %s, want /run/banhammer/control.sock", got)
	}

	// Both sides fall back to <state_dir>/control.sock when unprivileged.
	if !strings.Contains(string(src), `filepath.Join(stateDir, "control.sock")`) {
		t.Error(`daemon.go no longer joins stateDir with "control.sock"`)
	}
}
