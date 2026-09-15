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
	"strings"
	"testing"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/model"
)

// mockService implements control.Service for testing control CLI commands.
type mockService struct {
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
}

func (m *mockService) Status() (control.StatusResponse, error) {
	if m.statusErr != nil {
		return control.StatusResponse{}, m.statusErr
	}
	return m.statusResp, nil
}

func (m *mockService) Ban(ip netip.Addr, monitor string, d time.Duration) error {
	if m.banErr != nil {
		return m.banErr
	}
	m.bannedIP = ip
	m.bannedMon = monitor
	m.bannedDur = d
	return nil
}

func (m *mockService) Unban(ip netip.Addr) error {
	if m.unbanErr != nil {
		return m.unbanErr
	}
	m.unbannedIP = ip
	return nil
}

func (m *mockService) UnbanAll() error {
	if m.unbanAllErr != nil {
		return m.unbanAllErr
	}
	m.unbannedAll = true
	return nil
}

func (m *mockService) Reload() error {
	if m.reloadErr != nil {
		return m.reloadErr
	}
	m.reloaded = true
	return nil
}

// startMockControlServer starts an in-process control.Server on a temporary socket.
func startMockControlServer(t *testing.T, svc control.Service) (string, func()) {
	t.Helper()
	dir := t.TempDir()
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
		_, _, err := executeCommand("status", "--socket", filepath.Join(t.TempDir(), "nonexistent.sock"))
		if err == nil {
			t.Fatal("expected error connecting to nonexistent socket, got nil")
		}
	})
}

func TestBanCommand(t *testing.T) {
	mock := &mockService{}
	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("ValidBan", func(t *testing.T) {
		stdout, _, err := executeCommand("ban", "198.51.100.42", "-m", "custom_monitor", "-t", "45m", "--socket", sockPath)
		if err != nil {
			t.Fatalf("ban command failed: %v", err)
		}

		expected := "banned 198.51.100.42 for 45m (monitor: custom_monitor)"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

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

	t.Run("DefaultFlags", func(t *testing.T) {
		stdout, _, err := executeCommand("ban", "2001:db8::1", "--socket", sockPath)
		if err != nil {
			t.Fatalf("ban with defaults failed: %v", err)
		}

		expected := "banned 2001:db8::1 for 1h (monitor: manual)"
		if !strings.Contains(stdout, expected) {
			t.Errorf("expected output %q, got %q", expected, stdout)
		}

		if mock.bannedIP != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("expected banned IP 2001:db8::1, got %s", mock.bannedIP)
		}
		if mock.bannedMon != "manual" {
			t.Errorf("expected monitor manual, got %s", mock.bannedMon)
		}
		if mock.bannedDur != time.Hour {
			t.Errorf("expected duration 1h, got %s", mock.bannedDur)
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

	t.Run("MissingArg", func(t *testing.T) {
		_, _, err := executeCommand("ban", "--socket", sockPath)
		if err == nil {
			t.Fatal("expected error when IP argument is omitted, got nil")
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		mock.banErr = errors.New("underlying firewall error")
		defer func() { mock.banErr = nil }()

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
		mock.unbanErr = errors.New("ban not found")
		defer func() { mock.unbanErr = nil }()

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

		if !mock.reloaded {
			t.Error("expected reloaded to be true on mock service")
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		mock.reloadErr = errors.New("reload failed")
		defer func() { mock.reloadErr = nil }()

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
		res := resolveSocketPath("/custom/socket.sock", "/some/config.yaml")
		if res != "/custom/socket.sock" {
			t.Errorf("expected /custom/socket.sock, got %s", res)
		}
	})

	t.Run("ConfigDeterminesSocketPath", func(t *testing.T) {
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

		res := resolveSocketPath("", cfgPath)
		expected := filepath.Join(tmpDir, "control.sock")
		if res != expected {
			t.Errorf("expected %s, got %s", expected, res)
		}
	})

	t.Run("FallbackDefaultSocketPath", func(t *testing.T) {
		res := defaultControlSocketPath("/custom/state")
		expected := filepath.Join("/custom/state", "control.sock")
		if res != expected {
			t.Errorf("expected %s, got %s", expected, res)
		}
	})
}
