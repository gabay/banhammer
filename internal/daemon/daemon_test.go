package daemon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/config"
	"banhammer/internal/control"
	"banhammer/internal/model"
)

type recordingRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingRunner) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, slices.Clone(argv))
	r.mu.Unlock()
	return nil, nil
}

func (r *recordingRunner) Calls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.calls))
	copy(out, r.calls)
	return out
}

func (r *recordingRunner) HasArg(arg string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, call := range r.calls {
		if slices.Contains(call, arg) {
			return true
		}
	}
	return false
}

func baseTestConfig(stateDir string) *config.Config {
	return &config.Config{
		StateDir:   stateDir,
		LogFormat:  "text",
		AllowLocal: true,
		QueueSize:  1024,
		Defaults: config.Settings{
			Threshold:     3,
			Window:        10 * time.Minute,
			Bantime:       1 * time.Hour,
			BantimeFactor: 1,
			BantimeMax:    24 * time.Hour,
			FindHistory:   24 * time.Hour,
			MaxTracked:    1000,
			StartAt:       "beginning",
			OnRepeat:      "ignore",
			Action: config.ActionSpec{
				Name:    "iptables",
				Timeout: 5 * time.Second,
			},
		},
		Monitors: map[string]*config.Monitor{
			"sshd": {
				Name:   "sshd",
				Stdin:  true,
				Format: "text",
				Match: config.Patterns{
					Line: []string{"Failed password for .* from <IP>"},
				},
				Settings: config.Settings{
					Threshold:     3,
					Window:        10 * time.Minute,
					Bantime:       1 * time.Hour,
					BantimeFactor: 1,
					BantimeMax:    24 * time.Hour,
					FindHistory:   24 * time.Hour,
					MaxTracked:    1000,
					StartAt:       "beginning",
					OnRepeat:      "ignore",
					Action: config.ActionSpec{
						Name:    "iptables",
						Timeout: 5 * time.Second,
					},
				},
			},
		},
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

// 1. End-to-end: Feed log lines, reach threshold, verify ban is sent to executor and recorded in runner.
func TestDaemon_EndToEnd_ThresholdBan(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	logInput := "Failed password for invalid user admin from 192.0.2.10\n" +
		"Failed password for invalid user admin from 192.0.2.10\n" +
		"Failed password for invalid user admin from 192.0.2.10\n"

	stdinReader := bytes.NewBufferString(logInput)

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(stdinReader),
		WithControlSocket(""), // disable socket for this test
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- d.Run(ctx)
	}()

	// Wait for the ban to be recorded in runner
	waitForCondition(t, 3*time.Second, func() bool {
		return runner.HasArg("192.0.2.10")
	})

	if !runner.HasArg("192.0.2.10") {
		t.Fatalf("expected 192.0.2.10 to be banned in runner, calls: %v", runner.Calls())
	}

	// Verify metrics
	if got := d.Metrics().Matches("sshd"); got != 3 {
		t.Errorf("Matches = %d, want 3", got)
	}
	if got := d.Metrics().Bans("sshd"); got != 1 {
		t.Errorf("Bans = %d, want 1", got)
	}

	cancel()
	if err := <-runErrCh; err != nil {
		t.Errorf("Run error: %v", err)
	}
}

// 2. Verify status response via daemon.Service().Status()
func TestDaemon_Status(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = d.Run(ctx) }()

	// Add manual ban
	targetIP := netip.MustParseAddr("192.0.2.42")
	if err := d.Service().Ban(targetIP, "sshd", time.Hour); err != nil {
		t.Fatalf("manual ban failed: %v", err)
	}

	status, err := d.Service().Status()
	if err != nil {
		t.Fatalf("Status() failed: %v", err)
	}

	if len(status.Monitors) != 1 || status.Monitors[0].Name != "sshd" {
		t.Errorf("unexpected monitors: %+v", status.Monitors)
	}
	if status.Monitors[0].Type != "stdin" {
		t.Errorf("monitor type = %q, want stdin", status.Monitors[0].Type)
	}

	if len(status.Bans) != 1 || status.Bans[0].IP != targetIP {
		t.Errorf("bans = %+v, want ban for %v", status.Bans, targetIP)
	}
	if status.Stats.BansTotal != 1 {
		t.Errorf("Stats.BansTotal = %d, want 1", status.Stats.BansTotal)
	}
}

// 3. Verify manual ban and unban via daemon.Service()
func TestDaemon_ManualBanAndUnban(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	svc := d.Service()

	ip1 := netip.MustParseAddr("192.0.2.101")
	ip2 := netip.MustParseAddr("192.0.2.102")

	// 1. Ban ip1
	if err := svc.Ban(ip1, "sshd", time.Hour); err != nil {
		t.Fatalf("Ban ip1: %v", err)
	}
	waitForCondition(t, 2*time.Second, func() bool {
		return runner.HasArg("192.0.2.101")
	})

	// 2. Ban ip2
	if err := svc.Ban(ip2, "sshd", time.Hour); err != nil {
		t.Fatalf("Ban ip2: %v", err)
	}
	waitForCondition(t, 2*time.Second, func() bool {
		return runner.HasArg("192.0.2.102")
	})

	status, err := svc.Status()
	if err != nil || len(status.Bans) != 2 {
		t.Fatalf("Status expected 2 bans, got %d (err: %v)", len(status.Bans), err)
	}

	// 3. Unban ip1
	if err := svc.Unban(ip1); err != nil {
		t.Fatalf("Unban ip1: %v", err)
	}

	status, err = svc.Status()
	if err != nil || len(status.Bans) != 1 || status.Bans[0].IP != ip2 {
		t.Fatalf("Status after Unban expected only ip2, got: %+v", status.Bans)
	}

	// 4. UnbanAll
	if err := svc.UnbanAll(); err != nil {
		t.Fatalf("UnbanAll: %v", err)
	}

	status, err = svc.Status()
	if err != nil || len(status.Bans) != 0 {
		t.Fatalf("Status after UnbanAll expected 0 bans, got %d", len(status.Bans))
	}
}

// 4. Verify allowlist prevents ban
func TestDaemon_Allowlist(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.Allowlist = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	runner := &recordingRunner{}

	logInput := "Failed password for root from 192.0.2.5\n" +
		"Failed password for root from 192.0.2.5\n" +
		"Failed password for root from 192.0.2.5\n" +
		"Failed password for root from 192.0.2.5\n"

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(bytes.NewBufferString(logInput)),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	// Wait until matches are counted
	waitForCondition(t, 2*time.Second, func() bool {
		return d.Metrics().Matches("sshd") >= 3
	})

	// Assert runner has no ban for 192.0.2.5
	if runner.HasArg("192.0.2.5") {
		t.Fatalf("allowlisted IP was banned! calls: %v", runner.Calls())
	}

	// Manual ban should also fail with ErrAllowlisted
	err = d.Service().Ban(netip.MustParseAddr("192.0.2.5"), "sshd", time.Hour)
	if err == nil || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("expected allowlisted error, got: %v", err)
	}
}

// 5. Test drop-oldest behavior on full queue
func TestDaemon_DropOldestQueue(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.QueueSize = 2

	d, err := New(cfg,
		WithRunner(&recordingRunner{}),
		WithQueueSize(2),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer d.Close()

	// Enqueue 5 events into capacity-2 queue without consumers running
	ev1 := model.Event{Monitor: "sshd", Raw: []byte("line 1")}
	ev2 := model.Event{Monitor: "sshd", Raw: []byte("line 2")}
	ev3 := model.Event{Monitor: "sshd", Raw: []byte("line 3")}
	ev4 := model.Event{Monitor: "sshd", Raw: []byte("line 4")}
	ev5 := model.Event{Monitor: "sshd", Raw: []byte("line 5")}

	if !d.Enqueue(ev1) || !d.Enqueue(ev2) || !d.Enqueue(ev3) || !d.Enqueue(ev4) || !d.Enqueue(ev5) {
		t.Fatalf("Enqueue failed unexpectedly")
	}

	// Total dropped should be 3
	dropped := d.Metrics().TotalLinesDropped()
	if dropped != 3 {
		t.Errorf("TotalLinesDropped = %d, want 3", dropped)
	}

	// Queue should have 2 elements: ev4 and ev5
	first := <-d.queue
	second := <-d.queue

	if string(first.Raw) != "line 4" || string(second.Raw) != "line 5" {
		t.Errorf("queue contains [%s, %s], want [line 4, line 5]", first.Raw, second.Raw)
	}
}

// 6. Test restart recovery: start daemon 1, trigger ban, stop daemon 1, start daemon 2 with same store dir, assert ban is restored
func TestDaemon_RestartRecovery(t *testing.T) {
	stateDir := t.TempDir()
	cfg1 := baseTestConfig(stateDir)
	runner1 := &recordingRunner{}

	logInput := "Failed password for user from 192.0.2.77\n" +
		"Failed password for user from 192.0.2.77\n" +
		"Failed password for user from 192.0.2.77\n"

	d1, err := New(cfg1,
		WithRunner(runner1),
		WithStdin(bytes.NewBufferString(logInput)),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New d1: %v", err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	run1Done := make(chan error, 1)
	go func() {
		run1Done <- d1.Run(ctx1)
	}()

	// Wait for ban to be applied
	waitForCondition(t, 3*time.Second, func() bool {
		return runner1.HasArg("192.0.2.77")
	})

	// Stop daemon 1
	cancel1()
	if err := <-run1Done; err != nil {
		t.Fatalf("d1 Run error: %v", err)
	}

	// Start daemon 2 with the same state directory
	cfg2 := baseTestConfig(stateDir)
	runner2 := &recordingRunner{}

	d2, err := New(cfg2,
		WithRunner(runner2),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New d2: %v", err)
	}
	defer d2.Close()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = d2.Run(ctx2) }()

	// Verify ban was restored into daemon 2 state
	status, err := d2.Service().Status()
	if err != nil {
		t.Fatalf("d2 Status(): %v", err)
	}

	found := false
	for _, b := range status.Bans {
		if b.IP.String() == "192.0.2.77" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("restored bans in d2 do not include 192.0.2.77: %+v", status.Bans)
	}

	// Verify ban was re-applied to runner 2
	waitForCondition(t, 2*time.Second, func() bool {
		return runner2.HasArg("192.0.2.77")
	})
}

// 7. Test graceful shutdown cleans up and closes cleanly without goroutine leaks
func TestDaemon_GracefulShutdown(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- d.Run(ctx)
	}()

	// Give it a brief moment to initialize all subsystems
	time.Sleep(50 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung; goroutine leak or deadlock")
	}

	// Assert closing store works (idempotent)
	if err := d.Close(); err != nil {
		t.Errorf("Close error: %v", err)
	}
}

// 8. Test Control Server IPC over Unix domain socket
func TestDaemon_ControlIPC(t *testing.T) {
	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "test-control.sock")
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(socketPath),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = d.Run(ctx) }()

	// Wait for control server to bind socket
	select {
	case <-d.ControlReady():
	case <-time.After(3 * time.Second):
		t.Fatal("control server ready timed out")
	}

	client := control.NewClient(socketPath)

	// 1. Status query via IPC
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("client.Status: %v", err)
	}
	if len(status.Monitors) != 1 || status.Monitors[0].Name != "sshd" {
		t.Errorf("unexpected IPC status response: %+v", status)
	}

	// 2. Ban via IPC
	targetIP := netip.MustParseAddr("198.51.100.1")
	if err := client.Ban(ctx, targetIP, "sshd", time.Hour); err != nil {
		t.Fatalf("client.Ban: %v", err)
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return runner.HasArg("198.51.100.1")
	})

	// 3. Unban via IPC
	if err := client.Unban(ctx, targetIP); err != nil {
		t.Fatalf("client.Unban: %v", err)
	}

	// 4. Reload via IPC
	// Write a valid config file for reload
	cfgPath := filepath.Join(stateDir, "config.yaml")
	cfgContent := `
defaults:
  threshold: 2
  window: 5m
  bantime: 30m
monitors:
  sshd:
    stdin: true
    match: "Failed password .* from <IP>"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	d.configPath = cfgPath

	if err := client.Reload(ctx); err != nil {
		t.Fatalf("client.Reload: %v", err)
	}
}

// 9. Test dynamic config reload
func TestDaemon_ConfigReload(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	// New config with lower threshold (2 instead of 3)
	newCfg := baseTestConfig(stateDir)
	newCfg.Monitors["sshd"].Threshold = 2
	newCfg.Monitors["sshd"].Settings.Threshold = 2

	if err := d.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	// Send 2 lines for 192.0.2.88
	d.Enqueue(model.Event{Monitor: "sshd", Raw: []byte("Failed password for user from 192.0.2.88")})
	d.Enqueue(model.Event{Monitor: "sshd", Raw: []byte("Failed password for user from 192.0.2.88")})

	// Should trigger ban with 2 hits
	waitForCondition(t, 2*time.Second, func() bool {
		return runner.HasArg("192.0.2.88")
	})
}

// 10. Test metrics HTTP server
func TestDaemon_MetricsServer(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.Metrics.Listen = "127.0.0.1:0"
	runner := &recordingRunner{}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	select {
	case <-d.MetricsReady():
	case <-time.After(3 * time.Second):
		t.Fatal("metrics server ready timed out")
	}

	addr := d.metricsServer.Addr()
	if addr == "" {
		t.Fatal("metrics server address is empty")
	}

	// 1. Healthz probe
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok\n" {
		t.Errorf("GET /healthz body = %q, want ok\\n", body)
	}

	// 2. Metrics scrape
	resp2, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want 200", resp2.StatusCode)
	}
	mBody, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(mBody), "lines_read") {
		t.Errorf("GET /metrics output missing lines_read: %s", mBody)
	}
}

// 11. Test multi-monitor routing and custom actions
func TestDaemon_MultiMonitorCustomAction(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	runner := &recordingRunner{}

	cfg.Monitors["custom"] = &config.Monitor{
		Name:   "custom",
		Stdin:  true,
		Format: "text",
		Match: config.Patterns{
			Line: []string{"Attack from <IP>"},
		},
		Settings: config.Settings{
			Threshold:     1,
			Window:        5 * time.Minute,
			Bantime:       10 * time.Minute,
			BantimeFactor: 1,
			BantimeMax:    1 * time.Hour,
			FindHistory:   1 * time.Hour,
			MaxTracked:    100,
			Action: config.ActionSpec{
				Name:    "cmd",
				Ban:     "/bin/echo BAN {ip} {monitor}",
				Unban:   "/bin/echo UNBAN {ip} {monitor}",
				Timeout: 2 * time.Second,
			},
		},
	}

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	// Trigger custom monitor
	d.Enqueue(model.Event{
		Monitor: "custom",
		Raw:     []byte("Attack from 198.51.100.99"),
	})

	waitForCondition(t, 2*time.Second, func() bool {
		return runner.HasArg("198.51.100.99")
	})

	// Check that custom command template was formatted
	found := false
	for _, call := range runner.Calls() {
		if slices.Contains(call, "/bin/echo") && slices.Contains(call, "BAN") && slices.Contains(call, "198.51.100.99") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("custom action not found in runner calls: %v", runner.Calls())
	}
}

// 12. Test decode errors on JSON monitor
func TestDaemon_DecodeError(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.Monitors["jsonmon"] = &config.Monitor{
		Name:    "jsonmon",
		Stdin:   true,
		Format:  "json",
		IPField: "remote_ip",
		Match: config.Patterns{
			Fields: map[string]string{"status": "^403$"},
		},
		Settings: config.Settings{
			Threshold:     2,
			Window:        5 * time.Minute,
			Bantime:       10 * time.Minute,
			BantimeFactor: 1,
			BantimeMax:    1 * time.Hour,
			FindHistory:   1 * time.Hour,
			MaxTracked:    100,
			Action: config.ActionSpec{
				Name: "iptables",
			},
		},
	}

	d, err := New(cfg,
		WithRunner(&recordingRunner{}),
		WithStdin(strings.NewReader("")),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	// Send malformed JSON line
	d.Enqueue(model.Event{
		Monitor: "jsonmon",
		Raw:     []byte("{this is definitely not valid json"),
	})

	waitForCondition(t, 2*time.Second, func() bool {
		return d.Metrics().DecodeErrors("jsonmon") == 1
	})
}

// 13. Test sliding-window tracker sweep and instant clock
func TestDaemon_Sweep(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)

	mockTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var timeMu sync.Mutex
	nowFn := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return mockTime
	}

	d, err := New(cfg,
		WithRunner(&recordingRunner{}),
		WithStdin(strings.NewReader("")),
		WithNow(nowFn),
		WithControlSocket(""),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	// Send 1 hit (threshold is 3, so not banned yet)
	d.Enqueue(model.Event{
		Monitor: "sshd",
		Raw:     []byte("Failed password for root from 192.0.2.200"),
	})

	waitForCondition(t, 2*time.Second, func() bool {
		return d.Metrics().TrackedIPs("sshd") == 1
	})

	// Advance time past the 10-minute window
	timeMu.Lock()
	mockTime = mockTime.Add(15 * time.Minute)
	timeMu.Unlock()

	// Trigger sweep
	d.Sweep()

	waitForCondition(t, 2*time.Second, func() bool {
		return d.Metrics().TrackedIPs("sshd") == 0
	})
}
