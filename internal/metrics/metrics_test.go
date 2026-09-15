package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"banhammer/internal/control"
)

func newTestClock(initial time.Time) (func() time.Time, func(d time.Duration)) {
	var current atomic.Int64
	current.Store(initial.UnixNano())

	now := func() time.Time {
		return time.Unix(0, current.Load())
	}
	advance := func(d time.Duration) {
		current.Add(d.Nanoseconds())
	}
	return now, advance
}

func TestCounters(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, reg *Registry)
	}{
		{
			name: "lines_read increments and totals",
			run: func(t *testing.T, reg *Registry) {
				reg.IncLinesRead("sshd")
				reg.AddLinesRead("sshd", 9)
				reg.AddLinesRead("nginx", 5)

				if got, want := reg.LinesRead("sshd"), int64(10); got != want {
					t.Errorf("LinesRead(sshd) = %d, want %d", got, want)
				}
				if got, want := reg.LinesRead("nginx"), int64(5); got != want {
					t.Errorf("LinesRead(nginx) = %d, want %d", got, want)
				}
				if got, want := reg.LinesRead("missing"), int64(0); got != want {
					t.Errorf("LinesRead(missing) = %d, want %d", got, want)
				}
				if got, want := reg.TotalLinesRead(), int64(15); got != want {
					t.Errorf("TotalLinesRead() = %d, want %d", got, want)
				}
			},
		},
		{
			name: "lines_dropped per-monitor and global",
			run: func(t *testing.T, reg *Registry) {
				reg.IncLinesDropped("sshd")
				reg.AddLinesDropped("sshd", 2)
				reg.IncLinesDropped("") // normalized to global
				reg.IncGlobalLinesDropped()
				reg.AddGlobalLinesDropped(3)

				if got, want := reg.LinesDropped("sshd"), int64(3); got != want {
					t.Errorf("LinesDropped(sshd) = %d, want %d", got, want)
				}
				if got, want := reg.LinesDropped("global"), int64(5); got != want {
					t.Errorf("LinesDropped(global) = %d, want %d", got, want)
				}
				if got, want := reg.LinesDropped(""), int64(5); got != want {
					t.Errorf("LinesDropped(\"\") = %d, want %d", got, want)
				}
				if got, want := reg.TotalLinesDropped(), int64(8); got != want {
					t.Errorf("TotalLinesDropped() = %d, want %d", got, want)
				}
			},
		},
		{
			name: "matches increments and totals",
			run: func(t *testing.T, reg *Registry) {
				reg.IncMatches("sshd")
				reg.AddMatches("sshd", 4)
				reg.AddMatches("caddy", 3)

				if got, want := reg.Matches("sshd"), int64(5); got != want {
					t.Errorf("Matches(sshd) = %d, want %d", got, want)
				}
				if got, want := reg.Matches("caddy"), int64(3); got != want {
					t.Errorf("Matches(caddy) = %d, want %d", got, want)
				}
				if got, want := reg.TotalMatches(), int64(8); got != want {
					t.Errorf("TotalMatches() = %d, want %d", got, want)
				}
			},
		},
		{
			name: "bans and unbans increments and totals",
			run: func(t *testing.T, reg *Registry) {
				reg.IncBans("sshd")
				reg.AddBans("sshd", 2)
				reg.IncUnbans("sshd")

				reg.AddBans("postfix", 4)
				reg.AddUnbans("postfix", 3)

				if got, want := reg.Bans("sshd"), int64(3); got != want {
					t.Errorf("Bans(sshd) = %d, want %d", got, want)
				}
				if got, want := reg.Unbans("sshd"), int64(1); got != want {
					t.Errorf("Unbans(sshd) = %d, want %d", got, want)
				}
				if got, want := reg.TotalBans(), int64(7); got != want {
					t.Errorf("TotalBans() = %d, want %d", got, want)
				}
				if got, want := reg.TotalUnbans(), int64(4); got != want {
					t.Errorf("TotalUnbans() = %d, want %d", got, want)
				}
			},
		},
		{
			name: "action_errors increments and totals",
			run: func(t *testing.T, reg *Registry) {
				reg.IncActionErrors("iptables")
				reg.AddActionErrors("iptables", 2)
				reg.IncActionErrors("nft")
				reg.IncActionErrors("") // normalized to unknown

				if got, want := reg.ActionErrors("iptables"), int64(3); got != want {
					t.Errorf("ActionErrors(iptables) = %d, want %d", got, want)
				}
				if got, want := reg.ActionErrors("nft"), int64(1); got != want {
					t.Errorf("ActionErrors(nft) = %d, want %d", got, want)
				}
				if got, want := reg.ActionErrors("unknown"), int64(1); got != want {
					t.Errorf("ActionErrors(unknown) = %d, want %d", got, want)
				}
				if got, want := reg.TotalActionErrors(), int64(5); got != want {
					t.Errorf("TotalActionErrors() = %d, want %d", got, want)
				}
			},
		},
		{
			name: "decode_errors increments and totals",
			run: func(t *testing.T, reg *Registry) {
				reg.IncDecodeErrors("json_api")
				reg.AddDecodeErrors("json_api", 6)
				reg.IncDecodeErrors("caddy")

				if got, want := reg.DecodeErrors("json_api"), int64(7); got != want {
					t.Errorf("DecodeErrors(json_api) = %d, want %d", got, want)
				}
				if got, want := reg.DecodeErrors("caddy"), int64(1); got != want {
					t.Errorf("DecodeErrors(caddy) = %d, want %d", got, want)
				}
				if got, want := reg.TotalDecodeErrors(), int64(8); got != want {
					t.Errorf("TotalDecodeErrors() = %d, want %d", got, want)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry()
			tc.run(t, reg)
		})
	}
}

func TestGauges(t *testing.T) {
	t.Run("tracked_ips gauge updates", func(t *testing.T) {
		reg := New()
		reg.SetTrackedIPs("sshd", 10)
		reg.IncTrackedIPs("sshd")
		reg.DecTrackedIPs("sshd")
		reg.IncTrackedIPs("sshd")

		reg.SetTrackedIPs("nginx", 5)

		if got, want := reg.TrackedIPs("sshd"), int64(11); got != want {
			t.Errorf("TrackedIPs(sshd) = %d, want %d", got, want)
		}
		if got, want := reg.TrackedIPs("nginx"), int64(5); got != want {
			t.Errorf("TrackedIPs(nginx) = %d, want %d", got, want)
		}
		if got, want := reg.TotalTrackedIPs(), int64(16); got != want {
			t.Errorf("TotalTrackedIPs() = %d, want %d", got, want)
		}
	})

	t.Run("active_bans gauge updates", func(t *testing.T) {
		reg := New()
		reg.SetActiveBans("sshd", 3)
		reg.IncActiveBans("sshd")
		reg.DecActiveBans("sshd")

		reg.SetActiveBans("caddy", 2)

		if got, want := reg.ActiveBans("sshd"), int64(3); got != want {
			t.Errorf("ActiveBans(sshd) = %d, want %d", got, want)
		}
		if got, want := reg.ActiveBans("caddy"), int64(2); got != want {
			t.Errorf("ActiveBans(caddy) = %d, want %d", got, want)
		}
		if got, want := reg.TotalActiveBans(), int64(5); got != want {
			t.Errorf("TotalActiveBans() = %d, want %d", got, want)
		}
	})

	t.Run("uptime gauge with fake clock", func(t *testing.T) {
		t0 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
		clock, advance := newTestClock(t0)

		reg := NewRegistry(WithClock(clock), WithStartTime(t0))

		if got, want := reg.Uptime(), time.Duration(0); got != want {
			t.Errorf("Initial Uptime = %v, want %v", got, want)
		}
		if got, want := reg.UptimeSeconds(), 0.0; got != want {
			t.Errorf("Initial UptimeSeconds = %f, want %f", got, want)
		}

		advance(42 * time.Second)
		if got, want := reg.Uptime(), 42*time.Second; got != want {
			t.Errorf("Uptime after 42s = %v, want %v", got, want)
		}
		if got, want := reg.UptimeSeconds(), 42.0; got != want {
			t.Errorf("UptimeSeconds after 42s = %f, want %f", got, want)
		}

		advance(1500 * time.Millisecond)
		if got, want := reg.UptimeSeconds(), 43.5; got != want {
			t.Errorf("UptimeSeconds after 43.5s = %f, want %f", got, want)
		}

		// Test SetClock and SetStartTime setters
		t1 := t0.Add(100 * time.Second)
		reg.SetStartTime(t1)
		if got := reg.UptimeSeconds(); got >= 0 {
			t.Errorf("UptimeSeconds with future start time = %f, want negative", got)
		}
		reg.SetClock(func() time.Time { return t1.Add(10 * time.Second) })
		if got, want := reg.UptimeSeconds(), 10.0; got != want {
			t.Errorf("UptimeSeconds after SetClock = %f, want %f", got, want)
		}
	})
}

func TestControlStats(t *testing.T) {
	reg := NewRegistry()

	reg.AddLinesRead("sshd", 100)
	reg.AddLinesRead("caddy", 50)
	reg.AddLinesDropped("sshd", 3)
	reg.AddGlobalLinesDropped(7)
	reg.AddMatches("sshd", 20)
	reg.AddMatches("caddy", 10)
	reg.AddBans("sshd", 5)
	reg.AddBans("caddy", 2)
	reg.AddUnbans("sshd", 3)
	reg.AddUnbans("caddy", 1)
	reg.AddActionErrors("iptables", 2)
	reg.AddActionErrors("nft", 1)
	reg.AddDecodeErrors("caddy", 4)

	want := control.Stats{
		LinesRead:    150,
		LinesDropped: 10,
		Matches:      30,
		BansTotal:    7,
		UnbansTotal:  4,
		ActionErrors: 3,
		DecodeErrors: 4,
	}

	got := reg.Stats()
	if got != want {
		t.Fatalf("Stats() mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}

	gotSnapshot := reg.SnapshotStats()
	if gotSnapshot != want {
		t.Fatalf("SnapshotStats() mismatch:\ngot:  %+v\nwant: %+v", gotSnapshot, want)
	}
}

func TestInitMonitorAndBackend(t *testing.T) {
	reg := NewRegistry()
	reg.InitMonitor("auth")
	reg.InitBackend("nft")

	if got := reg.LinesRead("auth"); got != 0 {
		t.Errorf("LinesRead(auth) = %d, want 0", got)
	}
	if got := reg.Matches("auth"); got != 0 {
		t.Errorf("Matches(auth) = %d, want 0", got)
	}
	if got := reg.ActionErrors("nft"); got != 0 {
		t.Errorf("ActionErrors(nft) = %d, want 0", got)
	}

	prom := reg.FormatPrometheus()
	expectedSubstrings := []string{
		`lines_read{monitor="auth"} 0`,
		`lines_dropped{monitor="auth"} 0`,
		`matches{monitor="auth"} 0`,
		`bans{monitor="auth"} 0`,
		`unbans{monitor="auth"} 0`,
		`decode_errors{monitor="auth"} 0`,
		`tracked_ips{monitor="auth"} 0`,
		`active_bans{monitor="auth"} 0`,
		`action_errors{backend="nft"} 0`,
	}
	for _, sub := range expectedSubstrings {
		if !strings.Contains(prom, sub) {
			t.Errorf("FormatPrometheus() missing %q\nFull output:\n%s", sub, prom)
		}
	}
}

func TestReset(t *testing.T) {
	reg := NewRegistry()
	reg.AddLinesRead("sshd", 10)
	reg.SetTrackedIPs("sshd", 5)
	reg.AddActionErrors("iptables", 2)

	if reg.TotalLinesRead() != 10 {
		t.Fatalf("expected TotalLinesRead == 10")
	}

	reg.Reset()

	if got := reg.TotalLinesRead(); got != 0 {
		t.Errorf("after Reset(), TotalLinesRead() = %d, want 0", got)
	}
	if got := reg.TotalTrackedIPs(); got != 0 {
		t.Errorf("after Reset(), TotalTrackedIPs() = %d, want 0", got)
	}
	if got := reg.TotalActionErrors(); got != 0 {
		t.Errorf("after Reset(), TotalActionErrors() = %d, want 0", got)
	}
	if got := reg.Stats(); got != (control.Stats{}) {
		t.Errorf("after Reset(), Stats() = %+v, want empty", got)
	}
}

func TestPrometheusFormat(t *testing.T) {
	t0 := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	clock, _ := newTestClock(t0.Add(3600 * time.Second))

	reg := NewRegistry(WithClock(clock), WithStartTime(t0))

	reg.AddLinesRead("sshd", 100)
	reg.AddLinesDropped("sshd", 2)
	reg.AddGlobalLinesDropped(3)
	reg.AddMatches("sshd", 20)
	reg.AddBans("sshd", 5)
	reg.AddUnbans("sshd", 3)
	reg.AddActionErrors("iptables", 1)
	reg.AddDecodeErrors("sshd", 4)
	reg.SetTrackedIPs("sshd", 12)
	reg.SetActiveBans("sshd", 2)

	out := reg.FormatPrometheus()

	expectedLines := []string{
		"# HELP lines_read Total number of log lines read from sources.",
		"# TYPE lines_read counter",
		`lines_read{monitor="sshd"} 100`,

		"# HELP lines_dropped Total number of log lines dropped due to queue saturation or buffer limits.",
		"# TYPE lines_dropped counter",
		`lines_dropped{monitor="global"} 3`,
		`lines_dropped{monitor="sshd"} 2`,

		"# HELP matches Total number of log lines matching monitor attack patterns.",
		"# TYPE matches counter",
		`matches{monitor="sshd"} 20`,

		"# HELP bans Total number of firewall ban actions executed.",
		"# TYPE bans counter",
		`bans{monitor="sshd"} 5`,

		"# HELP unbans Total number of firewall unban actions executed.",
		"# TYPE unbans counter",
		`unbans{monitor="sshd"} 3`,

		"# HELP action_errors Total number of firewall action execution failures.",
		"# TYPE action_errors counter",
		`action_errors{backend="iptables"} 1`,

		"# HELP decode_errors Total number of log decoding or JSON parsing failures.",
		"# TYPE decode_errors counter",
		`decode_errors{monitor="sshd"} 4`,

		"# HELP tracked_ips Current number of unique offending IP addresses tracked in memory.",
		"# TYPE tracked_ips gauge",
		`tracked_ips{monitor="sshd"} 12`,

		"# HELP active_bans Current number of active firewall IP bans in effect.",
		"# TYPE active_bans gauge",
		`active_bans{monitor="sshd"} 2`,

		"# HELP uptime_seconds Total daemon uptime in seconds.",
		"# TYPE uptime_seconds gauge",
		"uptime_seconds 3600",
	}

	for _, expected := range expectedLines {
		if !strings.Contains(out, expected) {
			t.Errorf("Prometheus output missing line %q\nFull output:\n%s", expected, out)
		}
	}
}

func TestPrometheusEscaping(t *testing.T) {
	reg := NewRegistry()
	specialMonitor := "my\"monitor\\with\nnewline"
	reg.IncLinesRead(specialMonitor)

	out := reg.FormatPrometheus()
	expected := `lines_read{monitor="my\"monitor\\with\nnewline"} 1`
	if !strings.Contains(out, expected) {
		t.Fatalf("Prometheus escaping failed. Expected %q in output:\n%s", expected, out)
	}
}

func TestPrometheusSortedLabels(t *testing.T) {
	reg := NewRegistry()
	reg.AddLinesRead("zebra", 1)
	reg.AddLinesRead("alpha", 2)
	reg.AddLinesRead("charlie", 3)
	reg.AddLinesRead("bravo", 4)

	out := reg.FormatPrometheus()

	alphaIdx := strings.Index(out, `monitor="alpha"`)
	bravoIdx := strings.Index(out, `monitor="bravo"`)
	charlieIdx := strings.Index(out, `monitor="charlie"`)
	zebraIdx := strings.Index(out, `monitor="zebra"`)

	if !(alphaIdx < bravoIdx && bravoIdx < charlieIdx && charlieIdx < zebraIdx) {
		t.Fatalf("Labels not sorted lexicographically:\n%s", out)
	}
}

func TestWithPrefix(t *testing.T) {
	t0 := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	clock, _ := newTestClock(t0.Add(60 * time.Second))

	reg := NewRegistry(WithPrefix("banhammer_"), WithClock(clock), WithStartTime(t0))
	reg.IncLinesRead("sshd")

	out := reg.FormatPrometheus()

	expectedSubstrings := []string{
		"# HELP banhammer_lines_read",
		"# TYPE banhammer_lines_read counter",
		`banhammer_lines_read{monitor="sshd"} 1`,
		"# HELP banhammer_uptime_seconds",
		"# TYPE banhammer_uptime_seconds gauge",
		"banhammer_uptime_seconds 60",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("Expected prefixed output to contain %q\nFull output:\n%s", sub, out)
		}
	}
}

func TestHttpHandler(t *testing.T) {
	reg := NewRegistry()
	reg.IncLinesRead("sshd")
	h := reg.Handler()

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		checkBody  func(t *testing.T, body string)
	}{
		{
			name:       "GET /metrics returns 200 and text format",
			method:     http.MethodGet,
			target:     "/metrics",
			wantStatus: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if !strings.Contains(body, `lines_read{monitor="sshd"} 1`) {
					t.Errorf("missing lines_read metric in body: %s", body)
				}
				if !strings.Contains(body, "uptime_seconds") {
					t.Errorf("missing uptime_seconds metric in body: %s", body)
				}
			},
		},
		{
			name:       "HEAD /metrics returns 200 and empty body",
			method:     http.MethodHead,
			target:     "/metrics",
			wantStatus: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				if body != "" {
					t.Errorf("expected empty body for HEAD, got: %q", body)
				}
			},
		},
		{
			name:       "POST /metrics returns 405 Method Not Allowed",
			method:     http.MethodPost,
			target:     "/metrics",
			wantStatus: http.StatusMethodNotAllowed,
			checkBody:  nil,
		},
		{
			name:       "PUT /metrics returns 405 Method Not Allowed",
			method:     http.MethodPut,
			target:     "/metrics",
			wantStatus: http.StatusMethodNotAllowed,
			checkBody:  nil,
		},
		{
			name:       "DELETE /metrics returns 405 Method Not Allowed",
			method:     http.MethodDelete,
			target:     "/metrics",
			wantStatus: http.StatusMethodNotAllowed,
			checkBody:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.target, nil)

			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}

			if tc.wantStatus == http.StatusOK {
				ct := rec.Header().Get("Content-Type")
				if ct != ContentTypeLatest {
					t.Errorf("Content-Type = %q, want %q", ct, ContentTypeLatest)
				}
			}

			if tc.checkBody != nil {
				tc.checkBody(t, rec.Body.String())
			}
		})
	}
}

func TestConcurrentSafety(t *testing.T) {
	reg := NewRegistry()
	monitors := []string{"sshd", "nginx", "caddy", "dovecot", "postfix"}
	backends := []string{"iptables", "nft", "ipset", "cmd"}

	const numWorkers = 50
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers * 2)

	// Increment workers
	for w := 0; w < numWorkers; w++ {
		go func(id int) {
			defer wg.Done()
			mon := monitors[id%len(monitors)]
			be := backends[id%len(backends)]

			for i := 0; i < iterations; i++ {
				reg.IncLinesRead(mon)
				reg.IncLinesDropped(mon)
				reg.IncMatches(mon)
				reg.IncBans(mon)
				reg.IncUnbans(mon)
				reg.IncActionErrors(be)
				reg.IncDecodeErrors(mon)
				reg.IncTrackedIPs(mon)
				reg.IncActiveBans(mon)
			}
		}(w)
	}

	// Concurrent reader / scraper workers
	for w := 0; w < numWorkers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = reg.Stats()
				_ = reg.FormatPrometheus()
				_ = reg.TotalLinesRead()
				_ = reg.TotalActiveBans()
			}
		}()
	}

	wg.Wait()

	expectedIncrements := int64(numWorkers * iterations)
	if got := reg.TotalLinesRead(); got != expectedIncrements {
		t.Errorf("TotalLinesRead() = %d, want %d", got, expectedIncrements)
	}
	if got := reg.TotalMatches(); got != expectedIncrements {
		t.Errorf("TotalMatches() = %d, want %d", got, expectedIncrements)
	}
	if got := reg.TotalBans(); got != expectedIncrements {
		t.Errorf("TotalBans() = %d, want %d", got, expectedIncrements)
	}
	if got := reg.TotalUnbans(); got != expectedIncrements {
		t.Errorf("TotalUnbans() = %d, want %d", got, expectedIncrements)
	}
	if got := reg.TotalActionErrors(); got != expectedIncrements {
		t.Errorf("TotalActionErrors() = %d, want %d", got, expectedIncrements)
	}
	if got := reg.TotalDecodeErrors(); got != expectedIncrements {
		t.Errorf("TotalDecodeErrors() = %d, want %d", got, expectedIncrements)
	}
}

func TestServerLifecycle(t *testing.T) {
	reg := NewRegistry()
	reg.IncLinesRead("sshd")

	logger := slog.New(slog.DiscardHandler)
	srv := NewServer("127.0.0.1:0", reg, logger, WithShutdownTimeout(2*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- srv.Run(ctx)
	}()

	// Await ready signal without arbitrary sleeping
	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server Ready() signal")
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("server Addr() is empty after Ready()")
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Test /metrics
	resp, err := client.Get(fmt.Sprintf("http://%s/metrics", addr))
	if err != nil {
		t.Fatalf("GET /metrics error: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /metrics response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `lines_read{monitor="sshd"} 1`) {
		t.Errorf("GET /metrics body missing metric:\n%s", string(body))
	}

	// 2. Test /healthz
	resp, err = client.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("GET /healthz error: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /healthz response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok\n" {
		t.Errorf("GET /healthz body = %q, want %q", string(body), "ok\n")
	}

	// 3. Test / (root)
	resp, err = client.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET / error: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read / response error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "banhammer metrics server") {
		t.Errorf("GET / body = %q", string(body))
	}

	// 4. Test 404 for nonexistent path
	resp, err = client.Get(fmt.Sprintf("http://%s/not-found", addr))
	if err != nil {
		t.Fatalf("GET /not-found error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /not-found status = %d, want 404", resp.StatusCode)
	}

	// 5. Test 405 Method Not Allowed on /healthz
	resp, err = client.Post(fmt.Sprintf("http://%s/healthz", addr), "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /healthz error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz status = %d, want 405", resp.StatusCode)
	}

	// 6. Test graceful shutdown via context cancellation
	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Errorf("Server.Run() returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Server.Run() to exit gracefully")
	}
}

func TestServerCustomListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	reg := NewRegistry()
	srv := NewServer("", reg, nil, WithListener(ln))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- srv.Run(ctx)
	}()

	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Ready()")
	}

	if got, want := srv.Addr(), ln.Addr().String(); got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}

	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Errorf("Run() returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServerPreCancelledContext(t *testing.T) {
	reg := NewRegistry()
	srv := NewServer("127.0.0.1:0", reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before Run

	err := srv.Run(ctx)
	if err != nil {
		t.Errorf("Run with pre-cancelled context returned error: %v", err)
	}
}

func TestServerAlreadyRunning(t *testing.T) {
	reg := NewRegistry()
	srv := NewServer("127.0.0.1:0", reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Run(ctx)
	}()

	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Ready()")
	}

	// Attempt secondary concurrent Run call on same server instance
	err := srv.Run(ctx)
	if !errors.Is(err, ErrServerRunning) {
		t.Errorf("expected ErrServerRunning, got %v", err)
	}
}

func TestServerInvalidAddress(t *testing.T) {
	reg := NewRegistry()
	srv := NewServer("999.999.999.999:99999", reg, nil)

	err := srv.Run(context.Background())
	if err == nil {
		t.Fatal("expected error on invalid address, got nil")
	}
	if !strings.Contains(err.Error(), "metrics: listen on") {
		t.Errorf("error %q should wrap listen error", err.Error())
	}
}

func TestServerClose(t *testing.T) {
	reg := NewRegistry()
	srv := NewServer("127.0.0.1:0", reg, nil)

	go func() {
		_ = srv.Run(context.Background())
	}()

	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Ready()")
	}

	if err := srv.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}
