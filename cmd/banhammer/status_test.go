package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/model"
	"banhammer/internal/stats"
)

type cliGeo map[string]string

func (g cliGeo) Country(ip netip.Addr) (string, bool) {
	c, ok := g[ip.String()]
	return c, ok
}

// TestStatusCommandHistory covers the History section: it is printed when
// the daemon sends one, omitted when it does not (an older daemon, or a
// mock), and survives --json intact.
func TestStatusCommandHistory(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.10")
	ip2 := netip.MustParseAddr("198.51.100.7")
	events := []model.BanEvent{
		{IP: ip, Monitor: "sshd", At: now.Add(-5 * time.Minute)},
		{IP: ip, Monitor: "sshd", At: now.Add(-2 * time.Hour)},
		{IP: ip2, Monitor: "nginx", At: now.Add(-3 * 24 * time.Hour)},
	}
	active := []model.Ban{{IP: ip, Monitor: "sshd", At: now.Add(-5 * time.Minute), Until: now.Add(time.Hour), Count: 5, Offense: 2}}
	summary := stats.Summarize(events, active, now, stats.SummaryOptions{
		Location:    time.UTC,
		Retention:   30 * 24 * time.Hour,
		Geo:         cliGeo{ip.String(): "DE"},
		CountryName: func(c string) string { return map[string]string{"DE": "Germany"}[c] },
	})

	mock := &mockService{statusResp: control.StatusResponse{
		Uptime:   time.Hour,
		Monitors: []control.MonitorStatus{{Name: "sshd", Type: "file", Target: "/var/log/auth.log"}},
		Bans:     active,
		History:  &summary,
	}}
	sockPath, cleanup := startMockControlServer(t, mock)
	defer cleanup()

	t.Run("TextOutput", func(t *testing.T) {
		stdout, _, err := executeCommand("status", "--socket", sockPath)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		for _, want := range []string{
			"History (last 30d, 3 events):",
			"WINDOW", "1h", "24h", "7d", "30d",
			"Repeat offenders: 1 of 2 addresses banned more than once",
			"Bans by monitor:",
			"sshd", "nginx",
			"Top offenders:",
			"192.0.2.10", "Germany (DE)",
			"198.51.100.7", "unknown",
			"Top countries:",
			"Last 24h:", "Last 30d:",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("status output missing %q:\n%s", want, stdout)
			}
		}
	})

	t.Run("JSONOutput", func(t *testing.T) {
		stdout, _, err := executeCommand("status", "--socket", sockPath, "--json")
		if err != nil {
			t.Fatalf("status --json: %v", err)
		}
		var parsed control.StatusResponse
		if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
			t.Fatalf("parse: %v\n%s", err, stdout)
		}
		if parsed.History == nil || parsed.History.Events != 3 || parsed.History.TopOffenders[0].IP != ip {
			t.Errorf("history did not survive --json: %+v", parsed.History)
		}
	})

	t.Run("AbsentHistory", func(t *testing.T) {
		mock.mu.Lock()
		mock.statusResp.History = nil
		mock.mu.Unlock()
		stdout, _, err := executeCommand("status", "--socket", sockPath)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if strings.Contains(stdout, "History") {
			t.Errorf("History section printed without history:\n%s", stdout)
		}
	})
}

func TestSparkline(t *testing.T) {
	t.Parallel()
	b := func(ns ...int) []stats.Bucket {
		out := make([]stats.Bucket, len(ns))
		for i, n := range ns {
			out[i].Bans = n
		}
		return out
	}
	for _, tc := range []struct {
		in   []stats.Bucket
		want string
	}{
		{b(), ""},
		{b(0, 0), "  "},
		{b(1), "█"},
		{b(0, 1, 8), " ▁█"},
		{b(100, 50, 1), "█▄▁"},
	} {
		if got := sparkline(tc.in); got != tc.want {
			t.Errorf("sparkline(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShortDuration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{30 * 24 * time.Hour, "30d"},
		{36 * time.Hour, "36h"},
		{90 * time.Minute, "1h30m0s"},
	} {
		if got := shortDuration(tc.d); got != tc.want {
			t.Errorf("shortDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
