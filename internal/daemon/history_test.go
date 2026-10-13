package daemon

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"banhammer/internal/config"
	"banhammer/internal/stats"
	"banhammer/internal/store"
)

// writeTestGeoCSV writes a two-range country database the daemon can open.
func writeTestGeoCSV(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "countries.csv")
	csv := "start_ip,end_ip,country_code\n192.0.2.0,192.0.2.255,DE\n198.51.100.0,198.51.100.255,JP\n"
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestDaemon_HistoryAndStatusPage drives the whole statistics path: a
// threshold ban lands in the ledger, the status response carries a summary
// with geography, the web page serves it, history.json is written, and a
// second daemon on the same state directory restores the ledger.
func TestDaemon_HistoryAndStatusPage(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.Web = config.Web{
		Enabled:   true,
		Listen:    "127.0.0.1:0",
		GeoIP:     writeTestGeoCSV(t),
		Retention: 7 * 24 * time.Hour,
	}
	runner := &recordingRunner{}
	logInput := strings.Repeat("Failed password for invalid user admin from 192.0.2.10\n", 3)

	d, err := New(cfg,
		WithRunner(runner),
		WithStdin(bytes.NewBufferString(logInput)),
		WithControlSocket(""),
		WithHistoryInterval(50*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- d.Run(ctx) }()
	<-d.WebReady()

	waitForCondition(t, 3*time.Second, func() bool { return runner.HasArg("192.0.2.10") })
	// A manual ban from an address the database knows under another country.
	if err := d.Service().Ban(netip.MustParseAddr("198.51.100.7"), "manual", time.Hour); err != nil {
		t.Fatalf("manual ban: %v", err)
	}

	// --- status response -------------------------------------------------
	status, err := d.Service().Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	h := status.History
	if h == nil {
		t.Fatal("status has no history")
	}
	if h.Events != 2 || !h.GeoEnabled || h.RetentionSeconds != 7*24*3600 {
		t.Errorf("summary = events %d geo %v retention %d", h.Events, h.GeoEnabled, h.RetentionSeconds)
	}
	var day stats.Window
	for _, w := range h.Windows {
		if w.Name == stats.WindowDay {
			day = w
		}
	}
	if day.Bans != 2 || day.UniqueIPs != 2 {
		t.Errorf("24h window = %+v", day)
	}
	if h.IPCountries["192.0.2.10"] != "DE" || h.IPCountries["198.51.100.7"] != "JP" {
		t.Errorf("IPCountries = %v", h.IPCountries)
	}
	if len(h.ActiveCountries) != 2 || h.ActiveCountries[0].Name == "" {
		t.Errorf("ActiveCountries = %+v (names should come from geoip.Name)", h.ActiveCountries)
	}
	if len(h.Monitors) != 2 || h.Monitors[0].Name != "manual" || h.Monitors[1].Name != "sshd" {
		t.Errorf("Monitors = %+v", h.Monitors)
	}

	// --- web page ---------------------------------------------------------
	addr := d.WebAddr()
	if addr == "" {
		t.Fatal("WebAddr is empty after WebReady")
	}
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	for _, want := range []string{"192.0.2.10", "198.51.100.7", "Germany", "Japan", "🇩🇪", "🇯🇵", "Bans per hour"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("page missing %q", want)
		}
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("page served without a CSP")
	}
	post, err := http.Post("http://"+addr+"/", "text/plain", strings.NewReader("unban"))
	if err != nil {
		t.Fatalf("POST /: %v", err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d, want 405", post.StatusCode)
	}

	// --- persistence -----------------------------------------------------
	waitForCondition(t, 3*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(stateDir, store.HistoryFile))
		return err == nil
	})

	cancel()
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restart on the same state: the ledger comes back, and the restored
	// bans are not counted again.
	cfg2 := baseTestConfig(stateDir)
	cfg2.Web = cfg.Web
	d2, err := New(cfg2, WithRunner(&recordingRunner{}), WithStdin(strings.NewReader("")), WithControlSocket(""))
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	defer d2.Close()
	status2, err := d2.Service().Status()
	if err != nil {
		t.Fatalf("Status (restart): %v", err)
	}
	if status2.History == nil || status2.History.Events != 2 {
		t.Fatalf("history after restart = %+v, want the same 2 events", status2.History)
	}
	if len(status2.Bans) != 2 {
		t.Errorf("restored bans = %d, want 2", len(status2.Bans))
	}
	if d2.Ledger().Dirty() {
		t.Error("a restart alone must not dirty the ledger")
	}
}

// TestDaemon_BadGeoIPFailsStartup: a typo in web.geoip is a config error and
// must not be discovered three weeks later as an empty chart.
func TestDaemon_BadGeoIPFailsStartup(t *testing.T) {
	cfg := baseTestConfig(t.TempDir())
	cfg.Web = config.Web{GeoIP: filepath.Join(t.TempDir(), "missing.mmdb"), Retention: time.Hour}
	_, err := New(cfg, WithRunner(&recordingRunner{}), WithStdin(strings.NewReader("")), WithControlSocket(""))
	if err == nil || !strings.Contains(err.Error(), "web.geoip") {
		t.Fatalf("New with a missing database = %v, want a web.geoip error", err)
	}
}

// TestDaemon_ReloadSwapsGeoIP covers the one reload path with state to
// manage: the database handle is replaced, a bad new path keeps the old one,
// and removing the key turns geography off.
func TestDaemon_ReloadSwapsGeoIP(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	cfg.Web = config.Web{GeoIP: writeTestGeoCSV(t), Retention: 24 * time.Hour}
	d, err := New(cfg, WithRunner(&recordingRunner{}), WithStdin(strings.NewReader("")), WithControlSocket(""))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()
	if err := d.Service().Ban(netip.MustParseAddr("192.0.2.10"), "sshd", time.Hour); err != nil {
		t.Fatal(err)
	}
	country := func() string {
		st, err := d.Service().Status()
		if err != nil {
			t.Fatal(err)
		}
		return st.History.IPCountries["192.0.2.10"]
	}
	if got := country(); got != "DE" {
		t.Fatalf("before reload: %q", got)
	}

	// Different database, different answer.
	other := filepath.Join(t.TempDir(), "other.csv")
	if err := os.WriteFile(other, []byte("192.0.2.0,192.0.2.255,FR\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg2 := baseTestConfig(stateDir)
	cfg2.Web = config.Web{GeoIP: other, Retention: time.Hour}
	if err := d.Reload(cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := country(); got != "FR" {
		t.Errorf("after reload: %q, want FR", got)
	}
	if d.Ledger().Retention() != time.Hour {
		t.Errorf("retention after reload = %v", d.Ledger().Retention())
	}

	// A bad path is reported, and the previous database stays.
	cfg3 := baseTestConfig(stateDir)
	cfg3.Web = config.Web{GeoIP: filepath.Join(t.TempDir(), "nope.csv"), Retention: time.Hour}
	if err := d.Reload(cfg3); err != nil {
		t.Fatalf("Reload with a bad database must not fail the reload: %v", err)
	}
	if got := country(); got != "FR" {
		t.Errorf("after bad reload: %q, want FR kept", got)
	}

	// The same path, refreshed in place (what geoipupdate does), is picked
	// up by a reload without the path changing.
	if err := os.WriteFile(other, []byte("192.0.2.0,192.0.2.255,IT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.Reload(cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := country(); got != "IT" {
		t.Errorf("after in-place refresh: %q, want IT", got)
	}

	// Dropping the key turns geography off.
	cfg4 := baseTestConfig(stateDir)
	cfg4.Web = config.Web{Retention: time.Hour}
	if err := d.Reload(cfg4); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	st, _ := d.Service().Status()
	if st.History.GeoEnabled || st.History.IPCountries != nil {
		t.Errorf("geography still on after the key was removed: %+v", st.History)
	}
}

// TestDaemon_LastMinuteBanReachesHistory: a ban issued after the last
// periodic save — the history interval here is long enough that none runs —
// must still be in history.json after shutdown. ARCHITECTURE promises that
// nothing is lost in the shutdown order.
func TestDaemon_LastMinuteBanReachesHistory(t *testing.T) {
	stateDir := t.TempDir()
	cfg := baseTestConfig(stateDir)
	d, err := New(cfg, WithRunner(&recordingRunner{}), WithStdin(strings.NewReader("")), WithControlSocket(""), WithHistoryInterval(time.Hour))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- d.Run(ctx) }()
	<-d.ControlReady()

	if err := d.Service().Ban(netip.MustParseAddr("192.0.2.77"), "manual", time.Hour); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-runErrCh; err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = d.Close()

	s, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events, err := s.LoadHistory()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].IP != netip.MustParseAddr("192.0.2.77") {
		t.Fatalf("history.json after shutdown = %+v, want the last-minute ban", events)
	}
}
