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

// TestDaemon_BanCarriesOffendingLine: the line that crossed the threshold
// reaches the ledger and the status response; a manual ban has no line;
// with web.log_lines off nothing is captured at all. The ban record itself
// never carries log text in either case.
func TestDaemon_BanCarriesOffendingLine(t *testing.T) {
	for _, capture := range []bool{true, false} {
		t.Run(map[bool]string{true: "on", false: "off"}[capture], func(t *testing.T) {
			stateDir := t.TempDir()
			cfg := baseTestConfig(stateDir)
			cfg.Web = config.Web{Retention: 24 * time.Hour, LogLines: capture}
			runner := &recordingRunner{}
			// Every line carries an escape sequence to prove sanitisation
			// happens on this path. Which of the three is kept is not
			// defined: workers run in parallel, so the hit that crosses
			// the threshold at the aggregator may be any of them.
			input := "Failed password for invalid user admin from 192.0.2.10 port 1\x1b[2J\n" +
				"Failed password for invalid user admin from 192.0.2.10 port 2\x1b[2J\n" +
				"Failed password for root from 192.0.2.10 port 3 ssh2\x1b[2J\n"
			d, err := New(cfg, WithRunner(runner), WithStdin(strings.NewReader(input)), WithControlSocket(""))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer d.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = d.Run(ctx) }()
			waitForCondition(t, 3*time.Second, func() bool { return runner.HasArg("192.0.2.10") })
			if err := d.Service().Ban(netip.MustParseAddr("192.0.2.99"), "manual", time.Hour); err != nil {
				t.Fatal(err)
			}

			st, err := d.Service().Status()
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range st.Bans {
				if strings.Contains(b.Matched, "Failed password for root") {
					t.Fatalf("log text leaked into model.Ban.Matched: %q", b.Matched)
				}
			}
			sample, ok := st.History.Samples["192.0.2.10"]
			if capture {
				if !ok {
					t.Fatalf("no sample for the banned address: %+v", st.History.Samples)
				}
				if !strings.HasPrefix(sample.Line, "Failed password for ") || !strings.HasSuffix(sample.Line, "\uFFFD[2J") || strings.ContainsRune(sample.Line, 0x1b) || sample.Monitor != "sshd" {
					t.Errorf("sample = %+v, want one of the input lines, sanitised", sample)
				}
			} else if ok || st.History.Samples != nil {
				t.Errorf("log_lines off, yet samples = %+v", st.History.Samples)
			}
			if _, ok := st.History.Samples["192.0.2.99"]; ok {
				t.Error("a manual ban must not have a log line")
			}
		})
	}
}

// TestLineArena pins the aliasing contract: a copy is unaffected by later
// copies, cannot be appended into the chunk, and lines start on 8-byte
// boundaries.
func TestLineArena(t *testing.T) {
	t.Parallel()
	var a lineArena
	first := a.copyLine([]byte("first line"))
	second := a.copyLine([]byte("second"))
	if string(first) != "first line" || string(second) != "second" {
		t.Fatalf("copies = %q %q", first, second)
	}
	if cap(first) != len(first) {
		t.Errorf("copy has spare capacity %d; a receiver could append into the chunk", cap(first)-len(first))
	}
	// "first line" is 10 bytes; the next copy must start at offset 16 so
	// that the worker's later appends never touch a word the aggregator
	// may be reading.
	if &a.chunk[:cap(a.chunk)][16] != &second[0] {
		t.Error("second copy is not 8-byte aligned after the first")
	}
	// Fill a chunk: copies stay valid across the roll-over.
	long := bytes.Repeat([]byte("x"), arenaMaxLine*2)
	var keep [][]byte
	for range arenaChunkSize/arenaMaxLine + 5 {
		keep = append(keep, a.copyLine(long))
	}
	for i, k := range keep {
		if len(k) != arenaMaxLine || k[0] != 'x' || k[len(k)-1] != 'x' {
			t.Fatalf("copy %d corrupted or not truncated: len %d", i, len(k))
		}
	}
	if string(first) != "first line" {
		t.Error("first copy was overwritten by a chunk roll-over")
	}
}

// TestDaemon_GeoIPRefreshedWhenFileChanges: a geoipupdate sidecar (or a
// cron) replaces the database file; the daemon must notice on its own, no
// `banhammer reload` required, and must keep the old database while a new
// file is unreadable.
func TestDaemon_GeoIPRefreshedWhenFileChanges(t *testing.T) {
	stateDir := t.TempDir()
	path := writeTestGeoCSV(t)
	cfg := baseTestConfig(stateDir)
	cfg.Web = config.Web{GeoIP: path, Retention: 24 * time.Hour}
	d, err := New(cfg, WithRunner(&recordingRunner{}), WithStdin(strings.NewReader("")), WithControlSocket(""), WithHistoryInterval(20*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()
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
		t.Fatalf("before: %q", got)
	}

	// Replace the file the way geoipupdate does: write aside, rename over.
	// The mtime is pushed forward explicitly so the test does not depend on
	// filesystem timestamp granularity.
	replace := func(content string, mod time.Time) {
		t.Helper()
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(tmp, mod, mod); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(time.Hour)
	replace("192.0.2.0,192.0.2.255,FR\n", base)
	waitForCondition(t, 3*time.Second, func() bool { return country() == "FR" })

	// A broken replacement is ignored; the previous database stays.
	replace("not,a,database\n", base.Add(time.Minute))
	time.Sleep(100 * time.Millisecond) // several refresh ticks; nothing should change
	if got := country(); got != "FR" {
		t.Errorf("after a broken rewrite: %q, want FR kept", got)
	}

	// And a good one after that is picked up again.
	replace("192.0.2.0,192.0.2.255,IT\n", base.Add(2*time.Minute))
	waitForCondition(t, 3*time.Second, func() bool { return country() == "IT" })
}
