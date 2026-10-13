package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/model"
	"banhammer/internal/stats"
)

var epoch = time.Date(2024, 3, 15, 12, 30, 0, 0, time.UTC)

type fakeSource struct {
	mu    sync.Mutex
	resp  control.StatusResponse
	err   error
	calls atomic.Int64
}

func (f *fakeSource) Status() (control.StatusResponse, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resp, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// sampleStatus is a response with every section populated, including
// strings an attacker could influence (a monitor name, a rule pattern).
func sampleStatus(t *testing.T) control.StatusResponse {
	t.Helper()
	ip := netip.MustParseAddr("203.0.113.9")
	ip6 := netip.MustParseAddr("2001:db8::1")
	events := []model.BanEvent{
		{IP: ip, Monitor: "sshd", At: epoch.Add(-10 * time.Minute)},
		{IP: ip, Monitor: "sshd", At: epoch.Add(-3 * time.Hour)},
		{IP: ip6, Monitor: "<script>alert(1)</script>", At: epoch.Add(-2 * 24 * time.Hour)},
	}
	active := []model.Ban{
		{IP: ip, Monitor: "sshd", At: epoch.Add(-10 * time.Minute), Until: epoch.Add(50 * time.Minute), Count: 5, Offense: 2, Matched: `Failed password .* from <IP>`},
		{IP: ip6, Monitor: "<script>alert(1)</script>", At: epoch.Add(-time.Hour), Until: epoch.Add(23 * time.Hour), Count: 3, Offense: 1},
	}
	geo := geoMap{ip.String(): "DE"}
	summary := stats.Summarize(events, active, epoch, stats.SummaryOptions{
		Location: time.UTC, Retention: 30 * 24 * time.Hour, Geo: geo,
		CountryName: func(c string) string { return map[string]string{"DE": "Germany"}[c] },
	})
	return control.StatusResponse{
		Uptime: 3*24*time.Hour + 4*time.Hour + 5*time.Minute,
		Monitors: []control.MonitorStatus{
			{Name: "sshd", Type: "file", Target: "/var/log/auth.log", TrackedIPs: 7},
			{Name: "<script>alert(1)</script>", Type: "listen", Target: `udp://0.0.0.0:5140" onload="x`, TrackedIPs: 0},
		},
		Bans:    active,
		Stats:   control.Stats{LinesRead: 1234567, Matches: 89, BansTotal: 3, UnbansTotal: 1, ActionErrors: 2, DecodeErrors: 1, TrackedIPs: 7, ActiveBans: 2, LinesDropped: 4},
		History: &summary,
	}
}

type geoMap map[string]string

func (g geoMap) Country(ip netip.Addr) (string, bool) {
	c, ok := g[ip.String()]
	return c, ok
}

func newTestServer(t *testing.T, src StatusSource, opts ...Option) *Server {
	t.Helper()
	base := []Option{WithNow(func() time.Time { return epoch }), WithLocation(time.UTC)}
	return NewServer("127.0.0.1:0", src, discardLogger(), append(base, opts...)...)
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestIndexRendersEverySection(t *testing.T) {
	t.Parallel()
	src := &fakeSource{resp: sampleStatus(t)}
	rec := get(t, newTestServer(t, src).Handler(), http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<!doctype html>",
		`<meta http-equiv="refresh" content="30">`,
		"up 3d 4h",
		"generated 2024-03-15 12:30:00 UTC",
		">2<", "active bans", // card
		"bans · last 24h", "bans · last 7d", "bans · last 30d",
		"1\u202f234\u202f567", // grouped lines read
		"Bans per hour · last 24h",
		"Bans per day · last 30d",
		"By hour of day",
		"By day of week",
		"Countries · active bans",
		"🇩🇪", "Germany",
		"Repeat offenders",
		"203.0.113.9",
		"2001:db8::1",
		"/var/log/auth.log",
		"in 50m",                             // expiry of the first ban
		"Failed password .* from &lt;IP&gt;", // rule, escaped
		"2 firewall action(s) failed",
		"4 log line(s) were dropped",
		"read-only",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// TestIndexEscapesAttackerStrings is the one test that must never be
// deleted: monitor names and rule patterns are operator data today, but the
// page must not be the component that turns a sloppy config into XSS.
func TestIndexEscapesAttackerStrings(t *testing.T) {
	t.Parallel()
	src := &fakeSource{resp: sampleStatus(t)}
	body := get(t, newTestServer(t, src).Handler(), http.MethodGet, "/").Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatal("unescaped <script> reached the page")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the hostile monitor name should be present, escaped")
	}
	if strings.Contains(body, `" onload="`) {
		t.Fatal("unescaped attribute breakout reached the page")
	}
	// The template must not contain a single <script> of its own either.
	if strings.Contains(strings.ToLower(pageSource), "<script") {
		t.Fatal("the page template contains a script tag; the CSP forbids scripts and the design forbids them harder")
	}
}

func TestSecurityHeadersOnEveryRoute(t *testing.T) {
	t.Parallel()
	h := newTestServer(t, &fakeSource{resp: sampleStatus(t)}).Handler()
	for _, path := range []string{"/", "/status.json", "/healthz", "/nope"} {
		rec := get(t, h, http.MethodGet, path)
		hdr := rec.Header()
		if csp := hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("X-Content-Type-Options") != "nosniff" ||
			hdr.Get("Referrer-Policy") != "no-referrer" || hdr.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: headers = %v", path, hdr)
		}
	}
}

func TestOnlyGetAndHead(t *testing.T) {
	t.Parallel()
	h := newTestServer(t, &fakeSource{resp: sampleStatus(t)}).Handler()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "PROPFIND"} {
		for _, path := range []string{"/", "/status.json", "/healthz", "/unban"} {
			rec := get(t, h, method, path)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", method, path, rec.Code)
			}
			if rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s: Allow = %q", method, path, rec.Header().Get("Allow"))
			}
		}
	}
	head := get(t, h, http.MethodHead, "/")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("HEAD / = %d with %d bytes of body", head.Code, head.Body.Len())
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	t.Parallel()
	h := newTestServer(t, &fakeSource{resp: sampleStatus(t)}).Handler()
	for _, path := range []string{"/index.html", "/api", "/status", "/..%2f", "/favicon.ico"} {
		if rec := get(t, h, http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}

func TestStatusJSONMatchesControlFormat(t *testing.T) {
	t.Parallel()
	resp := sampleStatus(t)
	rec := get(t, newTestServer(t, &fakeSource{resp: resp}).Handler(), http.MethodGet, "/status.json")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status.json = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var got control.StatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body)
	}
	if got.Uptime != resp.Uptime || len(got.Bans) != 2 || got.History == nil || got.History.Events != 3 {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	rec := get(t, newTestServer(t, &fakeSource{}).Handler(), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body)
	}
}

func TestSourceErrorIs503(t *testing.T) {
	t.Parallel()
	src := &fakeSource{err: errors.New("boom")}
	h := newTestServer(t, src).Handler()
	for _, path := range []string{"/", "/status.json"} {
		rec := get(t, h, http.MethodGet, path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s = %d, want 503", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "boom") {
			t.Errorf("%s leaked the internal error to the client: %s", path, rec.Body)
		}
	}
	// healthz says the server is up even when status is not; liveness is
	// about the process, not the ban table.
	if rec := get(t, h, http.MethodGet, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}
}

func TestRenderIsCached(t *testing.T) {
	t.Parallel()
	var now atomic.Pointer[time.Time]
	start := epoch
	now.Store(&start)
	src := &fakeSource{resp: sampleStatus(t)}
	s := newTestServer(t, src, WithNow(func() time.Time { return *now.Load() }), WithCacheTTL(time.Second))
	h := s.Handler()

	for range 20 {
		get(t, h, http.MethodGet, "/")
		get(t, h, http.MethodGet, "/status.json")
	}
	if got := src.calls.Load(); got != 1 {
		t.Fatalf("Status called %d times within the TTL, want 1", got)
	}
	later := epoch.Add(2 * time.Second)
	now.Store(&later)
	get(t, h, http.MethodGet, "/")
	if got := src.calls.Load(); got != 2 {
		t.Fatalf("Status called %d times after the TTL, want 2", got)
	}

	// An error is cached too: a broken source must not be hammered.
	src.mu.Lock()
	src.err = errors.New("down")
	src.mu.Unlock()
	after := later.Add(2 * time.Second)
	now.Store(&after)
	for range 5 {
		get(t, h, http.MethodGet, "/")
	}
	if got := src.calls.Load(); got != 3 {
		t.Fatalf("Status called %d times while failing, want 3", got)
	}
}

func TestCacheCanBeDisabled(t *testing.T) {
	t.Parallel()
	src := &fakeSource{resp: sampleStatus(t)}
	h := newTestServer(t, src, WithCacheTTL(0)).Handler()
	for range 3 {
		get(t, h, http.MethodGet, "/")
	}
	if got := src.calls.Load(); got != 3 {
		t.Fatalf("Status called %d times with no cache, want 3", got)
	}
}

func TestPageWithoutHistoryOrBans(t *testing.T) {
	t.Parallel()
	resp := control.StatusResponse{
		Uptime:   5 * time.Second,
		Monitors: []control.MonitorStatus{{Name: "m", Type: "stdin", Target: "stdin"}},
	}
	rec := get(t, newTestServer(t, &fakeSource{resp: resp}, WithRefresh(0)).Handler(), http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "http-equiv") {
		t.Error("refresh 0 must drop the meta refresh")
	}
	if strings.Contains(body, "Bans per hour") || strings.Contains(body, "Repeat offenders") {
		t.Error("history sections rendered without history")
	}
	if !strings.Contains(body, "Nobody is banned right now.") {
		t.Error("empty ban table placeholder missing")
	}
}

func TestGeographyOffMessage(t *testing.T) {
	t.Parallel()
	resp := sampleStatus(t)
	resp.History.GeoEnabled = false
	resp.History.Countries, resp.History.ActiveCountries, resp.History.IPCountries = nil, nil, nil
	body := get(t, newTestServer(t, &fakeSource{resp: resp}).Handler(), http.MethodGet, "/").Body.String()
	if !strings.Contains(body, "No country database configured") {
		t.Error("the page should tell the operator how to turn geography on")
	}
	if strings.Contains(body, "<th>Country</th>") {
		t.Error("country columns must disappear when geography is off")
	}
}

func TestRunServesAndShutsDown(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, &fakeSource{resp: sampleStatus(t)}, WithListener(ln))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	<-s.Ready()

	if s.Addr() != ln.Addr().String() {
		t.Errorf("Addr = %q, want %q", s.Addr(), ln.Addr())
	}
	resp, err := http.Get("http://" + s.Addr() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "banhammer") {
		t.Errorf("GET / = %d", resp.StatusCode)
	}
	if err := s.Run(context.Background()); !errors.Is(err, ErrServerRunning) {
		t.Errorf("second Run = %v, want ErrServerRunning", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close after Run: %v", err)
	}
	if err := s.Run(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Run after Close = %v, want ErrServerClosed", err)
	}
}

func TestRunBindFailure(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := NewServer(ln.Addr().String(), &fakeSource{}, discardLogger())
	err = s.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("Run on a taken port = %v", err)
	}
	select {
	case <-s.Ready():
	default:
		t.Error("Ready must be closed even when binding fails, or callers hang")
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m 30s"},
		{time.Hour + 2*time.Minute + 59*time.Second, "1h 2m"},
		{49*time.Hour + 30*time.Minute, "2d 1h"},
		{30 * 24 * time.Hour, "30d"},
		{4 * time.Hour, "4h"},
		{2 * time.Minute, "2m"},
		{1500 * time.Millisecond, "2s"},
	} {
		if got := humanDuration(tc.d); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFmtInt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "0"}, {999, "999"}, {1000, "1\u202f000"}, {1234567, "1\u202f234\u202f567"}, {-1234, "-1\u202f234"},
	} {
		if got := fmtInt(tc.n); got != tc.want {
			t.Errorf("fmtInt(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestFlagOf(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"DE", "🇩🇪"}, {"us", "🇺🇸"}, {"", ""}, {"USA", ""}, {"1A", ""}, {"ZZ", "🇿🇿"},
	} {
		if got := flagOf(tc.in); got != tc.want {
			t.Errorf("flagOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScale(t *testing.T) {
	t.Parallel()
	c := scale([]bar{{Value: 0, Title: "a"}, {Value: 1, Title: "b"}, {Value: 50, Title: "c"}, {Value: 100, Title: "d"}})
	if c.Max != 100 || c.Total != 151 {
		t.Errorf("Max=%d Total=%d", c.Max, c.Total)
	}
	if c.Bars[0].Pct != 0 || c.Bars[1].Pct != 2 || c.Bars[2].Pct != 50 || c.Bars[3].Pct != 100 {
		t.Errorf("Pct = %d %d %d %d", c.Bars[0].Pct, c.Bars[1].Pct, c.Bars[2].Pct, c.Bars[3].Pct)
	}
	if c.Bars[1].Title != "b: 1 ban" || c.Bars[2].Title != "c: 50 bans" {
		t.Errorf("titles = %q %q", c.Bars[1].Title, c.Bars[2].Title)
	}
}

// TestRejectedMethodsStillGetSecurityHeaders: ARCHITECTURE promises every
// response carries the headers, and a 405 is a response.
func TestRejectedMethodsStillGetSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := newTestServer(t, &fakeSource{resp: sampleStatus(t)}).Handler()
	rec := get(t, h, http.MethodPost, "/")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / = %d", rec.Code)
	}
	for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("405 response lacks %s", k)
		}
	}
}

// TestActiveBansTableIsCapped guards the page size against an ipset-sized
// ban table; the JSON twin stays complete.
func TestActiveBansTableIsCapped(t *testing.T) {
	t.Parallel()
	resp := sampleStatus(t)
	resp.Bans = nil
	for i := range maxBanRows + 37 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		resp.Bans = append(resp.Bans, model.Ban{IP: ip, Monitor: "sshd", At: epoch, Until: epoch.Add(time.Hour), Offense: 1})
	}
	h := newTestServer(t, &fakeSource{resp: resp}).Handler()
	body := get(t, h, http.MethodGet, "/").Body.String()
	_, bansSection, _ := strings.Cut(body, "<h2>Active bans")
	if got := strings.Count(bansSection, `<td class="ip">`); got != maxBanRows {
		t.Errorf("page has %d ban rows, want %d", got, maxBanRows)
	}
	if !strings.Contains(body, "and 37 more") {
		t.Error("page does not say how many bans were omitted")
	}
	var full control.StatusResponse
	if err := json.Unmarshal(get(t, h, http.MethodGet, "/status.json").Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Bans) != maxBanRows+37 {
		t.Errorf("status.json has %d bans, want all %d", len(full.Bans), maxBanRows+37)
	}
}

// TestRenderErrorIsLoggedOncePerRender: repeated errors are rate-limited
// (house rule), so a request flood against a broken source must not become a
// log flood.
func TestRenderErrorIsLoggedOncePerRender(t *testing.T) {
	t.Parallel()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	src := &fakeSource{err: errors.New("boom")}
	s := NewServer("127.0.0.1:0", src, logger, WithNow(func() time.Time { return epoch }), WithCacheTTL(time.Second))
	h := s.Handler()
	for range 50 {
		get(t, h, http.MethodGet, "/")
		get(t, h, http.MethodGet, "/status.json")
	}
	if got := strings.Count(logBuf.String(), "render failed"); got != 1 {
		t.Errorf("100 failing requests produced %d log lines, want 1:\n%s", got, logBuf.String())
	}
}

// TestNoTrustedHTMLInSource pins the design rule that nothing in this package
// bypasses html/template's escaping: no template.HTML, template.JS,
// template.CSS or template.URL anywhere, and no <script> in the template.
func TestNoTrustedHTMLInSource(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"server.go", "view.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"template.HTML", "template.JS", "template.CSS", "template.URL", "template.HTMLAttr", "template.Srcset"} {
			if bytes.Contains(src, []byte(bad)) {
				t.Errorf("%s uses %s, which bypasses escaping", name, bad)
			}
		}
	}
	lower := strings.ToLower(pageSource)
	if strings.Contains(lower, "<script") || strings.Contains(lower, "javascript:") || regexpOnHandler.MatchString(pageSource) {
		t.Error("page.html contains script, a javascript: URL or an event handler attribute")
	}
}

// regexpOnHandler spots onclick= and friends in the template source.
var regexpOnHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
