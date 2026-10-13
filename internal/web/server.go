// Package web serves Banhammer's read-only status page.
//
// # What it is
//
// One HTML page, rendered on the server from the same StatusResponse that
// `banhammer status` prints, plus the same data as JSON at /status.json and a
// liveness probe at /healthz. It exists because a chart of the last month is
// worth more than a scrolling log, and because the control socket is root's.
//
// # What it deliberately is not
//
// There are no forms, no actions and no JavaScript. The page cannot ban,
// unban or reload; it has no session, no cookie and no state. Only GET and
// HEAD are answered. Every dynamic value passes through html/template, and
// the response carries a Content-Security-Policy that forbids scripts, frames
// and external resources outright. The listener binds to loopback unless the
// operator says otherwise. The threat model is "an attacker who can reach the
// port learns which addresses are banned and which log files are watched" —
// which is why loopback is the default — and nothing worse.
//
// # Cost
//
// Rendering calls Status (a lock on the ban table, a pass over the ledger)
// and executes a template. A client that refreshes in a tight loop, or many
// clients, would turn that into measurable load on the aggregator's lock, so
// the rendered output is cached for a second and served from memory.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"banhammer/internal/control"
)

var (
	// ErrServerRunning indicates an attempt to start a Server that is already active.
	ErrServerRunning = errors.New("web: server already running")
	// ErrServerClosed indicates an operation was attempted on a closed Server.
	ErrServerClosed = errors.New("web: server closed")
)

// StatusSource is the one thing the page needs from the daemon. It is
// satisfied by control.Service, and by anything a test cares to write.
type StatusSource interface {
	Status() (control.StatusResponse, error)
}

// Defaults for the knobs below.
const (
	defaultCacheTTL        = time.Second
	defaultRefresh         = 30 * time.Second
	defaultShutdownTimeout = 5 * time.Second
)

// Server is the HTTP server behind the status page. Build it with NewServer
// and drive it with Run.
type Server struct {
	addr   string
	source StatusSource
	log    *slog.Logger

	listener        net.Listener
	actualAddr      string
	ready           chan struct{}
	readyOnce       sync.Once
	shutdownTimeout time.Duration

	now         func() time.Time
	location    *time.Location
	refresh     time.Duration
	cacheTTL    time.Duration
	countryName func(string) string

	mu         sync.Mutex
	running    bool
	closed     bool
	httpServer *http.Server

	// cacheMu serialises rendering as well as guarding the cache, so a burst
	// of requests costs one Status call, not one each.
	cacheMu   sync.Mutex
	cacheAt   time.Time
	cacheHTML []byte
	cacheJSON []byte
	cacheErr  error
}

// Option configures a Server.
type Option func(*Server)

// WithListener injects a pre-bound listener, so tests can use 127.0.0.1:0
// without a bind race.
func WithListener(ln net.Listener) Option {
	return func(s *Server) { s.listener = ln }
}

// WithShutdownTimeout bounds how long Run waits for in-flight requests.
func WithShutdownTimeout(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.shutdownTimeout = d
		}
	}
}

// WithNow injects the clock used for "generated at" and cache expiry.
func WithNow(now func() time.Time) Option {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// WithLocation sets the zone timestamps are displayed in. Default time.Local,
// which is also what the ledger buckets by, so charts and tables agree.
func WithLocation(loc *time.Location) Option {
	return func(s *Server) {
		if loc != nil {
			s.location = loc
		}
	}
}

// WithRefresh sets the page's meta-refresh interval. Zero disables it.
func WithRefresh(d time.Duration) Option {
	return func(s *Server) {
		if d >= 0 {
			s.refresh = d
		}
	}
}

// WithCacheTTL sets how long a rendered page is reused. Zero disables the
// cache, which only a test should want.
func WithCacheTTL(d time.Duration) Option {
	return func(s *Server) {
		if d >= 0 {
			s.cacheTTL = d
		}
	}
}

// WithCountryName supplies the code→name function used to label addresses.
// The daemon passes geoip.Name; without one the page shows bare codes.
func WithCountryName(f func(code string) string) Option {
	return func(s *Server) {
		if f != nil {
			s.countryName = f
		}
	}
}

// NewServer builds a status server bound to addr.
func NewServer(addr string, source StatusSource, log *slog.Logger, opts ...Option) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		addr:            addr,
		source:          source,
		log:             log,
		ready:           make(chan struct{}),
		shutdownTimeout: defaultShutdownTimeout,
		now:             time.Now,
		location:        time.Local,
		refresh:         defaultRefresh,
		cacheTTL:        defaultCacheTTL,
		countryName:     func(string) string { return "" },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Ready is closed once the listener is bound (or has failed to bind), so
// callers can synchronise without sleeping.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Addr is the bound address, useful when listening on port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actualAddr
}

// Close stops the server immediately. Safe to call twice.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Close()
	} else if s.listener != nil {
		err = s.listener.Close()
	}
	return err
}

// Handler returns the page's http.Handler, for embedding in another mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/status.json", s.handleJSON)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return secure(mux)
}

// Run serves until ctx is cancelled, then drains in-flight requests for up
// to the shutdown timeout. It returns nil on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	if s.running {
		s.mu.Unlock()
		return ErrServerRunning
	}
	s.running = true

	ln := s.listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.running = false
			s.readyOnce.Do(func() { close(s.ready) })
			s.mu.Unlock()
			return fmt.Errorf("web: listen on %s: %w", s.addr, err)
		}
	}
	s.actualAddr = ln.Addr().String()
	s.readyOnce.Do(func() { close(s.ready) })

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Nothing legitimate sends this page a large request.
		MaxHeaderBytes: 8 << 10,
	}
	s.httpServer = srv
	s.mu.Unlock()

	s.log.Info("status page listening", "addr", s.actualAddr)

	shutdownDone := make(chan struct{})
	shutdownErrCh := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				_ = srv.Close()
				shutdownErrCh <- err
				return
			}
			shutdownErrCh <- nil
		case <-shutdownDone:
			shutdownErrCh <- nil
		}
	}()

	serveErr := srv.Serve(ln)
	close(shutdownDone)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("web: serve: %w", serveErr)
	}
	if err := <-shutdownErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("web: shutdown: %w", err)
	}
	return nil
}

// secure wraps a handler with the method gate and the response headers every
// route shares. It lives in one place so that a new route cannot forget them.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Headers first, so that the 405 below carries them too. No
		// scripts, no frames, no fonts, no fetches, no external anything.
		// Inline <style> and style attributes are the only thing allowed,
		// and they carry no attacker-controlled bytes (see view.go).
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed: this page is read-only", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html, _, err := s.rendered()
	if err != nil {
		http.Error(w, "status unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(html)
}

func (s *Server) handleJSON(w http.ResponseWriter, r *http.Request) {
	_, data, err := s.rendered()
	if err != nil {
		http.Error(w, "status unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}

// rendered returns the page and its JSON twin, re-rendering only when the
// cached copy is older than the TTL. Holding cacheMu across the render is
// the point: concurrent requests wait for one render rather than each doing
// their own.
func (s *Server) rendered() (html, js []byte, err error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	now := s.now()
	if s.cacheTTL > 0 && !s.cacheAt.IsZero() && now.Sub(s.cacheAt) < s.cacheTTL {
		return s.cacheHTML, s.cacheJSON, s.cacheErr
	}
	s.cacheAt = now
	s.cacheHTML, s.cacheJSON, s.cacheErr = s.render(now)
	if s.cacheErr != nil {
		// Logged here, once per render, rather than in the handlers once
		// per request: with a broken source and a client hammering the
		// page, the cache turns a request flood into one line a second.
		s.log.Error("status page render failed", "err", s.cacheErr)
	}
	return s.cacheHTML, s.cacheJSON, s.cacheErr
}

func (s *Server) render(now time.Time) ([]byte, []byte, error) {
	resp, err := s.source.Status()
	if err != nil {
		return nil, nil, fmt.Errorf("status: %w", err)
	}
	js, err := json.Marshal(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("encode status: %w", err)
	}
	v := buildView(resp, now, s.location, s.refresh, s.countryName)
	var buf bytes.Buffer
	if err := page.Execute(&buf, v); err != nil {
		return nil, nil, fmt.Errorf("render template: %w", err)
	}
	return buf.Bytes(), js, nil
}
