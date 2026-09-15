package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	// ErrServerRunning indicates an attempt to start a Server that is already active.
	ErrServerRunning = errors.New("metrics: server already running")

	// ErrServerClosed indicates an operation was attempted on a closed Server.
	ErrServerClosed = errors.New("metrics: server closed")
)

// Server hosts the HTTP Prometheus scraping endpoint (/metrics) and health probe (/healthz).
//
// It encapsulates listener lifecycle and graceful shutdown semantics so the banhammer
// daemon can cleanly unbind network interfaces during termination without dropping
// in-flight metrics scrapes.
type Server struct {
	addr            string
	reg             *Registry
	log             *slog.Logger
	listener        net.Listener
	actualAddr      string
	ready           chan struct{}
	readyOnce       sync.Once
	shutdownTimeout time.Duration

	mu         sync.Mutex
	running    bool
	closed     bool
	httpServer *http.Server
}

// ServerOption configures Server parameters during creation.
type ServerOption func(*Server)

// WithListener configures a pre-existing net.Listener for the Server.
//
// This allows tests or caller harnesses to inject custom loopback listeners (such as
// from net.Listen("tcp", "127.0.0.1:0")) avoiding address binding races.
func WithListener(ln net.Listener) ServerOption {
	return func(s *Server) {
		s.listener = ln
	}
}

// WithShutdownTimeout configures the maximum duration allowed for in-flight requests
// to complete during graceful server shutdown.
func WithShutdownTimeout(d time.Duration) ServerOption {
	return func(s *Server) {
		if d > 0 {
			s.shutdownTimeout = d
		}
	}
}

// NewServer constructs an HTTP metrics server bound to the specified TCP address.
//
// If reg is nil, a new Registry is created; if log is nil, slog.Default() is used.
func NewServer(addr string, reg *Registry, log *slog.Logger, opts ...ServerOption) *Server {
	if reg == nil {
		reg = NewRegistry()
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		addr:            addr,
		reg:             reg,
		log:             log,
		ready:           make(chan struct{}),
		shutdownTimeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Ready returns a channel that is closed as soon as the server listener is bound
// and accepting TCP connections.
//
// Callers and tests synchronize on Ready to prevent race conditions during startup
// without relying on non-deterministic time.Sleep calls.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Addr returns the bound network address of the running server.
//
// When listening on an ephemeral port (e.g. ":0"), Addr allows callers to discover
// the dynamically assigned operating system port.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actualAddr
}

// Close immediately closes the active listener and HTTP server.
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

// Run starts the HTTP listener and serves incoming metrics requests until the
// provided context is cancelled.
//
// Upon cancellation, Run gracefully drains active connections with a 5-second
// timeout, returning nil if the shutdown completed cleanly.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrServerRunning
	}
	s.running = true

	var ln net.Listener
	var err error
	if s.listener != nil {
		ln = s.listener
	} else {
		ln, err = net.Listen("tcp", s.addr)
		if err != nil {
			s.running = false
			s.readyOnce.Do(func() { close(s.ready) })
			s.mu.Unlock()
			return fmt.Errorf("metrics: listen on %s: %w", s.addr, err)
		}
	}
	s.actualAddr = ln.Addr().String()
	s.readyOnce.Do(func() { close(s.ready) })

	mux := http.NewServeMux()
	mux.Handle("/metrics", s.reg.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("banhammer metrics server\n"))
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.httpServer = srv
	s.mu.Unlock()

	s.log.Info("metrics server listening", "addr", s.actualAddr)

	shutdownDone := make(chan struct{})
	shutdownErrCh := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			s.log.Debug("shutting down metrics server", "reason", ctx.Err())
			shutdownTimeout := s.shutdownTimeout
			if shutdownTimeout <= 0 {
				shutdownTimeout = 5 * time.Second
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				s.log.Error("metrics server shutdown error", "err", err)
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
		return fmt.Errorf("metrics: serve: %w", serveErr)
	}

	if err := <-shutdownErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics: shutdown: %w", err)
	}
	return nil
}
