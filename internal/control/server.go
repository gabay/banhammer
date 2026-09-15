package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultReadTimeout  = 5 * time.Second
	defaultWriteTimeout = 5 * time.Second
	staleDialTimeout    = 100 * time.Millisecond
)

// Server listens on a Unix domain socket and serves IPC requests for
// daemon status and operational controls.
type Server struct {
	socketPath   string
	svc          Service
	log          *slog.Logger
	readTimeout  time.Duration
	writeTimeout time.Duration

	mu       sync.Mutex
	running  bool
	closed   bool
	listener net.Listener

	ready     chan struct{}
	readyOnce sync.Once

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// ServerOption configures Server parameters during creation.
type ServerOption func(*Server)

// WithTimeouts configures custom per-connection read and write deadlines.
//
// This is primarily used in tests to simulate or verify deadline timeouts without
// waiting for default multi-second timeouts.
func WithTimeouts(read, write time.Duration) ServerOption {
	return func(s *Server) {
		s.readTimeout = read
		s.writeTimeout = write
	}
}

// NewServer initializes a control Server bound to socketPath.
//
// socketPath specifies the filesystem path of the Unix domain socket.
// svc must not be nil; if log is nil, slog.Default() is used.
func NewServer(socketPath string, svc Service, log *slog.Logger, opts ...ServerOption) (*Server, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("%w: socket path cannot be empty", ErrInvalidArgument)
	}
	if svc == nil {
		return nil, fmt.Errorf("%w: service cannot be nil", ErrInvalidArgument)
	}
	if log == nil {
		log = slog.Default()
	}

	s := &Server{
		socketPath:   socketPath,
		svc:          svc,
		log:          log,
		readTimeout:  defaultReadTimeout,
		writeTimeout: defaultWriteTimeout,
		ready:        make(chan struct{}),
		conns:        make(map[net.Conn]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Ready returns a channel that is closed as soon as the Unix domain socket is
// bound and accepting connections.
//
// Callers and tests can synchronize on this channel to ensure the server is
// receptive before initiating client dials, avoiding arbitrary sleeps.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Run executes the server accept loop.
//
// Before binding, it verifies whether any existing socket file at socketPath is
// stale. If a live process responds on the socket, Run aborts with ErrSocketInUse.
// If the socket is dead, it is safely unlinked. When ctx is cancelled or Close
// is called, Run terminates the listener, severs active connections, cleans up the
// socket file, and returns nil.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.running {
		s.mu.Unlock()
		return ErrRunning
	}
	s.running = true
	s.mu.Unlock()

	defer s.readyOnce.Do(func() { close(s.ready) })

	// Check if a socket or file already exists at socketPath.
	if _, err := os.Stat(s.socketPath); err == nil {
		conn, dialErr := net.DialTimeout("unix", s.socketPath, staleDialTimeout)
		if dialErr == nil {
			_ = conn.Close()
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("%w: socket %q already in use", ErrSocketInUse, s.socketPath)
		}
		s.log.Debug("control: removing stale socket file", "path", s.socketPath)
		if rmErr := os.Remove(s.socketPath); rmErr != nil && !os.IsNotExist(rmErr) {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("control: remove stale socket: %w", rmErr)
		}
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(s.socketPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("control: create socket directory: %w", err)
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("control: listen on %q: %w", s.socketPath, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	// Signal readiness to clients/tests.
	s.readyOnce.Do(func() { close(s.ready) })

	// Restrict permissions to owner and group.
	_ = os.Chmod(s.socketPath, 0660)

	// Ensure socket is closed when context cancels or Run exits.
	stopWatcher := context.AfterFunc(ctx, func() {
		_ = s.Close()
	})
	defer stopWatcher()
	defer func() { _ = s.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control: accept connection: %w", err)
		}

		s.trackConn(conn, true)
		go func(c net.Conn) {
			defer func() {
				s.trackConn(c, false)
				_ = c.Close()
			}()
			s.handleConn(ctx, c)
		}(conn)
	}
}

// Close gracefully terminates the server, closes the listener and any open
// connections, and unlinks the socket file from disk.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	s.mu.Unlock()

	s.readyOnce.Do(func() { close(s.ready) })

	var errs []error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close listener: %w", err))
		}
	}

	s.connsMu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	s.connsMu.Unlock()

	if s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove socket file: %w", err))
		}
	}

	return errors.Join(errs...)
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) trackConn(c net.Conn, active bool) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if active {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReader(conn)
	enc := json.NewEncoder(conn)

	for {
		if s.readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			if ctx.Err() != nil || s.isClosed() {
				return
			}
			if len(line) == 0 {
				return
			}
		}

		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(trimmed, &req); err != nil {
			if s.writeTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
			}
			_ = enc.Encode(Response{
				OK:    false,
				Error: fmt.Sprintf("malformed JSON request: %v", err),
			})
			return
		}

		resp := s.dispatch(req)
		if s.writeTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		}
		if err := enc.Encode(resp); err != nil {
			s.log.Debug("control: write response failed", "err", err)
			return
		}
	}
}

func (s *Server) dispatch(req Request) Response {
	cmd := strings.ToLower(strings.TrimSpace(req.Command))
	switch cmd {
	case "status":
		status, err := s.svc.Status()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Status: &status}

	case "ban":
		if strings.TrimSpace(req.IP) == "" {
			return Response{OK: false, Error: "ip is required"}
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
		if err != nil || !ip.IsValid() {
			return Response{OK: false, Error: fmt.Sprintf("invalid ip address: %s", req.IP)}
		}
		dur, err := parseDuration(req.Duration)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		if dur < 0 {
			return Response{OK: false, Error: "duration cannot be negative"}
		}
		if err := s.svc.Ban(ip, req.Monitor, dur); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case "unban":
		if strings.TrimSpace(req.IP) == "" {
			return Response{OK: false, Error: "ip is required"}
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
		if err != nil || !ip.IsValid() {
			return Response{OK: false, Error: fmt.Sprintf("invalid ip address: %s", req.IP)}
		}
		if err := s.svc.Unban(ip); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case "unban_all", "unban-all", "unbanall":
		if err := s.svc.UnbanAll(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case "reload":
		if err := s.svc.Reload(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case "":
		return Response{OK: false, Error: "empty command"}

	default:
		return Response{OK: false, Error: fmt.Sprintf("unknown command %q", req.Command)}
	}
}

func parseDuration(raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return 0, nil
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return d, nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return time.Duration(n), nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return time.Duration(int64(f)), nil
	}
	return 0, errors.New("invalid duration: expected duration string or nanoseconds number")
}
