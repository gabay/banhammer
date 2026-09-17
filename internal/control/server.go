package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultReadTimeout  = 5 * time.Second
	defaultWriteTimeout = 5 * time.Second

	// staleDialTimeout bounds the liveness probe against an existing socket.
	// Connecting to a local socket either succeeds or fails immediately, so a
	// timeout here means something pathological — which counts as "in use",
	// never as "stale".
	staleDialTimeout = 100 * time.Millisecond

	// defaultMaxRequestBytes caps a single newline-delimited request. Control
	// requests are a handful of JSON fields; the cap exists so a client that
	// never sends a newline cannot make the daemon buffer without bound.
	// internal/source caps its log lines at the same 64 KiB.
	defaultMaxRequestBytes = 64 << 10

	// defaultMaxConns bounds concurrently served control connections, matching
	// the cap the TCP log source uses. Excess connections wait in the kernel
	// backlog, which costs us nothing and lets the peer retry.
	defaultMaxConns = 64

	// defaultSocketMode keeps the socket owner- and group-writable only:
	// anyone who can write to it can ban and unban arbitrary addresses.
	defaultSocketMode fs.FileMode = 0o660

	// socketDirMode matches defaultSocketMode: a world-traversable parent
	// directory is pointless protection for a group-only socket, and a
	// world-writable one would let anyone replace the socket outright.
	socketDirMode fs.FileMode = 0o750

	// Accept backoff bounds, modelled on net/http.Server.Serve: a transient
	// EMFILE or ENFILE must not take the control plane down for good.
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

// errRequestTooLarge marks a request that exceeded maxRequestBytes before its
// terminating newline arrived.
var errRequestTooLarge = errors.New("control: request too large")

// Server listens on a Unix domain socket and serves IPC requests for
// daemon status and operational controls.
type Server struct {
	socketPath      string
	svc             Service
	log             *slog.Logger
	readTimeout     time.Duration
	writeTimeout    time.Duration
	maxRequestBytes int
	maxConns        int
	socketMode      fs.FileMode

	mu       sync.Mutex
	running  bool
	closed   bool
	listener net.Listener
	// bound records that this server, and not some other process, created the
	// file at socketPath. Close unlinks only what it owns.
	bound bool
	// bindErr is the reason the socket never came up, surfaced by Err.
	bindErr error

	ready     chan struct{}
	readyOnce sync.Once
	// done is closed by Close so the accept loop can unblock even when the
	// caller shuts the server down without cancelling its context.
	done     chan struct{}
	doneOnce sync.Once

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

// WithMaxRequestBytes overrides the per-request size cap. Values below 1 are
// ignored so a caller cannot accidentally disable the limit.
func WithMaxRequestBytes(n int) ServerOption {
	return func(s *Server) {
		if n > 0 {
			s.maxRequestBytes = n
		}
	}
}

// WithSocketMode overrides the permission bits applied to the socket after
// bind.
//
// Deployments that reach the socket through a dedicated group (systemd's
// Group= plus RuntimeDirectoryMode=, say) may want 0o600 or 0o660 explicitly
// rather than inheriting this package's default. Ownership itself is left to
// the supervisor: chown requires privileges the daemon should not keep, and
// getting the group wrong is how a control socket becomes world-reachable.
func WithSocketMode(mode fs.FileMode) ServerOption {
	return func(s *Server) {
		s.socketMode = mode.Perm()
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
		socketPath:      socketPath,
		svc:             svc,
		log:             log,
		readTimeout:     defaultReadTimeout,
		writeTimeout:    defaultWriteTimeout,
		maxRequestBytes: defaultMaxRequestBytes,
		maxConns:        defaultMaxConns,
		socketMode:      defaultSocketMode,
		ready:           make(chan struct{}),
		done:            make(chan struct{}),
		conns:           make(map[net.Conn]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Ready returns a channel that is closed once Run has stopped trying to bind:
// either the socket is up and accepting, or the bind failed and Err says why.
//
// It is closed on failure too so that a caller waiting on it can never hang.
// Check Err after it fires; a caller that only needs "is it up yet" can ignore
// the error and will simply fail on its first dial.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Err reports the error that prevented the socket from binding, or nil while
// the server is healthy. It is meaningful once Ready has fired.
func (s *Server) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bindErr
}

// Run executes the server accept loop.
//
// Before binding it clears a socket left behind by a crash; see
// clearStaleSocket for what it refuses to touch. A live socket yields
// ErrSocketInUse and a non-socket ErrNotASocket, in both cases without
// disturbing the file. When ctx is cancelled or Close is called, Run
// terminates the listener, severs active connections, unlinks the socket it
// created, and returns nil.
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

	if err := s.clearStaleSocket(); err != nil {
		return s.bindFailed(err)
	}

	// The socket must be no more reachable than its parent directory.
	dir := filepath.Dir(s.socketPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, socketDirMode); err != nil {
			return s.bindFailed(fmt.Errorf("control: create socket directory %q: %w", dir, err))
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		return s.bindFailed(fmt.Errorf("control: listen on %q: %w", s.socketPath, err))
	}

	// net.Listen creates the socket with 0777&^umask, so under a permissive
	// umask it is briefly world-writable — and anyone who can write to it can
	// ban or unban anything. The window between bind and chmod cannot be
	// closed from here (there is no bind-with-mode); it is narrowed by running
	// with a sane umask and by keeping the parent directory at 0750, which is
	// what makes the socket unreachable to others in the first place.
	if err := os.Chmod(s.socketPath, s.socketMode); err != nil {
		_ = ln.Close()
		if rmErr := os.Remove(s.socketPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			s.log.Warn("control: cannot remove socket after failed chmod", "path", s.socketPath, "err", rmErr)
		}
		return s.bindFailed(fmt.Errorf("control: set socket permissions on %q: %w", s.socketPath, err))
	}

	s.mu.Lock()
	s.listener = ln
	s.bound = true
	s.mu.Unlock()

	// Signal readiness to clients/tests.
	s.readyOnce.Do(func() { close(s.ready) })
	s.log.Info("control socket listening", "path", s.socketPath, "mode", s.socketMode.String())

	// Ensure socket is closed when context cancels or Run exits.
	stopWatcher := context.AfterFunc(ctx, func() {
		_ = s.Close()
	})
	defer stopWatcher()

	var wg sync.WaitGroup
	defer wg.Wait()
	defer func() { _ = s.Close() }()

	sem := make(chan struct{}, s.maxConns)
	var backoff time.Duration
	for {
		// Take a slot before accepting: a connection we would immediately have
		// to drop is better left in the kernel backlog.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		}

		conn, err := ln.Accept()
		if err != nil {
			<-sem
			if s.isClosed() || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			// A transient accept failure (EMFILE, ENFILE, ECONNABORTED) must
			// not kill the control plane: back off and keep serving.
			if backoff == 0 {
				backoff = minAcceptBackoff
			} else {
				backoff = min(2*backoff, maxAcceptBackoff)
			}
			s.log.Warn("control: accept failed, retrying", "err", err, "retry_in", backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-s.done:
				timer.Stop()
				return nil
			}
			continue
		}
		backoff = 0

		s.trackConn(conn, true)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				s.trackConn(c, false)
				_ = c.Close()
			}()
			s.handleConn(ctx, c)
		}(conn)
	}
}

// bindFailed records why the socket never came up and hands the error back to
// Run's caller. Ready is closed by Run's deferred close either way, so nobody
// waiting on it hangs; Err is how they learn it failed.
func (s *Server) bindFailed(err error) error {
	s.mu.Lock()
	s.running = false
	s.bindErr = err
	s.mu.Unlock()
	return err
}

// clearStaleSocket removes a socket left behind by a crash.
//
// Two rules keep this from being destructive. First, anything that is not a
// socket is left alone: `banhammer run --socket /etc/banhammer/config.yaml`
// must fail loudly, not silently delete the config, so only fs.ModeSocket
// qualifies — this mirrors source.listener.clearStaleSocket.
//
// Second, staleness is decided only by ECONNREFUSED, which for an AF_UNIX
// socket means the inode is there but nothing is bound to it. The old code
// treated *any* dial failure as stale, so a live daemon with a full accept
// backlog or one stopped by SIGSTOP would have its socket deleted and replaced
// — two daemons, one reachable. Anything other than a clean refusal is
// therefore read as "somebody is using this" and aborts the run. The listener
// in internal/source can skip the probe entirely because the store lockfile
// already makes it single-instance; the control socket cannot, since a second
// daemon with its own state_dir takes a different lock and would otherwise
// walk straight over this one.
func (s *Server) clearStaleSocket() error {
	fi, err := os.Lstat(s.socketPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("control: stat %q: %w", s.socketPath, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("%w: %q", ErrNotASocket, s.socketPath)
	}

	conn, dialErr := net.DialTimeout("unix", s.socketPath, staleDialTimeout)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("%w: socket %q already in use", ErrSocketInUse, s.socketPath)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: socket %q did not refuse a connection: %v", ErrSocketInUse, s.socketPath, dialErr)
	}

	if err := os.Remove(s.socketPath); err != nil {
		return fmt.Errorf("control: remove stale socket %q: %w", s.socketPath, err)
	}
	s.log.Info("control: removed stale socket", "path", s.socketPath)
	return nil
}

// Close gracefully terminates the server, closes the listener and any open
// connections, and unlinks the socket file it created.
//
// The socket is unlinked only when this server bound it. A Run that aborted
// (bad path, address in use, failed chmod) leaves a file that belongs to
// somebody else — very likely the live daemon this one lost the race to — and
// deleting it would leave that daemon running but unreachable forever.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	owned := s.bound
	s.mu.Unlock()

	s.doneOnce.Do(func() { close(s.done) })
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

	if owned && s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
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

		line, err := s.readRequest(reader)
		if err != nil {
			if errors.Is(err, errRequestTooLarge) {
				s.respond(conn, enc, Response{OK: false, Error: "request too large"})
				return
			}
			// Whatever arrived before the error is a fragment, not a request:
			// executing it would run a command nobody finished sending.
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil && !s.isClosed() {
				s.log.Debug("control: read request failed", "err", err)
			}
			return
		}

		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(trimmed, &req); err != nil {
			s.respond(conn, enc, Response{
				OK:    false,
				Error: fmt.Sprintf("malformed JSON request: %v", err),
			})
			return
		}

		if err := s.respond(conn, enc, s.dispatch(req)); err != nil {
			s.log.Debug("control: write response failed", "err", err)
			return
		}
	}
}

// readRequest reads one newline-terminated request, refusing anything longer
// than maxRequestBytes.
//
// bufio.Reader.ReadBytes grows to whatever the peer sends, so a client writing
// a gigabyte without a newline would make the daemon allocate a gigabyte
// before the read deadline saved it. A partial read is reported as an error
// with no data: the caller must never see half a request.
func (s *Server) readRequest(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > s.maxRequestBytes {
			return nil, errRequestTooLarge
		}
		buf = append(buf, chunk...)
		switch {
		case err == nil:
			return buf, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, err
		}
	}
}

// respond writes one response under the write deadline.
func (s *Server) respond(conn net.Conn, enc *json.Encoder, resp Response) error {
	if s.writeTimeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	return enc.Encode(resp)
}

// logMutation records every privileged state change the control plane makes.
// Whoever can reach the socket can ban and unban at will, so "who changed what,
// and did it work" has to survive in the journal even when nothing goes wrong.
func (s *Server) logMutation(verb, address string, err error, attrs ...any) {
	args := make([]any, 0, len(attrs)+6)
	args = append(args, "verb", verb)
	if address != "" {
		args = append(args, "address", address)
	}
	args = append(args, attrs...)
	if err != nil {
		s.log.Warn("control: mutation rejected", append(args, "outcome", "error", "err", err)...)
		return
	}
	s.log.Info("control: mutation applied", append(args, "outcome", "ok")...)
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
			s.logMutation("ban", ip.String(), err, "monitor", req.Monitor, "duration", dur)
			return Response{OK: false, Error: err.Error()}
		}
		s.logMutation("ban", ip.String(), nil, "monitor", req.Monitor, "duration", dur)
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
			s.logMutation("unban", ip.String(), err)
			return Response{OK: false, Error: err.Error()}
		}
		s.logMutation("unban", ip.String(), nil)
		return Response{OK: true}

	case "unban_all", "unban-all", "unbanall":
		if err := s.svc.UnbanAll(); err != nil {
			s.logMutation("unban_all", "", err)
			return Response{OK: false, Error: err.Error()}
		}
		s.logMutation("unban_all", "", nil)
		return Response{OK: true}

	case "reload":
		if err := s.svc.Reload(); err != nil {
			s.logMutation("reload", "", err)
			return Response{OK: false, Error: err.Error()}
		}
		s.logMutation("reload", "", nil)
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
