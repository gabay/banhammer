package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"banhammer/internal/model"
)

const (
	// maxTCPConns caps concurrent accepted connections. Without a cap a
	// slowloris opens sockets until the daemon runs out of descriptors.
	maxTCPConns = 64
	// connIdleTimeout closes a connection that has sent nothing for this
	// long, which is what actually frees the slots the cap hands out.
	connIdleTimeout = 2 * time.Minute
	// udpReadSlice bounds how long a UDP read blocks, so cancellation is
	// prompt even if the socket close race is lost.
	udpReadSlice = 250 * time.Millisecond
	// udpBuffer is sized for a jumbo datagram (max UDP payload is 65507).
	udpBuffer = 64 << 10
	// connReadChunk is the per-connection read buffer.
	connReadChunk = 16 << 10
	// unixSocketMode keeps the socket off the world: a local user who can
	// write to it can forge log lines and get arbitrary addresses banned.
	unixSocketMode fs.FileMode = 0o660
)

// NewListener returns a Source that accepts log lines over the network.
//
// addr is udp://host:port, tcp://host:port or unix:///path/to.sock. Framing is
// newline-delimited for the stream transports; for UDP the datagram is the
// frame (and may itself contain several lines). If stripSyslog is set, the
// RFC3164/RFC5424 "<PRI>timestamp host tag:" prefix is peeled off before the
// line reaches the pipeline.
func NewListener(monitor, addr string, stripSyslog bool, log *slog.Logger) (Source, error) {
	if monitor == "" {
		return nil, errors.New("listener: monitor name is empty")
	}
	network, address, err := parseListen(addr)
	if err != nil {
		return nil, fmt.Errorf("listener %q: %w", monitor, err)
	}
	return &listener{
		monitor:  monitor,
		network:  network,
		address:  address,
		strip:    stripSyslog,
		log:      orDefaultLogger(log).With("monitor", monitor, "listen", addr),
		idle:     connIdleTimeout,
		maxConns: maxTCPConns,
		ready:    make(chan struct{}),
	}, nil
}

func parseListen(addr string) (network, address string, err error) {
	scheme, rest, ok := strings.Cut(addr, "://")
	if !ok {
		return "", "", fmt.Errorf("bad listen address %q: want scheme://address", addr)
	}
	switch scheme {
	case "udp", "tcp":
		if rest == "" {
			return "", "", fmt.Errorf("bad listen address %q: missing host:port", addr)
		}
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return "", "", fmt.Errorf("bad listen address %q: %w", addr, err)
		}
		return scheme, rest, nil
	case "unix":
		if rest == "" {
			return "", "", fmt.Errorf("bad listen address %q: missing socket path", addr)
		}
		return "unix", rest, nil
	default:
		return "", "", fmt.Errorf("bad listen address %q: unsupported scheme %q (want udp|tcp|unix)", addr, scheme)
	}
}

type listener struct {
	monitor  string
	network  string
	address  string
	strip    bool
	log      *slog.Logger
	idle     time.Duration
	maxConns int

	// ready is closed once bound; tests use it with a :0 port.
	ready     chan struct{}
	readyOnce sync.Once

	mu        sync.Mutex
	local     net.Addr
	conns     map[net.Conn]struct{}
	closing   bool
	closeConn func() // set to close the listening socket on shutdown
}

func (l *listener) Name() string { return l.monitor }

// Checkpoints returns nil: a socket has no resumable position.
func (l *listener) Checkpoints() []model.Checkpoint { return nil }

// LocalAddr reports the bound address, or nil before Run has bound it. It is
// useful for logging the effective port when the config asks for :0.
func (l *listener) LocalAddr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.local
}

func (l *listener) setLocal(a net.Addr) {
	l.mu.Lock()
	l.local = a
	l.mu.Unlock()
	l.readyOnce.Do(func() { close(l.ready) })
}

func (l *listener) Run(ctx context.Context, out chan<- model.Event) error {
	if out == nil {
		return fmt.Errorf("listener %q: nil output channel", l.monitor)
	}
	// Whatever happens, unblock anything waiting for the bind.
	defer l.readyOnce.Do(func() { close(l.ready) })

	if l.network == "udp" {
		return l.runPacket(ctx, out)
	}
	return l.runStream(ctx, out)
}

func (l *listener) transform() func([]byte) []byte {
	if !l.strip {
		return nil
	}
	return stripSyslog
}

func (l *listener) runPacket(ctx context.Context, out chan<- model.Event) error {
	pc, err := net.ListenPacket("udp", l.address)
	if err != nil {
		return fmt.Errorf("listener %q: listen udp %s: %w", l.monitor, l.address, err)
	}
	l.setLocal(pc.LocalAddr())
	l.log.Info("listening", "addr", pc.LocalAddr().String())

	// Closing the socket is what makes cancellation instant; the read
	// deadline below is only a backstop for platforms where a concurrent
	// close does not unblock the read.
	var once sync.Once
	closeSock := func() {
		once.Do(func() {
			if err := pc.Close(); err != nil {
				l.log.Debug("closing udp socket", "err", err)
			}
		})
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			closeSock()
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
		closeSock()
	}()

	em := emitter{monitor: l.monitor, out: out, transform: l.transform()}
	buf := make([]byte, udpBuffer)
	for {
		if err := pc.SetReadDeadline(time.Now().Add(udpReadSlice)); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("listener %q: set read deadline: %w", l.monitor, err)
		}
		n, _, err := pc.ReadFrom(buf)
		if n > 0 {
			// A datagram is a frame: split on newlines but do not require a
			// terminating one, because syslog senders usually omit it.
			for _, line := range splitDatagram(buf[:n]) {
				if len(line) > maxLineBytes {
					line = line[:maxLineBytes]
				}
				if err := em.emit(ctx, line); err != nil {
					return nil // context cancelled
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A malformed datagram or transient ICMP error must not kill
			// the monitor.
			l.log.Warn("udp read failed", "err", err)
			continue
		}
	}
}

// splitDatagram yields the newline-separated segments of one datagram,
// dropping empty ones.
func splitDatagram(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		var seg []byte
		if i < 0 {
			seg, b = b, nil
		} else {
			seg, b = b[:i], b[i+1:]
		}
		if seg = trimCR(seg); len(seg) > 0 {
			out = append(out, seg)
		}
	}
	return out
}

func (l *listener) runStream(ctx context.Context, out chan<- model.Event) error {
	if l.network == "unix" {
		if err := l.clearStaleSocket(); err != nil {
			return err
		}
	}
	ln, err := net.Listen(l.network, l.address)
	if err != nil {
		return fmt.Errorf("listener %q: listen %s %s: %w", l.monitor, l.network, l.address, err)
	}
	if l.network == "unix" {
		// net.Listen creates the socket with 0777&^umask; tighten it. There
		// is a brief window where the umask value applies — acceptable, and
		// noted in the package docs.
		if err := os.Chmod(l.address, unixSocketMode); err != nil {
			l.log.Warn("cannot set socket permissions", "path", l.address, "err", err)
		}
	}
	l.setLocal(ln.Addr())
	l.log.Info("listening", "addr", ln.Addr().String())

	l.mu.Lock()
	l.conns = make(map[net.Conn]struct{})
	l.mu.Unlock()

	var once sync.Once
	closeLn := func() {
		once.Do(func() {
			if err := ln.Close(); err != nil {
				l.log.Debug("closing listener", "err", err)
			}
		})
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			closeLn()
			l.shutdownConns()
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		closeLn()
		l.shutdownConns()
		wg.Wait() // joins the closer and every connection goroutine
	}()

	sem := make(chan struct{}, l.maxConns)
	for {
		// Take a slot before accepting: a connection we would immediately
		// have to drop is better left in the kernel backlog, where it costs
		// us nothing and the peer can retry.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		conn, err := ln.Accept()
		if err != nil {
			<-sem
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			l.log.Warn("accept failed", "err", err)
			continue
		}
		if !l.trackConn(conn) {
			// Shutting down; do not start a goroutine we would have to wait on.
			_ = conn.Close() // best effort during shutdown
			<-sem
			return nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer l.untrackConn(conn)
			l.serveConn(ctx, conn, out)
		}()
	}
}

// clearStaleSocket removes a socket left behind by a crash. Anything that is
// not a socket is left alone: refusing to start beats deleting a user's file.
func (l *listener) clearStaleSocket() error {
	fi, err := os.Lstat(l.address)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("listener %q: stat %s: %w", l.monitor, l.address, err)
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("listener %q: %s exists and is not a socket", l.monitor, l.address)
	}
	// A live daemon would still hold it; a connect test would be racy, so we
	// rely on the store lockfile to guarantee single-instance operation.
	if err := os.Remove(l.address); err != nil {
		return fmt.Errorf("listener %q: remove stale socket %s: %w", l.monitor, l.address, err)
	}
	l.log.Info("removed stale socket", "path", l.address)
	return nil
}

func (l *listener) trackConn(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *listener) untrackConn(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// shutdownConns closes every live connection so its goroutine returns from a
// blocking read immediately instead of after the idle timeout.
func (l *listener) shutdownConns() {
	l.mu.Lock()
	l.closing = true
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close() // shutting down; a close error changes nothing
	}
}

func (l *listener) serveConn(ctx context.Context, conn net.Conn, out chan<- model.Event) {
	defer func() { _ = conn.Close() }() // idempotent alongside shutdownConns

	em := emitter{monitor: l.monitor, out: out, transform: l.transform()}
	emit := func(line []byte) error { return em.emit(ctx, line) }
	sp := splitter{max: maxLineBytes}
	buf := make([]byte, connReadChunk)
	log := l.log.With("peer", conn.RemoteAddr().String())

	for {
		if err := conn.SetReadDeadline(time.Now().Add(l.idle)); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if n > 0 {
			if perr := sp.push(buf[:n], emit); perr != nil {
				return // context cancelled
			}
		}
		if err != nil {
			switch {
			case ctx.Err() != nil || errors.Is(err, net.ErrClosed):
				return
			case errors.Is(err, os.ErrDeadlineExceeded):
				log.Debug("closing idle connection", "idle", l.idle)
				return
			case errors.Is(err, io.EOF):
				// The peer is done, so a trailing unterminated line is
				// complete by definition.
				if ferr := sp.flush(emit); ferr != nil {
					return
				}
				if sp.truncated > 0 {
					log.Warn("over-long lines were truncated", "count", sp.truncated, "max", maxLineBytes)
				}
				return
			default:
				log.Debug("connection read failed", "err", err)
				return
			}
		}
	}
}
