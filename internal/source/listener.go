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
	// connMaxLifetime closes a connection after this long no matter how
	// chatty it is. The idle timeout alone is not enough: a peer that dribbles
	// one byte a minute resets it forever and parks one of the 64 slots for
	// the life of the daemon. A legitimate syslog forwarder simply
	// reconnects, so the cost of being wrong here is one reconnect an hour.
	connMaxLifetime = time.Hour
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
	// acceptRetryMin and acceptRetryMax bound the backoff after a failed
	// Accept, matching net/http.Server.Serve's schedule.
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// nextAcceptDelay returns the delay to wait after a failed Accept, doubling
// from acceptRetryMin up to acceptRetryMax.
//
// Under EMFILE/ENFILE Accept fails instantly and keeps failing, so retrying in
// a bare loop burns a core and writes a warning per iteration until the disk
// fills. net/http solved this years ago; there is no reason to solve it
// differently.
func nextAcceptDelay(d time.Duration) time.Duration {
	if d <= 0 {
		return acceptRetryMin
	}
	if d *= 2; d > acceptRetryMax {
		return acceptRetryMax
	}
	return d
}

// NewListener returns a Source that accepts log lines over the network.
//
// addr is udp://host:port, tcp://host:port or unix:///path/to.sock. Framing is
// newline-delimited for the stream transports; for UDP the datagram is the
// frame (and may itself contain several lines). If stripSyslog is set, the
// RFC3164/RFC5424 "<PRI>timestamp host tag:" prefix is peeled off before the
// line reaches the pipeline.
//
// Stream connections are bounded three ways: at most maxTCPConns at once, an
// idle timeout, and an absolute lifetime. The last two are not redundant — a
// peer that sends one byte per minute never goes idle.
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
		maxLife:  connMaxLifetime,
		maxConns: maxTCPConns,
		maxLine:  maxLineBytes,
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
	monitor string
	network string
	address string
	strip   bool
	log     *slog.Logger

	// Tunables; overridden by tests so they neither wait for real timeouts
	// nor have to push 64 KiB through a socket to exercise the line cap.
	idle     time.Duration
	maxLife  time.Duration
	maxConns int
	maxLine  int

	// ready is closed once bound; tests use it with a :0 port.
	ready     chan struct{}
	readyOnce sync.Once

	stats sourceStats
	// Accept failures and malformed datagrams are both unbounded in the
	// worst case (EMFILE, a misconfigured sender), so each gets its own
	// limiter rather than one starving the other. PROJECT.md §4.9.
	acceptWarn rateLimiter
	packetWarn rateLimiter

	mu      sync.Mutex
	local   net.Addr
	conns   map[net.Conn]struct{}
	closing bool
}

func (l *listener) Name() string { return l.monitor }

// Checkpoints returns nil: a socket has no resumable position.
func (l *listener) Checkpoints() []model.Checkpoint { return nil }

// Stats reports over-long lines truncated on the way through, counting both
// stream lines and oversized datagrams.
func (l *listener) Stats() Stats { return l.stats.snapshot() }

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
			var truncated uint64
			for _, line := range splitDatagram(buf[:n]) {
				if len(line) > l.maxLine {
					// Counted, not silent: the stream path promises
					// "truncated and counted" (PROJECT.md §4.1) and a
					// datagram is no different — a sender whose lines are
					// all being cut in half should be diagnosable.
					truncated++
					line = line[:l.maxLine]
				}
				if err := em.emit(ctx, line); err != nil {
					l.stats.noteTruncated(l.log, truncated, l.maxLine)
					return nil // context cancelled
				}
			}
			l.stats.noteTruncated(l.log, truncated, l.maxLine)
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
			// the monitor. One misconfigured sender can produce these at
			// line rate, so the warning is rate limited.
			l.packetWarn.warn(l.log, "udp read failed", "err", err)
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
	var acceptDelay time.Duration
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
			// Descriptor exhaustion (EMFILE/ENFILE) is the case that
			// matters: Accept returns instantly and keeps doing so, so
			// continuing straight away spins a core and writes a warning
			// per iteration. Back off instead, and give the rest of the
			// daemon a chance to release descriptors.
			acceptDelay = nextAcceptDelay(acceptDelay)
			l.acceptWarn.warn(l.log, "accept failed, backing off", "err", err, "delay", acceptDelay)
			select {
			case <-time.After(acceptDelay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		acceptDelay = 0
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
	sp := splitter{max: l.maxLine}
	buf := make([]byte, connReadChunk)
	log := l.log.With("peer", conn.RemoteAddr().String())
	// Truncations are reported as they happen, not at EOF: an idle timeout, a
	// cancellation or a read error ends most connections, and the count used
	// to be dropped on the floor in all three cases.
	defer l.stats.noteSplitter(log, &sp)

	// The idle timeout is reset on every read, so on its own it is exactly
	// what a slowloris defeats: one byte an hour keeps a slot forever. This
	// deadline is absolute and never moves.
	expiry := time.Now().Add(l.maxLife)

	for {
		deadline := time.Now().Add(l.idle)
		if deadline.After(expiry) {
			deadline = expiry
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if n > 0 {
			perr := sp.push(buf[:n], emit)
			l.stats.noteSplitter(log, &sp)
			if perr != nil {
				return // context cancelled
			}
		}
		if err != nil {
			switch {
			case ctx.Err() != nil || errors.Is(err, net.ErrClosed):
				return
			case errors.Is(err, os.ErrDeadlineExceeded):
				if !time.Now().Before(expiry) {
					log.Debug("closing connection at its lifetime limit", "lifetime", l.maxLife)
				} else {
					log.Debug("closing idle connection", "idle", l.idle)
				}
				return
			case errors.Is(err, io.EOF):
				// The peer is done, so a trailing unterminated line is
				// complete by definition.
				if ferr := sp.flush(emit); ferr != nil {
					return
				}
				return
			default:
				log.Debug("connection read failed", "err", err)
				return
			}
		}
	}
}
