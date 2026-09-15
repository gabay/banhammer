package source

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"banhammer/internal/model"
)

// newTestListener builds a listener on a loopback/temp address and returns it
// plus its recording handler.
func newTestListener(t *testing.T, addr string, strip bool) (*listener, *countingHandler) {
	t.Helper()
	log, h := testLogger()
	s, err := NewListener("mon", addr, strip, log)
	if err != nil {
		t.Fatalf("NewListener(%q): %v", addr, err)
	}
	l := s.(*listener)
	l.idle = 2 * time.Second
	return l, h
}

// waitBound blocks until Run has bound the socket and returns its address.
func waitBound(t *testing.T, l *listener) net.Addr {
	t.Helper()
	select {
	case <-l.ready:
	case <-time.After(waitTimeout):
		t.Fatal("listener never bound")
	}
	addr := l.LocalAddr()
	if addr == nil {
		t.Fatal("listener bound but LocalAddr is nil")
	}
	return addr
}

func TestParseListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in          string
		net, addr   string
		wantErrPart string
	}{
		{in: "udp://0.0.0.0:5140", net: "udp", addr: "0.0.0.0:5140"},
		{in: "udp://:5140", net: "udp", addr: ":5140"},
		{in: "tcp://127.0.0.1:0", net: "tcp", addr: "127.0.0.1:0"},
		{in: "tcp://[::1]:5140", net: "tcp", addr: "[::1]:5140"},
		{in: "unix:///run/banhammer.sock", net: "unix", addr: "/run/banhammer.sock"},
		{in: "/run/banhammer.sock", wantErrPart: "want scheme://address"},
		{in: "udp://", wantErrPart: "missing host:port"},
		{in: "unix://", wantErrPart: "missing socket path"},
		{in: "tcp://127.0.0.1", wantErrPart: "missing port"},
		{in: "sctp://127.0.0.1:1", wantErrPart: "unsupported scheme"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			gotNet, gotAddr, err := parseListen(tc.in)
			if tc.wantErrPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("parseListen = (%q,%q,%v), want error containing %q", gotNet, gotAddr, err, tc.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseListen = %v", err)
			}
			if gotNet != tc.net || gotAddr != tc.addr {
				t.Fatalf("parseListen = (%q,%q), want (%q,%q)", gotNet, gotAddr, tc.net, tc.addr)
			}
		})
	}
}

func TestNewListenerValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewListener("", "tcp://127.0.0.1:0", false, nil); err == nil {
		t.Error("empty monitor accepted")
	}
	if _, err := NewListener("m", "nope", false, nil); err == nil {
		t.Error("bad address accepted")
	}
	s, err := NewListener("m", "udp://127.0.0.1:0", false, nil)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	if s.Name() != "m" {
		t.Errorf("Name = %q, want m", s.Name())
	}
}

// Raw must stay valid after the consumer has moved on: the package promises
// arena-backed, write-once buffers, and this is the test that would fail if
// somebody "optimised" that into a reused read buffer.
func TestListenerRawIsSafeToRetain(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	events := make(chan model.Event, 4096)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- l.Run(ctx, events) }()
	addr := waitBound(t, l)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	const n = 2000
	var sent []string
	var payload strings.Builder
	for i := range n {
		line := strings.Repeat(string(rune('a'+i%26)), 1+i%300)
		sent = append(sent, line)
		payload.WriteString(line)
		payload.WriteByte('\n')
	}
	go func() {
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, payload.String()) // failures surface as missing events
	}()

	// Retain every event, then verify afterwards.
	retained := make([]model.Event, 0, n)
	deadline := time.After(waitTimeout)
	for len(retained) < n {
		select {
		case ev := <-events:
			retained = append(retained, ev)
		case <-deadline:
			t.Fatalf("got %d/%d events", len(retained), n)
		}
	}
	for i, ev := range retained {
		if string(ev.Raw) != sent[i] {
			t.Fatalf("event %d = %q..., want %q... (Raw was overwritten after hand-off)",
				i, truncate(string(ev.Raw)), truncate(sent[i]))
		}
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func truncate(s string) string {
	if len(s) > 24 {
		return s[:24]
	}
	return s
}

func TestListenerTCP(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	h := start(t, l)
	addr := waitBound(t, l)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Two whole lines, then a fragment that only completes with the next write.
	if _, err := io.WriteString(conn, "first\nsecond\nthi"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := h.lines(2); !equalStrings(got, []string{"first", "second"}) {
		t.Fatalf("lines = %q", got)
	}
	h.expectQuiet() // the fragment must not be emitted yet
	if _, err := io.WriteString(conn, "rd\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"third"}) {
		t.Fatalf("lines = %q", got)
	}

	// A trailing unterminated line is complete once the peer closes.
	if _, err := io.WriteString(conn, "last-no-newline"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"last-no-newline"}) {
		t.Fatalf("lines = %q", got)
	}
	if cps := l.Checkpoints(); cps != nil {
		t.Errorf("Checkpoints = %v, want nil for a socket", cps)
	}
}

func TestListenerTCPOversizedLine(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	h := start(t, l)
	addr := waitBound(t, l)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, strings.Repeat("y", maxLineBytes+1000)+"\nnext\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := h.lines(2)
	if len(got[0]) != maxLineBytes {
		t.Errorf("first line = %d bytes, want %d", len(got[0]), maxLineBytes)
	}
	if got[1] != "next" {
		t.Errorf("second line = %q, want next", got[1])
	}
}

// The connection cap must bound concurrency, and freeing a slot must let a
// waiting connection through — a cap that never releases is a self-DoS.
func TestListenerTCPConnCap(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	l.maxConns = 2
	h := start(t, l)
	addr := waitBound(t, l)

	dial := func(payload string) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if _, err := io.WriteString(c, payload+"\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		return c
	}

	c1 := dial("one")
	c2 := dial("two")
	defer func() { _ = c2.Close() }()
	got := h.lines(2)
	if len(got) != 2 {
		t.Fatalf("lines = %q", got)
	}

	c3 := dial("three") // queued in the backlog, not served
	defer func() { _ = c3.Close() }()
	h.expectQuiet()

	if err := c1.Close(); err != nil { // frees a slot
		t.Fatalf("close: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"three"}) {
		t.Fatalf("after freeing a slot lines = %q, want [three]", got)
	}
}

// A connection that connects and says nothing must be reaped, otherwise a
// slowloris parks all 64 slots forever.
func TestListenerTCPIdleTimeout(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	l.idle = 50 * time.Millisecond
	start(t, l)
	addr := waitBound(t, l)

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read = %v, want EOF from the server closing an idle connection", err)
	}
}

func TestListenerUDP(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "udp://127.0.0.1:0", false)
	h := start(t, l)
	addr := waitBound(t, l)

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// A datagram is its own frame: no trailing newline required, and one
	// datagram may carry several lines.
	for _, payload := range []string{"no-newline-datagram", "multi1\nmulti2\n", "\n"} {
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	got := h.lines(3)
	want := []string{"no-newline-datagram", "multi1", "multi2"}
	if !equalStrings(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	h.expectQuiet() // the empty datagram produced nothing
}

func TestListenerUDPStripsSyslog(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "udp://127.0.0.1:0", true)
	h := start(t, l)
	addr := waitBound(t, l)

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("<34>Oct 11 22:14:15 mymachine sshd[1]: Failed password from 10.0.0.9")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"Failed password from 10.0.0.9"}) {
		t.Fatalf("lines = %q", got)
	}
}

func TestListenerUnix(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "bh.sock")
	l, _ := newTestListener(t, "unix://"+sock, false)
	h := start(t, l)
	waitBound(t, l)

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != unixSocketMode.Perm() {
		t.Errorf("socket mode = %o, want %o", perm, unixSocketMode.Perm())
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "over-unix\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"over-unix"}) {
		t.Fatalf("lines = %q", got)
	}
}

func TestListenerUnixStaleSocket(t *testing.T) {
	t.Parallel()
	sock := filepath.Join(t.TempDir(), "stale.sock")

	// Leave a socket file behind the way a SIGKILLed daemon would.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("stale socket missing: %v", err)
	}

	l, lh := newTestListener(t, "unix://"+sock, false)
	h := start(t, l)
	waitBound(t, l)
	if n := lh.count(slog.LevelInfo, "removed stale socket"); n != 1 {
		t.Errorf("stale-socket removals logged = %d, want 1", n)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "rebound\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := h.lines(1); !equalStrings(got, []string{"rebound"}) {
		t.Fatalf("lines = %q", got)
	}
}

// A regular file at the socket path is someone else's data: refuse rather than
// delete it.
func TestListenerUnixRefusesNonSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	l, _ := newTestListener(t, "unix://"+path, false)
	err := l.Run(context.Background(), make(chan model.Event, 1))
	if err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("Run = %v, want a 'not a socket' error", err)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("existing file was removed: %v", serr)
	}
}

func TestListenerRunRejectsNilChannel(t *testing.T) {
	t.Parallel()
	l, _ := newTestListener(t, "tcp://127.0.0.1:0", false)
	if err := l.Run(context.Background(), nil); err == nil {
		t.Fatal("Run(nil channel) = nil, want error")
	}
}

func TestListenerBindFailure(t *testing.T) {
	t.Parallel()
	// Port 1 on loopback needs privileges we do not have in tests.
	l, _ := newTestListener(t, "tcp://127.0.0.1:1", false)
	if err := l.Run(context.Background(), make(chan model.Event, 1)); err == nil {
		t.Skip("binding to port 1 succeeded; test needs an unprivileged environment")
	}
}

// Cancellation must be prompt for every transport, including a UDP socket with
// no traffic at all, and must leave nothing running.
func TestListenerCancelPromptlyWithoutLeaking(t *testing.T) {
	tests := []struct {
		name string
		addr func(t *testing.T) string
	}{
		{name: "udp", addr: func(*testing.T) string { return "udp://127.0.0.1:0" }},
		{name: "tcp", addr: func(*testing.T) string { return "tcp://127.0.0.1:0" }},
		{name: "unix", addr: func(t *testing.T) string {
			return "unix://" + filepath.Join(t.TempDir(), "cancel.sock")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := runtime.NumGoroutine()

			l, _ := newTestListener(t, tc.addr(t), false)
			l.idle = time.Hour // a live connection must not be waited on
			ctx, cancel := context.WithCancel(context.Background())
			errc := make(chan error, 1)
			go func() { errc <- l.Run(ctx, make(chan model.Event, 16)) }()
			addr := waitBound(t, l)

			// Park an idle connection on the stream transports so shutdown
			// has a connection goroutine to join.
			if tc.name != "udp" {
				c, err := net.Dial(addr.Network(), addr.String())
				if err != nil {
					t.Fatalf("dial: %v", err)
				}
				defer func() { _ = c.Close() }()
			}

			start := time.Now()
			cancel()
			select {
			case err := <-errc:
				if err != nil {
					t.Fatalf("Run = %v, want nil on cancellation", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not return within 2s of cancellation")
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("cancellation took %v, want well under a second", d)
			}
			assertNoLeak(t, before)
		})
	}
}
