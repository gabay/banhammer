package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
	"banhammer/internal/stats"
)

type mockService struct {
	mu          sync.Mutex
	statusResp  StatusResponse
	statusErr   error
	banErr      error
	unbanErr    error
	unbanAllErr error
	reloadErr   error
	calls       []string
	lastBanIP   netip.Addr
	lastBanMon  string
	lastBanDur  time.Duration
	lastUnbanIP netip.Addr
	statusBlock chan struct{}
}

func (m *mockService) Status() (StatusResponse, error) {
	m.mu.Lock()
	block := m.statusBlock
	m.calls = append(m.calls, "Status")
	resp, err := m.statusResp, m.statusErr
	m.mu.Unlock()

	if block != nil {
		<-block
	}
	return resp, err
}

func (m *mockService) Ban(ip netip.Addr, monitor string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Ban")
	m.lastBanIP = ip
	m.lastBanMon = monitor
	m.lastBanDur = d
	return m.banErr
}

func (m *mockService) Unban(ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Unban")
	m.lastUnbanIP = ip
	return m.unbanErr
}

func (m *mockService) UnbanAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "UnbanAll")
	return m.unbanAllErr
}

func (m *mockService) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Reload")
	return m.reloadErr
}

// tempSocket returns a socket path inside a short-lived directory.
//
// t.TempDir() bakes the test and subtest names into the path, which already
// runs to ~103 bytes here and goes over the 108-byte sun_path limit on a host
// with a longer TMPDIR. os.MkdirTemp("", "bh") keeps it short.
func tempSocket(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bh")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func startTestServer(t *testing.T, svc Service, opts ...ServerOption) (*Server, string) {
	t.Helper()
	sock := tempSocket(t, "control.sock")
	srv, err := NewServer(sock, svc, nil, opts...)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = srv.Close() })

	errc := make(chan error, 1)
	go func() {
		errc <- srv.Run(ctx)
	}()

	select {
	case <-srv.Ready():
		if err := srv.Err(); err != nil {
			t.Fatalf("Server failed to bind: %v", err)
		}
	case err := <-errc:
		t.Fatalf("Server failed to bind: %v", err)
	}

	return srv, sock
}

func TestCommands(t *testing.T) {
	testIP := netip.MustParseAddr("198.51.100.42")
	expectedStatus := StatusResponse{
		Uptime: 42 * time.Minute,
		Monitors: []MonitorStatus{
			{
				Name:       "sshd",
				Type:       "file",
				Target:     "/var/log/auth.log",
				TrackedIPs: 15,
			},
		},
		Bans: []model.Ban{
			{
				IP:      testIP,
				Monitor: "sshd",
				At:      time.Unix(1000, 0),
				Until:   time.Unix(4600, 0),
				Count:   5,
				Offense: 1,
			},
		},
		Stats: Stats{
			LinesRead:    1000,
			LinesDropped: 2,
			Matches:      50,
			BansTotal:    10,
			UnbansTotal:  3,
			ActionErrors: 0,
			DecodeErrors: 1,
		},
	}

	tests := []struct {
		name string
		call func(ctx context.Context, client *Client, mock *mockService) error
	}{
		{
			name: "status",
			call: func(ctx context.Context, client *Client, mock *mockService) error {
				mock.mu.Lock()
				mock.statusResp = expectedStatus
				mock.mu.Unlock()

				resp, err := client.Status(ctx)
				if err != nil {
					return fmt.Errorf("Status call failed: %w", err)
				}
				if resp.Uptime != expectedStatus.Uptime {
					return fmt.Errorf("uptime mismatch: got %v, want %v", resp.Uptime, expectedStatus.Uptime)
				}
				if len(resp.Monitors) != 1 || resp.Monitors[0].Name != "sshd" {
					return fmt.Errorf("monitors mismatch: got %+v", resp.Monitors)
				}
				if len(resp.Bans) != 1 || resp.Bans[0].IP != testIP {
					return fmt.Errorf("bans mismatch: got %+v", resp.Bans)
				}
				if resp.Stats.LinesRead != 1000 {
					return fmt.Errorf("stats mismatch: got %+v", resp.Stats)
				}
				return nil
			},
		},
		{
			name: "ban",
			call: func(ctx context.Context, client *Client, mock *mockService) error {
				banDur := 2 * time.Hour
				if err := client.Ban(ctx, testIP, "sshd", banDur); err != nil {
					return fmt.Errorf("Ban call failed: %w", err)
				}
				mock.mu.Lock()
				defer mock.mu.Unlock()
				if mock.lastBanIP != testIP {
					return fmt.Errorf("ban ip mismatch: got %v, want %v", mock.lastBanIP, testIP)
				}
				if mock.lastBanMon != "sshd" {
					return fmt.Errorf("ban monitor mismatch: got %q, want %q", mock.lastBanMon, "sshd")
				}
				if mock.lastBanDur != banDur {
					return fmt.Errorf("ban duration mismatch: got %v, want %v", mock.lastBanDur, banDur)
				}
				return nil
			},
		},
		{
			name: "unban",
			call: func(ctx context.Context, client *Client, mock *mockService) error {
				if err := client.Unban(ctx, testIP); err != nil {
					return fmt.Errorf("Unban call failed: %w", err)
				}
				mock.mu.Lock()
				defer mock.mu.Unlock()
				if mock.lastUnbanIP != testIP {
					return fmt.Errorf("unban ip mismatch: got %v, want %v", mock.lastUnbanIP, testIP)
				}
				return nil
			},
		},
		{
			name: "unban_all",
			call: func(ctx context.Context, client *Client, mock *mockService) error {
				if err := client.UnbanAll(ctx); err != nil {
					return fmt.Errorf("UnbanAll call failed: %w", err)
				}
				mock.mu.Lock()
				defer mock.mu.Unlock()
				if len(mock.calls) == 0 || mock.calls[len(mock.calls)-1] != "UnbanAll" {
					return fmt.Errorf("UnbanAll not recorded in mock calls: %v", mock.calls)
				}
				return nil
			},
		},
		{
			name: "reload",
			call: func(ctx context.Context, client *Client, mock *mockService) error {
				if err := client.Reload(ctx); err != nil {
					return fmt.Errorf("Reload call failed: %w", err)
				}
				mock.mu.Lock()
				defer mock.mu.Unlock()
				if len(mock.calls) == 0 || mock.calls[len(mock.calls)-1] != "Reload" {
					return fmt.Errorf("Reload not recorded in mock calls: %v", mock.calls)
				}
				return nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockService{}
			_, sock := startTestServer(t, mock)
			client := NewClient(sock)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err := tc.call(ctx, client, mock); err != nil {
				t.Fatalf("test case %q failed: %v", tc.name, err)
			}
		})
	}
}

func TestServiceErrors(t *testing.T) {
	testIP := netip.MustParseAddr("203.0.113.1")
	tests := []struct {
		name       string
		setupMock  func(m *mockService)
		invoke     func(ctx context.Context, c *Client) error
		wantErrMsg string
	}{
		{
			name: "status error",
			setupMock: func(m *mockService) {
				m.statusErr = errors.New("daemon database offline")
			},
			invoke: func(ctx context.Context, c *Client) error {
				_, err := c.Status(ctx)
				return err
			},
			wantErrMsg: "daemon database offline",
		},
		{
			name: "ban error allowlisted",
			setupMock: func(m *mockService) {
				m.banErr = errors.New("ban: address is allowlisted")
			},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Ban(ctx, testIP, "sshd", time.Hour)
			},
			wantErrMsg: "ban: address is allowlisted",
		},
		{
			name: "unban error not banned",
			setupMock: func(m *mockService) {
				m.unbanErr = errors.New("ban: address is not banned")
			},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Unban(ctx, testIP)
			},
			wantErrMsg: "ban: address is not banned",
		},
		{
			name: "unban_all error",
			setupMock: func(m *mockService) {
				m.unbanAllErr = errors.New("iptables flush failed")
			},
			invoke: func(ctx context.Context, c *Client) error {
				return c.UnbanAll(ctx)
			},
			wantErrMsg: "iptables flush failed",
		},
		{
			name: "reload error",
			setupMock: func(m *mockService) {
				m.reloadErr = errors.New("syntax error in config.yaml: line 12")
			},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Reload(ctx)
			},
			wantErrMsg: "syntax error in config.yaml: line 12",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockService{}
			tc.setupMock(mock)

			_, sock := startTestServer(t, mock)
			client := NewClient(sock)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := tc.invoke(ctx, client)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrMsg)
			}
			if !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Fatalf("error %q does not contain expected substring %q", err.Error(), tc.wantErrMsg)
			}
			if !errors.Is(err, ErrServer) {
				t.Fatalf("expected error to wrap ErrServer, got: %v", err)
			}
		})
	}
}

func TestInvalidCommandsAndArguments(t *testing.T) {
	mock := &mockService{}
	_, sock := startTestServer(t, mock)
	client := NewClient(sock)

	t.Run("client-side argument validation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var invalidIP netip.Addr
		if err := client.Ban(ctx, invalidIP, "sshd", time.Hour); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for invalid ban IP, got: %v", err)
		}
		if err := client.Ban(ctx, netip.MustParseAddr("1.2.3.4"), "sshd", -1*time.Hour); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for negative duration, got: %v", err)
		}
		if err := client.Unban(ctx, invalidIP); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for invalid unban IP, got: %v", err)
		}
	})

	wireTests := []struct {
		name        string
		requestJSON string
		wantErrSub  string
	}{
		{
			name:        "unknown command",
			requestJSON: `{"command": "shutdown_now"}` + "\n",
			wantErrSub:  "unknown command",
		},
		{
			name:        "empty command",
			requestJSON: `{"command": ""}` + "\n",
			wantErrSub:  "empty command",
		},
		{
			name:        "ban missing ip",
			requestJSON: `{"command": "ban", "monitor": "sshd"}` + "\n",
			wantErrSub:  "ip is required",
		},
		{
			name:        "ban invalid ip",
			requestJSON: `{"command": "ban", "ip": "999.999.999.999", "monitor": "sshd"}` + "\n",
			wantErrSub:  "invalid ip address",
		},
		{
			name:        "ban invalid duration string",
			requestJSON: `{"command": "ban", "ip": "1.2.3.4", "duration": "not-a-duration"}` + "\n",
			wantErrSub:  "invalid duration",
		},
		{
			name:        "ban negative duration",
			requestJSON: `{"command": "ban", "ip": "1.2.3.4", "duration": "-10m"}` + "\n",
			wantErrSub:  "duration cannot be negative",
		},
		{
			name:        "unban missing ip",
			requestJSON: `{"command": "unban"}` + "\n",
			wantErrSub:  "ip is required",
		},
		{
			name:        "unban invalid ip",
			requestJSON: `{"command": "unban", "ip": "hostname.local"}` + "\n",
			wantErrSub:  "invalid ip address",
		},
		{
			name:        "malformed json syntax",
			requestJSON: `{"command": ` + "\n",
			wantErrSub:  "malformed JSON",
		},
	}

	for _, wt := range wireTests {
		t.Run(wt.name, func(t *testing.T) {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatalf("net.Dial failed: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte(wt.requestJSON)); err != nil {
				t.Fatalf("write request failed: %v", err)
			}

			dec := json.NewDecoder(conn)
			var resp Response
			if err := dec.Decode(&resp); err != nil {
				t.Fatalf("decode response failed: %v", err)
			}

			if resp.OK {
				t.Fatalf("expected failure for request %s, but got OK: true", wt.requestJSON)
			}
			if !strings.Contains(resp.Error, wt.wantErrSub) {
				t.Fatalf("error %q does not contain expected substring %q", resp.Error, wt.wantErrSub)
			}
		})
	}
}

func TestSocketCleanupAndStaleHandling(t *testing.T) {
	mock := &mockService{}

	t.Run("cleanup of socket file on server close", func(t *testing.T) {
		sock := tempSocket(t, "cleanup.sock")
		srv, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errc := make(chan error, 1)
		go func() { errc <- srv.Run(ctx) }()

		<-srv.Ready()

		if _, err := os.Stat(sock); err != nil {
			t.Fatalf("expected socket file %q to exist, got: %v", sock, err)
		}

		if err := srv.Close(); err != nil {
			t.Fatalf("srv.Close failed: %v", err)
		}

		if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected socket file to be deleted, got: %v", err)
		}

		// Verify idempotency
		if err := srv.Close(); err != nil {
			t.Fatalf("second srv.Close should be idempotent, got: %v", err)
		}
	})

	t.Run("refuses to touch a non-socket at the socket path", func(t *testing.T) {
		// `banhammer run --socket /etc/banhammer/config.yaml` must not delete
		// the config it was mistakenly pointed at.
		path := tempSocket(t, "config.yaml")
		const content = "state_dir: /var/lib/banhammer\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		srv, err := NewServer(path, mock, nil)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		t.Cleanup(func() { _ = srv.Close() })

		runErr := srv.Run(context.Background())
		if !errors.Is(runErr, ErrNotASocket) {
			t.Fatalf("expected error wrapping ErrNotASocket, got: %v", runErr)
		}

		// Ready must fire even on failure, and Err must explain why.
		select {
		case <-srv.Ready():
		case <-time.After(2 * time.Second):
			t.Fatal("Ready was never closed after a failed bind")
		}
		if !errors.Is(srv.Err(), ErrNotASocket) {
			t.Fatalf("Err() = %v, want ErrNotASocket", srv.Err())
		}

		// Neither Run nor Close may have removed the file.
		_ = srv.Close()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("the operator's file was deleted: %v", err)
		}
		if string(got) != content {
			t.Fatalf("file content changed: got %q, want %q", got, content)
		}
	})

	t.Run("removal of stale socket on startup", func(t *testing.T) {
		// A genuine socket with nobody listening: what a crashed daemon leaves.
		sock := tempSocket(t, "stale.sock")
		dead, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		// Close the listener without unlinking, mimicking SIGKILL.
		if ul, ok := dead.(*net.UnixListener); ok {
			ul.SetUnlinkOnClose(false)
		}
		if err := dead.Close(); err != nil {
			t.Fatalf("closing seed listener: %v", err)
		}
		if _, err := os.Lstat(sock); err != nil {
			t.Fatalf("expected the stale socket to survive its listener: %v", err)
		}

		srv, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() { _ = srv.Run(ctx) }()
		<-srv.Ready()
		defer srv.Close()
		if err := srv.Err(); err != nil {
			t.Fatalf("bind over stale socket failed: %v", err)
		}

		// Verify client can connect and issue commands on the recovered socket
		client := NewClient(sock)
		if err := client.Reload(ctx); err != nil {
			t.Fatalf("Reload failed on recovered socket: %v", err)
		}
	})

	t.Run("socket and parent directory are not world-reachable", func(t *testing.T) {
		base := tempSocket(t, "run")
		sock := filepath.Join(base, "control.sock")

		srv, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer failed: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = srv.Run(ctx) }()
		<-srv.Ready()
		defer srv.Close()
		if err := srv.Err(); err != nil {
			t.Fatalf("bind failed: %v", err)
		}

		fi, err := os.Stat(sock)
		if err != nil {
			t.Fatalf("stat socket: %v", err)
		}
		if got := fi.Mode().Perm(); got != defaultSocketMode {
			t.Errorf("socket mode = %v, want %v", got, defaultSocketMode)
		}

		di, err := os.Stat(base)
		if err != nil {
			t.Fatalf("stat socket directory: %v", err)
		}
		// The umask may clear further bits; what must never survive is
		// anything for "other".
		if got := di.Mode().Perm(); got&0o007 != 0 {
			t.Errorf("socket directory mode = %v, want no world access", got)
		}
	})

	t.Run("refuses bind when socket actively in use", func(t *testing.T) {
		sock := tempSocket(t, "inuse.sock")
		srv1, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer srv1: %v", err)
		}

		ctx1, cancel1 := context.WithCancel(context.Background())
		defer cancel1()

		go func() { _ = srv1.Run(ctx1) }()
		<-srv1.Ready()
		defer srv1.Close()

		// Attempt to start a second server on the same active socket
		srv2, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer srv2: %v", err)
		}

		ctx2, cancel2 := context.WithCancel(context.Background())
		defer cancel2()

		err2 := srv2.Run(ctx2)
		if err2 == nil {
			t.Fatal("expected srv2.Run to fail with active socket, got nil")
		}
		if !errors.Is(err2, ErrSocketInUse) {
			t.Fatalf("expected error wrapping ErrSocketInUse, got: %v", err2)
		}

		// The losing server must not take the live daemon's socket with it:
		// a second `banhammer run` against a different state_dir escapes the
		// store lock, and unlinking here would leave srv1 running but
		// permanently unreachable.
		if err := srv2.Close(); err != nil {
			t.Fatalf("srv2.Close: %v", err)
		}
		if _, err := os.Lstat(sock); err != nil {
			t.Fatalf("srv2.Close deleted the live socket: %v", err)
		}
		client := NewClient(sock)
		if err := client.Reload(ctx1); err != nil {
			t.Fatalf("live server unreachable after srv2.Close: %v", err)
		}
	})
}

func TestContextCancellationAndTimeouts(t *testing.T) {
	t.Run("pre-cancelled client context", func(t *testing.T) {
		mock := &mockService{}
		_, sock := startTestServer(t, mock)
		client := NewClient(sock)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		_, err := client.Status(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	})

	t.Run("in-flight client context cancellation", func(t *testing.T) {
		statusBlock := make(chan struct{})
		mock := &mockService{statusBlock: statusBlock}
		_, sock := startTestServer(t, mock)
		client := NewClient(sock)

		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)

		go func() {
			_, err := client.Status(ctx)
			errc <- err
		}()

		// Cancel context while request is blocked inside mock.Status
		cancel()

		select {
		case err := <-errc:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled, got: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for client to abort after context cancellation")
		}

		// Unblock mock service to let server goroutine terminate cleanly
		close(statusBlock)
	})

	t.Run("client expired deadline", func(t *testing.T) {
		mock := &mockService{}
		_, sock := startTestServer(t, mock)
		client := NewClient(sock)

		// Context with an already-expired deadline (in the past)
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Minute))
		defer cancel()

		_, err := client.Status(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
		}
	})
}

func TestServerValidationAndLifecycle(t *testing.T) {
	mock := &mockService{}

	t.Run("invalid arguments to NewServer", func(t *testing.T) {
		if _, err := NewServer("", mock, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for empty socket path, got: %v", err)
		}
		if _, err := NewServer("/tmp/test.sock", nil, nil); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for nil service, got: %v", err)
		}
	})

	t.Run("concurrent Run calls return ErrRunning", func(t *testing.T) {
		sock := tempSocket(t, "running.sock")
		srv, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() { _ = srv.Run(ctx) }()
		<-srv.Ready()
		defer srv.Close()

		if err := srv.Run(ctx); !errors.Is(err, ErrRunning) {
			t.Fatalf("expected ErrRunning for second Run call, got: %v", err)
		}
	})

	t.Run("Run after Close returns ErrClosed", func(t *testing.T) {
		sock := tempSocket(t, "closed.sock")
		srv, err := NewServer(sock, mock, nil)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		_ = srv.Close()

		if err := srv.Run(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed for Run after Close, got: %v", err)
		}
	})
}

func TestMultipleRequestsOnConnection(t *testing.T) {
	mock := &mockService{}
	_, sock := startTestServer(t, mock)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	// Send reload
	if err := enc.Encode(Request{Command: "reload"}); err != nil {
		t.Fatalf("Encode reload failed: %v", err)
	}
	var resp1 Response
	if err := dec.Decode(&resp1); err != nil {
		t.Fatalf("Decode resp1 failed: %v", err)
	}
	if !resp1.OK {
		t.Fatalf("expected resp1 OK, got error: %s", resp1.Error)
	}

	// Send unban_all over the same stream
	if err := enc.Encode(Request{Command: "unban_all"}); err != nil {
		t.Fatalf("Encode unban_all failed: %v", err)
	}
	var resp2 Response
	if err := dec.Decode(&resp2); err != nil {
		t.Fatalf("Decode resp2 failed: %v", err)
	}
	if !resp2.OK {
		t.Fatalf("expected resp2 OK, got error: %s", resp2.Error)
	}
}

// syncBuffer collects log output written from the server's connection
// goroutines while the test goroutine reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRequestFraming(t *testing.T) {
	t.Run("partial line is never dispatched", func(t *testing.T) {
		// A request without its terminating newline is a fragment. Executing
		// it would run a command the client never finished sending.
		mock := &mockService{}
		_, sock := startTestServer(t, mock)

		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte(`{"command":"unban_all"`)); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		// Half-close so the server reads EOF with data still buffered.
		if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
			t.Fatalf("CloseWrite failed: %v", err)
		}

		// The server must close without answering.
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		buf := make([]byte, 64)
		if n, err := conn.Read(buf); err == nil {
			t.Fatalf("expected EOF, got response %q", buf[:n])
		}

		mock.mu.Lock()
		defer mock.mu.Unlock()
		if len(mock.calls) != 0 {
			t.Fatalf("partial request was dispatched: %v", mock.calls)
		}
	})

	t.Run("oversized request is refused, not buffered", func(t *testing.T) {
		const limit = 1024
		mock := &mockService{}
		_, sock := startTestServer(t, mock, WithMaxRequestBytes(limit))

		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		// No newline anywhere: the old ReadBytes would have grown to whatever
		// the client cared to send.
		junk := bytes.Repeat([]byte("x"), 8*limit)
		go func() { _, _ = conn.Write(junk) }()

		dec := json.NewDecoder(conn)
		var resp Response
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("decode response failed: %v", err)
		}
		if resp.OK {
			t.Fatal("expected failure for oversized request")
		}
		if !strings.Contains(resp.Error, "request too large") {
			t.Fatalf("error %q does not mention the size limit", resp.Error)
		}
	})

	t.Run("idle connection hits the read deadline", func(t *testing.T) {
		// Exercises the WithTimeouts branches, which had no coverage at all.
		mock := &mockService{}
		_, sock := startTestServer(t, mock, WithTimeouts(50*time.Millisecond, 50*time.Millisecond))

		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		buf := make([]byte, 1)
		if n, err := conn.Read(buf); err == nil {
			t.Fatalf("expected the server to drop an idle connection, read %q", buf[:n])
		}
	})
}

func TestMutationAuditLog(t *testing.T) {
	testIP := netip.MustParseAddr("198.51.100.7")

	tests := []struct {
		name     string
		mock     *mockService
		invoke   func(ctx context.Context, c *Client) error
		wantErr  bool
		contains []string
	}{
		{
			name: "ban",
			mock: &mockService{},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Ban(ctx, testIP, "sshd", 30*time.Minute)
			},
			contains: []string{"verb=ban", "address=198.51.100.7", "monitor=sshd", "duration=30m0s", "outcome=ok"},
		},
		{
			name: "unban",
			mock: &mockService{},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Unban(ctx, testIP)
			},
			contains: []string{"verb=unban", "address=198.51.100.7", "outcome=ok"},
		},
		{
			name: "unban_all",
			mock: &mockService{},
			invoke: func(ctx context.Context, c *Client) error {
				return c.UnbanAll(ctx)
			},
			contains: []string{"verb=unban_all", "outcome=ok"},
		},
		{
			name: "reload",
			mock: &mockService{},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Reload(ctx)
			},
			contains: []string{"verb=reload", "outcome=ok"},
		},
		{
			name: "rejected ban is audited too",
			mock: &mockService{banErr: errors.New("ban: address is allowlisted")},
			invoke: func(ctx context.Context, c *Client) error {
				return c.Ban(ctx, testIP, "sshd", time.Hour)
			},
			wantErr:  true,
			contains: []string{"verb=ban", "address=198.51.100.7", "outcome=error", "allowlisted"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := &syncBuffer{}
			logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

			sock := tempSocket(t, "audit.sock")
			srv, err := NewServer(sock, tc.mock, logger)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Run(ctx) }()
			<-srv.Ready()
			defer srv.Close()
			if err := srv.Err(); err != nil {
				t.Fatalf("bind failed: %v", err)
			}

			err = tc.invoke(ctx, NewClient(sock))
			if tc.wantErr && err == nil {
				t.Fatal("expected the command to fail")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("command failed: %v", err)
			}

			got := logs.String()
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("audit log missing %q, got:\n%s", want, got)
				}
			}
		})
	}
}

func TestStatusResponseJSONRoundTrip(t *testing.T) {
	// `banhammer status --json` used to emit "uptime": 7200000000000.
	in := StatusResponse{
		Uptime:   2 * time.Hour,
		Monitors: []MonitorStatus{{Name: "sshd", Type: "file", Target: "/var/log/auth.log", TrackedIPs: 3}},
		Stats:    Stats{LinesRead: 10, TrackedIPs: 3, ActiveBans: 1},
	}

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"uptime":"2h0m0s"`) {
		t.Errorf("uptime is not human readable: %s", data)
	}
	if !strings.Contains(string(data), `"uptime_seconds":7200`) {
		t.Errorf("uptime_seconds missing: %s", data)
	}
	if !strings.Contains(string(data), `"tracked_ips":3`) || !strings.Contains(string(data), `"active_bans":1`) {
		t.Errorf("stats gauges missing: %s", data)
	}

	var out StatusResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if out.Uptime != in.Uptime {
		t.Errorf("uptime round trip: got %v, want %v", out.Uptime, in.Uptime)
	}
	if out.Stats != in.Stats {
		t.Errorf("stats round trip: got %+v, want %+v", out.Stats, in.Stats)
	}
}

// TestStatusResponseHistoryRoundTrip pins that the ledger statistics ride
// along on the status wire format: absent when the daemon has none, and
// intact — including the typed address and time fields — when it does.
func TestStatusResponseHistoryRoundTrip(t *testing.T) {
	without, err := json.Marshal(StatusResponse{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(without), `"history"`) {
		t.Errorf("a response without history must omit the key: %s", without)
	}

	at := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.9")
	in := StatusResponse{
		History: &stats.Summary{
			GeneratedAt: at,
			Events:      1,
			Windows:     []stats.Window{{Name: stats.WindowDay, Seconds: 86400, Bans: 1, UniqueIPs: 1}},
			TopOffenders: []stats.Offender{{
				IP: ip, Bans: 1, LastAt: at, Country: "DE", Monitors: []string{"sshd"},
			}},
			Countries:   []stats.Country{{Code: "DE", Name: "Germany", Bans: 1}},
			IPCountries: map[string]string{ip.String(): "DE"},
			GeoEnabled:  true,
		},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"history":{`, `"generated_at":"2024-03-01T12:00:00Z"`, `"top_offenders":[{"ip":"203.0.113.9"`, `"by_hour_of_day":[0,0,0`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("wire format missing %s in:\n%s", want, data)
		}
	}

	var out StatusResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.History == nil {
		t.Fatal("history lost on the wire")
	}
	if !out.History.GeneratedAt.Equal(at) || out.History.TopOffenders[0].IP != ip || out.History.IPCountries[ip.String()] != "DE" {
		t.Errorf("history round trip: %+v", out.History)
	}
}
