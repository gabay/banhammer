package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"banhammer/internal/model"
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

func startTestServer(t *testing.T, svc Service, opts ...ServerOption) (*Server, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
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
		sock := filepath.Join(t.TempDir(), "cleanup.sock")
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

	t.Run("removal of stale socket on startup", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "stale.sock")
		// Write a dummy file where no process is listening.
		if err := os.WriteFile(sock, []byte("stale socket content"), 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
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

		// Verify client can connect and issue commands on the recovered socket
		client := NewClient(sock)
		if err := client.Reload(ctx); err != nil {
			t.Fatalf("Reload failed on recovered socket: %v", err)
		}
	})

	t.Run("refuses bind when socket actively in use", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "inuse.sock")
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
		sock := filepath.Join(t.TempDir(), "running.sock")
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
		sock := filepath.Join(t.TempDir(), "closed.sock")
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
