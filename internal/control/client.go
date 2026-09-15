package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Client provides an IPC client for issuing commands to a banhammer daemon
// over a Unix domain socket.
type Client struct {
	socketPath string
}

// NewClient constructs a Client targeting the Unix domain socket at socketPath.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

// Status queries the daemon for a point-in-time snapshot of runtime metrics,
// configured monitors, and active bans.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	req := Request{Command: "status"}
	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return StatusResponse{}, err
	}
	if resp.Status == nil {
		return StatusResponse{}, fmt.Errorf("control client: missing status payload from server")
	}
	return *resp.Status, nil
}

// Ban sends a manual ban command for ip under the given monitor for duration d.
// If d is zero or negative, the daemon applies the monitor's default bantime.
func (c *Client) Ban(ctx context.Context, ip netip.Addr, monitor string, d time.Duration) error {
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid ip address", ErrInvalidArgument)
	}
	if d < 0 {
		return fmt.Errorf("%w: duration cannot be negative", ErrInvalidArgument)
	}
	req := Request{
		Command: "ban",
		IP:      ip.String(),
		Monitor: monitor,
	}
	if d > 0 {
		raw, err := json.Marshal(d.String())
		if err != nil {
			return fmt.Errorf("control client: marshal duration: %w", err)
		}
		req.Duration = raw
	}
	_, err := c.roundTrip(ctx, req)
	return err
}

// Unban sends a manual unban command for ip, removing its active firewall drop rule.
func (c *Client) Unban(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid ip address", ErrInvalidArgument)
	}
	req := Request{
		Command: "unban",
		IP:      ip.String(),
	}
	_, err := c.roundTrip(ctx, req)
	return err
}

// UnbanAll instructs the daemon to immediately lift all active bans.
func (c *Client) UnbanAll(ctx context.Context) error {
	req := Request{Command: "unban_all"}
	_, err := c.roundTrip(ctx, req)
	return err
}

// Reload requests the daemon to re-read its configuration file and apply rule updates.
func (c *Client) Reload(ctx context.Context) error {
	req := Request{Command: "reload"}
	_, err := c.roundTrip(ctx, req)
	return err
}

func (c *Client) roundTrip(ctx context.Context, req Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	if c.socketPath == "" {
		return Response{}, fmt.Errorf("%w: empty socket path", ErrInvalidArgument)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("control client: dial %q: %w", c.socketPath, err)
	}

	stopWatcher := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopWatcher()
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("control client: send request: %w", err)
	}

	dec := json.NewDecoder(conn)
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("control client: receive response: %w", err)
	}

	if !resp.OK {
		return resp, fmt.Errorf("%w: %s", ErrServer, resp.Error)
	}
	return resp, nil
}
