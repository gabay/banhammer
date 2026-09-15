// Package control implements the Unix domain socket IPC control plane between
// the banhammer daemon and administrative CLI commands (status, ban, unban,
// reload).
//
// # Why Unix Domain Sockets
//
// A local Unix domain socket gives the daemon a zero-configuration, filesystem-
// permissioned control interface. It avoids binding network ports, requires no
// TLS certificates or authentication tokens beyond OS user/group permissions,
// and ensures administrative commands cannot be routed across the network.
//
// # Wire Protocol
//
// The wire format is newline-delimited JSON. Each request is a single JSON
// object containing a "command" verb and optional parameters; each response is
// a JSON object indicating success or failure, along with command-specific
// payload data (such as status snapshots). Framing by line allows inspection
// and debugging using standard Unix utilities like socat or nc.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"banhammer/internal/model"
)

// Sentinel errors representing control-plane failure states.
var (
	// ErrSocketInUse indicates that the requested Unix domain socket is already
	// held by an active, responsive process, preventing accidental dual-daemon runs.
	ErrSocketInUse = errors.New("control: socket already in use")

	// ErrClosed indicates an operation was attempted on a server or client that
	// has already been terminated.
	ErrClosed = errors.New("control: closed")

	// ErrRunning indicates that Run was called on a server that is already actively running.
	ErrRunning = errors.New("control: server already running")

	// ErrInvalidCommand indicates that the client sent an unknown or empty command verb.
	ErrInvalidCommand = errors.New("control: invalid command")

	// ErrInvalidArgument indicates that a command was supplied with missing or malformed arguments.
	ErrInvalidArgument = errors.New("control: invalid argument")

	// ErrServer represents an execution error returned by the remote control server.
	ErrServer = errors.New("control: server error")
)

// Service abstracts the daemon actions accessible to the control plane.
//
// This decouples the IPC server from the concrete daemon coordinator, allowing
// hermetic unit testing of the IPC layer using mock services without running
// actual log ingestion pipelines or firewall mutations.
type Service interface {
	// Status captures a point-in-time snapshot of the daemon's operational health,
	// active monitors, live bans, and pipeline counters.
	Status() (StatusResponse, error)

	// Ban manually imposes an immediate ban on ip under the given monitor for
	// duration d. If d is zero or negative, the monitor's configured default
	// bantime is applied.
	Ban(ip netip.Addr, monitor string, d time.Duration) error

	// Unban removes an active ban for ip, immediately lifting firewall rules.
	Unban(ip netip.Addr) error

	// UnbanAll removes all currently active bans across all monitors.
	UnbanAll() error

	// Reload instructs the daemon to re-read its configuration file and update
	// monitor rules and allowlists without restarting the process.
	Reload() error
}

// StatusResponse encapsulates a complete diagnostic view of the running daemon.
//
// It provides operators with all data required to render the `banhammer status`
// dashboard: how long the daemon has run, which sources are actively monitored,
// who is currently banned, and overall pipeline throughput counters.
type StatusResponse struct {
	Uptime   time.Duration   `json:"uptime"`
	Monitors []MonitorStatus `json:"monitors"`
	Bans     []model.Ban     `json:"bans"`
	Stats    Stats           `json:"stats"`
}

// UnmarshalJSON provides flexible decoding of StatusResponse, accepting Uptime
// both as an integer count of nanoseconds and as a standard Go duration string
// (e.g. "1h30m").
func (s *StatusResponse) UnmarshalJSON(data []byte) error {
	type Alias StatusResponse
	aux := struct {
		Uptime any `json:"uptime"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("control: unmarshal StatusResponse: %w", err)
	}
	switch v := aux.Uptime.(type) {
	case nil:
		s.Uptime = 0
	case float64:
		s.Uptime = time.Duration(v)
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("control: parse uptime duration %q: %w", v, err)
		}
		s.Uptime = d
	default:
		return fmt.Errorf("control: invalid uptime format: %T", aux.Uptime)
	}
	return nil
}

// MonitorStatus reports the runtime state of a single configured log monitor,
// including its source type, path or address target, and memory footprint in the
// sliding-window IP tracker.
type MonitorStatus struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // "file", "listen", "stdin"
	Target     string `json:"target"`
	TrackedIPs int    `json:"tracked_ips"`
}

// Stats holds cumulative operational counters across all monitors and pipeline
// stages since the daemon started.
type Stats struct {
	LinesRead    int64 `json:"lines_read"`
	LinesDropped int64 `json:"lines_dropped"`
	Matches      int64 `json:"matches"`
	BansTotal    int64 `json:"bans_total"`
	UnbansTotal  int64 `json:"unbans_total"`
	ActionErrors int64 `json:"action_errors"`
	DecodeErrors int64 `json:"decode_errors"`
}

// Request is the serialized envelope transmitted by clients over the control socket.
type Request struct {
	Command  string          `json:"command"`
	IP       string          `json:"ip,omitempty"`
	Monitor  string          `json:"monitor,omitempty"`
	Duration json.RawMessage `json:"duration,omitempty"`
}

// Response is the serialized envelope returned by the server for every request.
type Response struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Status *StatusResponse `json:"status,omitempty"`
}
