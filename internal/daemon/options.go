package daemon

import (
	"io"
	"log/slog"
	"time"

	"banhammer/internal/action"
	"banhammer/internal/ban"
	"banhammer/internal/store"
)

// Option tunes Daemon creation and execution parameters.
type Option func(*Daemon)

// WithLogger sets the structured logger for the daemon.
// If unset or nil, slog.Default() is used.
func WithLogger(log *slog.Logger) Option {
	return func(d *Daemon) {
		d.log = log
	}
}

// WithRunner configures an external command runner for firewall actions.
// This allows hermetic testing without executing real host firewall mutations.
func WithRunner(r action.Runner) Option {
	return func(d *Daemon) {
		d.runner = r
	}
}

// WithNow configures a custom time provider for hermetic, deterministic testing.
func WithNow(now func() time.Time) Option {
	return func(d *Daemon) {
		d.now = now
	}
}

// WithStdin sets the standard input reader for monitors configured with stdin: true.
func WithStdin(r io.Reader) Option {
	return func(d *Daemon) {
		d.stdin = r
	}
}

// WithDryRun forces the action backend to operate in dry-run mode, logging
// firewall actions rather than executing them.
func WithDryRun(dryRun bool) Option {
	return func(d *Daemon) {
		d.dryRun = dryRun
	}
}

// WithControlSocket sets the filesystem path for the Unix domain control socket.
// Passing an empty string disables the control server.
func WithControlSocket(path string) Option {
	return func(d *Daemon) {
		d.controlSocket = path
		d.controlSocketSet = true
	}
}

// WithQueueSize overrides the bounded event queue capacity.
func WithQueueSize(size int) Option {
	return func(d *Daemon) {
		if size > 0 {
			d.queueSize = size
		}
	}
}

// WithConfigPath sets the configuration file path, enabling reload from disk.
func WithConfigPath(path string) Option {
	return func(d *Daemon) {
		d.configPath = path
	}
}

// WithNumWorkers overrides the number of worker goroutines in the matcher pool.
func WithNumWorkers(n int) Option {
	return func(d *Daemon) {
		if n > 0 {
			d.numWorkers = n
		}
	}
}

// WithOffsetInterval sets the interval for periodic source checkpoint persistence.
func WithOffsetInterval(interval time.Duration) Option {
	return func(d *Daemon) {
		if interval > 0 {
			d.offsetInterval = interval
		}
	}
}

// WithSweepInterval sets the interval for periodic sliding-window tracker sweeps.
func WithSweepInterval(interval time.Duration) Option {
	return func(d *Daemon) {
		if interval > 0 {
			d.sweepInterval = interval
		}
	}
}

// WithStore allows injecting a pre-opened Store, primarily for tests.
func WithStore(s *store.Store) Option {
	return func(d *Daemon) {
		d.store = s
	}
}

// WithInterfaces allows injecting a custom network interface lister for allowLocal.
func WithInterfaces(lister ban.InterfaceLister) Option {
	return func(d *Daemon) {
		d.interfaces = lister
	}
}
