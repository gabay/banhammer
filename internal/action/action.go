package action

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"banhammer/internal/model"
)

// defaultTimeout is the per-command timeout when Spec.Timeout is unset. A
// firewall command that has not returned in ten seconds is wedged (usually on
// the xtables lock), and the Executor's retry is a better answer than waiting.
const defaultTimeout = 10 * time.Second

// DefaultChain is the firewall chain (or netfilter hook for nft) attached to
// when Spec.Chain is empty.
const DefaultChain = "INPUT"

// Spec selects and configures a Backend. It is the action section of the
// config, resolved for one monitor.
type Spec struct {
	// Name is one of iptables|ipset|nft|cmd|dryrun. Empty means iptables.
	Name string

	// Chain names the firewall chain (or netfilter hook for nft) to attach to
	// (e.g. "INPUT" by default, or "DOCKER-USER" for Docker containers).
	// Empty means DefaultChain ("INPUT").
	Chain string

	// Start, Ban, Unban and Stop are command templates for the cmd backend.
	// Ban and Unban are required there; Start and Stop are optional.
	Start, Ban, Unban, Stop string

	// Shell runs cmd templates through "/bin/sh -c" instead of exec'ing them
	// directly.
	//
	// This forfeits the injection guarantee this package otherwise provides.
	// Every substitution variable is currently trusted — {ip} is rendered from
	// a parsed netip.Addr, {monitor} and {matched} come from the config — so
	// the immediate risk is low, but the guarantee is structural and Shell
	// removes it: the day a variable starts carrying log text, a crafted line
	// runs arbitrary commands as the daemon's user. Shell exists only because
	// some templates genuinely need pipes or ';'. Prefer wrapping those in a
	// script and calling the script.
	Shell bool

	// Timeout bounds a single external command. Zero means defaultTimeout.
	Timeout time.Duration

	// DryRun wraps whichever backend Name selects so that nothing is executed;
	// every command that would have run is logged instead.
	DryRun bool
}

// Backend applies and removes bans through one concrete mechanism.
//
// Implementations are not required to be goroutine-safe: [Executor] calls them
// from a single goroutine precisely because iptables is not concurrency-safe.
type Backend interface {
	// Name identifies the backend in logs and metrics.
	Name() string
	// Start prepares the firewall (chains, sets, tables). It must be
	// idempotent: it runs on every daemon start, over state left by the last.
	Start(ctx context.Context) error
	// Ban blocks b.IP. Re-banning an already-blocked address must succeed.
	Ban(ctx context.Context, b model.Ban) error
	// Unban removes the block. Removing a rule that is already gone (manual
	// flush, reboot, kernel-side timeout) is a no-op success, not an error.
	Unban(ctx context.Context, b model.Ban) error
	// Stop is optional teardown. The built-in backends deliberately leave bans
	// in place, matching flush_on_exit: false.
	Stop(ctx context.Context) error
}

// New builds the Backend described by spec. r may be nil, in which case a real
// exec Runner is used; log may be nil, in which case slog.Default() is used.
func New(spec Spec, r Runner, log *slog.Logger) (Backend, error) {
	if log == nil {
		log = slog.Default()
	}
	if r == nil {
		r = NewExecRunner()
	}
	if spec.Timeout <= 0 {
		spec.Timeout = defaultTimeout
	}
	chain := strings.TrimSpace(spec.Chain)
	if chain == "" {
		chain = DefaultChain
	}
	spec.Chain = chain

	name := strings.ToLower(strings.TrimSpace(spec.Name))
	if name == "" {
		name = "iptables"
	}
	// A dryrun action is just the default backend that never executes, so the
	// operator sees the real iptables commands rather than a vague "would ban".
	dry := spec.DryRun || name == "dryrun"
	if name == "dryrun" {
		name = "iptables"
	}
	if dry {
		r = newDryRunner(r, log)
		log.Info("dry-run: no firewall changes will be made", "backend", name)
	}

	base := base{run: r, log: log.With("backend", name), timeout: spec.Timeout}

	var (
		b   Backend
		err error
	)
	switch name {
	case "iptables":
		b = newIPTables(base, chain)
	case "ipset":
		b = newIPSet(base, chain)
	case "nft":
		b = newNFT(base, chain)
	case "cmd":
		b, err = newCmd(base, spec)
	default:
		return nil, fmt.Errorf("action: unknown backend %q (want iptables|ipset|nft|cmd|dryrun)", spec.Name)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// base is the plumbing every backend shares: a Runner, a logger and the
// per-command timeout.
type base struct {
	run     Runner
	log     *slog.Logger
	timeout time.Duration
}

// exec runs one command under the per-command timeout. The timeout is applied
// here, per command, rather than per ban, so that a three-command bootstrap
// cannot silently consume a whole operation's budget on its first step.
func (b base) exec(ctx context.Context, shell bool, argv ...string) ([]byte, error) {
	if b.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
	}
	out, err := b.run.Run(ctx, argv, shell)
	if err != nil {
		return out, err
	}
	b.log.Debug("command ok", "cmd", Quote(argv))
	return out, nil
}

// addrString renders the address exactly as the firewall should see it.
// Unmap() collapses ::ffff:1.2.3.4 onto 1.2.3.4 so a v4-mapped address is
// handed to iptables rather than ip6tables.
func addrString(b model.Ban) string { return b.IP.Unmap().String() }

// banDuration is the nominal length of the ban, used for kernel-side timeouts
// and the {bantime} template variable. It is derived from the record rather
// than from the clock so the value is stable across restarts and hermetic in
// tests; the daemon's own unban remains the authority.
func banDuration(b model.Ban) time.Duration {
	if b.At.IsZero() || b.Until.IsZero() {
		return 0
	}
	d := b.Until.Sub(b.At)
	if d < 0 {
		return 0
	}
	return d.Round(time.Second)
}
