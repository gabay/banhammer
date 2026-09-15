package action

import (
	"context"
	"errors"
	"fmt"

	"banhammer/internal/model"
)

// chainName is the chain banhammer owns. Everything the daemon adds lives
// here, so an operator can audit or flush our rules without touching theirs.
const chainName = "BANHAMMER"

const (
	binIPTables  = "iptables"
	binIP6Tables = "ip6tables"
)

// ErrFamilyUnavailable is returned when a ban targets an address family whose
// firewall binary failed to bootstrap (typically a host built without IPv6).
// Startup still succeeds — the daemon keeps protecting the family it can.
var ErrFamilyUnavailable = errors.New("action: address family unavailable")

// iptablesNotFound lists the stderr fragments iptables emits when the rule or
// chain we asked it to delete is not there. Combined with a non-zero exit this
// means "already gone", which for Unban is success.
//
// HEURISTIC: these strings come from iptables 1.8.x (legacy and nft variants)
// running under LC_ALL=C. iptables has no machine-readable "not found" exit
// code, so this is the only signal available. A localised or much older build
// can miss, in which case a benign unban is reported as a failure — noisy, but
// never an incorrect firewall state.
var iptablesNotFound = []string{
	"does a matching rule exist",
	"no chain/target/match by that name",
	"no such file or directory",
}

// iptables is the default backend: a DROP rule per banned address in our own
// chain, jumped to from INPUT.
type iptables struct {
	base
	// v4 and v6 are the per-family binaries plus whether they are usable.
	v4, v6 *xtables
}

// xtables is one iptables-family binary and what we learned about it at Start.
type xtables struct {
	bin   string
	ok    bool
	wait  bool // whether the binary understands --wait
	fam   model.Family
	setup bool
}

func newIPTables(b base) *iptables {
	return &iptables{
		base: b,
		v4:   &xtables{bin: binIPTables, fam: model.IPv4},
		v6:   &xtables{bin: binIP6Tables, fam: model.IPv6},
	}
}

func (*iptables) Name() string { return "iptables" }

// Start creates the chain and the INPUT jump for both families, idempotently.
//
// An IPv6 failure never fails startup: plenty of hosts have no ip6tables at
// all, and refusing to protect IPv4 because of that would be a self-inflicted
// outage. We log once and disable the v6 path instead.
func (t *iptables) Start(ctx context.Context) error {
	if err := t.setup(ctx, t.v4); err != nil {
		return err
	}
	if err := t.setup(ctx, t.v6); err != nil {
		t.log.Warn("IPv6 firewall unavailable, IPv6 bans will be skipped",
			"binary", t.v6.bin, "err", err)
	}
	return nil
}

func (t *iptables) setup(ctx context.Context, x *xtables) error {
	x.setup = true
	x.wait = t.probeWait(ctx, x)

	// -N fails with "Chain already exists" on a restart; that is the normal
	// path, not an error.
	if _, err := t.exec(ctx, false, x.args("-t", "filter", "-N", chainName)...); err != nil {
		if !(ExitCode(err) > 0 && stderrContains(err, "chain already exists", "file exists")) {
			return fmt.Errorf("creating chain %s via %s: %w", chainName, x.bin, err)
		}
	}

	// -C is a question, not a command: a non-zero exit means "absent" and is
	// expected control flow, so it must never be propagated as an error.
	if _, err := t.exec(ctx, false, x.args("-t", "filter", "-C", "INPUT", "-j", chainName)...); err != nil {
		if ExitCode(err) <= 0 {
			return fmt.Errorf("checking INPUT jump via %s: %w", x.bin, err)
		}
		if _, err := t.exec(ctx, false, x.args("-t", "filter", "-I", "INPUT", "-j", chainName)...); err != nil {
			return fmt.Errorf("inserting INPUT jump via %s: %w", x.bin, err)
		}
		t.log.Info("installed INPUT jump", "binary", x.bin, "chain", chainName)
	}

	x.ok = true
	return nil
}

// probeWait asks the binary whether it understands --wait. Old iptables
// (< 1.4.20) does not, and passing it would break every command; new iptables
// without it fails spuriously whenever something else holds the xtables lock.
func (t *iptables) probeWait(ctx context.Context, x *xtables) bool {
	if _, err := t.exec(ctx, false, x.bin, "--wait", "-V"); err != nil {
		t.log.Info("binary does not support --wait, xtables lock contention may cause retries",
			"binary", x.bin)
		return false
	}
	return true
}

// args prefixes the binary and --wait (when supported) onto a command.
func (x *xtables) args(rest ...string) []string {
	argv := make([]string, 0, len(rest)+2)
	argv = append(argv, x.bin)
	if x.wait {
		argv = append(argv, "--wait")
	}
	return append(argv, rest...)
}

func (t *iptables) forFamily(b model.Ban) (*xtables, error) {
	x := t.v4
	if b.Family() == model.IPv6 {
		x = t.v6
	}
	if !x.setup {
		// Without Start the chain does not exist, so the command would fail
		// anyway; failing here says why instead of leaving a cryptic
		// "No chain/target/match by that name" in the log.
		return nil, fmt.Errorf("action: %s backend not started", x.bin)
	}
	if !x.ok {
		return nil, fmt.Errorf("%w: %s", ErrFamilyUnavailable, b.Family())
	}
	return x, nil
}

// Ban inserts a DROP for the address at the head of our chain.
func (t *iptables) Ban(ctx context.Context, b model.Ban) error {
	x, err := t.forFamily(b)
	if err != nil {
		return err
	}
	argv := x.args("-t", "filter", "-I", chainName, "-s", addrString(b), "-j", "DROP")
	if _, err := t.exec(ctx, false, argv...); err != nil {
		return fmt.Errorf("banning %s: %w", b.IP, err)
	}
	return nil
}

// Unban deletes the DROP. A missing rule (someone flushed the chain, or the
// box rebooted with our state file intact) is success: the desired end state
// already holds.
func (t *iptables) Unban(ctx context.Context, b model.Ban) error {
	x, err := t.forFamily(b)
	if err != nil {
		if errors.Is(err, ErrFamilyUnavailable) {
			// Nothing was ever installed for this family, so nothing to remove.
			return nil
		}
		return err
	}
	argv := x.args("-t", "filter", "-D", chainName, "-s", addrString(b), "-j", "DROP")
	if _, err := t.exec(ctx, false, argv...); err != nil {
		if ExitCode(err) > 0 && stderrContains(err, iptablesNotFound...) {
			t.log.Debug("unban: rule already absent", "ip", b.IP)
			return nil
		}
		return fmt.Errorf("unbanning %s: %w", b.IP, err)
	}
	return nil
}

// Stop intentionally leaves the chain and its rules in place: bans outlive the
// daemon (flush_on_exit defaults to false) and Start is idempotent.
func (t *iptables) Stop(context.Context) error { return nil }
