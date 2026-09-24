package action

import (
	"context"
	"errors"
	"fmt"

	"banhammer/internal/model"
)

// Set names, one per family: ipset sets are single-family by construction.
const (
	setV4 = "banhammer4"
	setV6 = "banhammer6"
)

// ipsetNotFound covers "the entry/set is already gone", which for Unban means
// the work is done — the chain was flushed, the host rebooted, or an operator
// cleared the set by hand.
//
// HEURISTIC: strings observed on ipset 7.x under LC_ALL=C; ipset returns exit 1
// for both "missing element" and real kernel errors, so the message text is the
// only discriminator. A miss makes a benign unban look like a failure.
var ipsetNotFound = []string{
	"element is missing",
	"not added to the set",
	"the set with the given name does not exist",
	"no such file or directory",
}

// ipset is the scaling backend: one hash:ip set per family plus one static
// iptables rule each, so a ban is an O(1) kernel-side insert instead of a new
// rule.
//
// The sets deliberately carry **no** kernel-side timeout. internal/ban owns
// expiry, and it does not re-issue Ban when a ban is extended; a kernel
// timeout would be a second, unsynchronised expiry authority that silently
// released an extended ban early.
type ipset struct {
	base
	t *iptables // reused for the static match-set rules and the v6 degradation
}

func newIPSet(b base, chain string) *ipset {
	return &ipset{base: b, t: newIPTables(b, chain)}
}

func (*ipset) Name() string { return "ipset" }

// Start creates both sets and the two iptables rules that consult them.
func (s *ipset) Start(ctx context.Context) error {
	// -exist makes create idempotent, including across restarts where the set
	// already holds live bans (which we must not flush).
	if _, err := s.exec(ctx, false, "ipset", "-exist", "create", setV4, "hash:ip", "family", "inet"); err != nil {
		return fmt.Errorf("creating ipset %s: %w", setV4, err)
	}
	if err := s.matchRule(ctx, s.t.v4, setV4); err != nil {
		return err
	}

	if _, err := s.exec(ctx, false, "ipset", "-exist", "create", setV6, "hash:ip", "family", "inet6"); err != nil {
		s.log.Warn("IPv6 ipset unavailable, IPv6 bans will be skipped", "set", setV6, "err", err)
		return nil
	}
	if err := s.matchRule(ctx, s.t.v6, setV6); err != nil {
		s.log.Warn("IPv6 firewall unavailable, IPv6 bans will be skipped", "err", err)
	}
	return nil
}

// matchRule installs "-m set --match-set <set> src -j DROP" in s.t.chain once.
func (s *ipset) matchRule(ctx context.Context, x *xtables, set string) error {
	x.setup = true
	x.wait = s.t.probeWait(ctx, x)

	rule := []string{s.t.chain, "-m", "set", "--match-set", set, "src", "-j", "DROP"}
	check := append([]string{"-t", "filter", "-C"}, rule...)
	if _, err := s.exec(ctx, false, x.args(check...)...); err == nil {
		x.ok = true
		return nil
	} else if ExitCode(err) <= 0 {
		return fmt.Errorf("checking match-set rule via %s: %w", x.bin, err)
	}
	insert := append([]string{"-t", "filter", "-I"}, rule...)
	if _, err := s.exec(ctx, false, x.args(insert...)...); err != nil {
		return fmt.Errorf("inserting match-set rule via %s: %w", x.bin, err)
	}
	s.log.Info("installed match-set rule", "binary", x.bin, "chain", s.t.chain, "set", set)
	x.ok = true
	return nil
}

func (s *ipset) setFor(b model.Ban) (string, error) {
	if b.Family() == model.IPv6 {
		if !s.t.v6.ok {
			return "", fmt.Errorf("%w: %s", ErrFamilyUnavailable, b.Family())
		}
		return setV6, nil
	}
	return setV4, nil
}

// Ban adds the address to the set. -exist makes a re-ban a no-op instead of an
// "element already added" error, which matters because Restore re-applies
// every live ban on each daemon start — "already present" is the normal case.
func (s *ipset) Ban(ctx context.Context, b model.Ban) error {
	set, err := s.setFor(b)
	if err != nil {
		return err
	}
	argv := []string{"ipset", "-exist", "add", set, addrString(b)}
	if _, err := s.exec(ctx, false, argv...); err != nil {
		return fmt.Errorf("adding %s to %s: %w", b.IP, set, err)
	}
	return nil
}

// Unban deletes the element. If it is already gone (flushed set, reboot,
// manual ipset del) that is success: the desired end state already holds.
func (s *ipset) Unban(ctx context.Context, b model.Ban) error {
	set, err := s.setFor(b)
	if err != nil {
		return nil // family never installed: nothing to remove
	}
	argv := []string{"ipset", "-exist", "del", set, addrString(b)}
	if _, err := s.exec(ctx, false, argv...); err != nil {
		if ExitCode(err) > 0 && stderrContains(err, ipsetNotFound...) {
			s.log.Debug("unban: ipset entry already absent", "ip", b.IP, "set", set)
			return nil
		}
		return fmt.Errorf("deleting %s from %s: %w", b.IP, set, err)
	}
	return nil
}

// Stop leaves the sets populated by default; bans survive a restart by
// design. When flush_on_exit is set it removes the match-set rules it
// installed and destroys both sets.
func (s *ipset) Stop(ctx context.Context) error {
	if !s.flushOnExit {
		return nil
	}
	var errs []error
	for _, f := range []struct {
		x   *xtables
		set string
	}{{s.t.v4, setV4}, {s.t.v6, setV6}} {
		if f.x.ok {
			if err := s.removeMatchRule(ctx, f.x, f.set); err != nil {
				errs = append(errs, err)
			}
		}
		if _, err := s.exec(ctx, false, "ipset", "destroy", f.set); err != nil {
			if !(ExitCode(err) > 0 && stderrContains(err, ipsetNotFound...)) {
				errs = append(errs, fmt.Errorf("destroying ipset %s: %w", f.set, err))
			}
		}
	}
	return errors.Join(errs...)
}

// removeMatchRule undoes matchRule: delete the "-m set --match-set" rule this
// backend installed. A rule already gone is not an error.
func (s *ipset) removeMatchRule(ctx context.Context, x *xtables, set string) error {
	rule := []string{s.t.chain, "-m", "set", "--match-set", set, "src", "-j", "DROP"}
	argv := append([]string{"-t", "filter", "-D"}, rule...)
	if _, err := s.exec(ctx, false, x.args(argv...)...); err != nil {
		if ExitCode(err) > 0 && stderrContains(err, iptablesNotFound...) {
			return nil
		}
		return fmt.Errorf("removing match-set rule via %s: %w", x.bin, err)
	}
	s.log.Info("removed match-set rule", "binary", x.bin, "chain", s.t.chain, "set", set)
	return nil
}
