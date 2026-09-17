package action

import (
	"context"
	"fmt"
	"strings"

	"banhammer/internal/model"
)

const (
	nftFamily = "inet"
	nftTable  = "banhammer"
	nftChain  = "input"
)

// nftExists is what nft says when an object is already there. For "add" that
// is success (we asked for the end state, and it holds).
//
// HEURISTIC: message text from nft 0.9.x/1.0.x under LC_ALL=C; nft exits 1 for
// every rule-processing error, so the text is the only discriminator.
var nftExists = []string{"file exists"}

// nftNotFound is what nft says when the element we are deleting is gone —
// someone flushed the set, or the host rebooted. Same version/locale caveat as
// nftExists.
var nftNotFound = []string{"no such file or directory", "does not exist"}

// nft is the nftables backend: one inet table with two address sets and a
// chain that drops anything in them. Same O(1) scaling story as ipset, with no
// iptables dependency at all.
//
// The sets deliberately have **no** timeout flag. internal/ban owns expiry and
// does not re-issue Ban when a ban is extended, so a kernel-side timeout would
// silently release an extended ban early.
type nft struct {
	base
	hook string
}

func newNFT(b base, chain string) *nft {
	hook := strings.ToLower(strings.TrimSpace(chain))
	if hook == "" {
		hook = nftChain
	}
	return &nft{base: b, hook: hook}
}

func (*nft) Name() string { return "nft" }

// Start creates the table, sets and chain, then adds the two lookup rules if
// they are not already present.
//
// "nft add" is idempotent for named objects but *not* for rules: adding the
// same rule twice appends a duplicate. So rules are guarded by listing the
// chain and looking for them, rather than blindly re-adding on every start.
func (n *nft) Start(ctx context.Context) error {
	steps := [][]string{
		{"nft", "add", "table", nftFamily, nftTable},
		{"nft", "add", "set", nftFamily, nftTable, setV4, "{ type ipv4_addr; }"},
		{"nft", "add", "set", nftFamily, nftTable, setV6, "{ type ipv6_addr; }"},
		{"nft", "add", "chain", nftFamily, nftTable, n.hook,
			fmt.Sprintf("{ type filter hook %s priority -10; policy accept; }", n.hook)},
	}
	for _, argv := range steps {
		if _, err := n.exec(ctx, false, argv...); err != nil {
			if ExitCode(err) > 0 && stderrContains(err, nftExists...) {
				continue
			}
			return fmt.Errorf("nft bootstrap (%s): %w", Quote(argv), err)
		}
	}

	listed, err := n.exec(ctx, false, "nft", "list", "chain", nftFamily, nftTable, n.hook)
	if err != nil {
		return fmt.Errorf("listing nft chain %s: %w", n.hook, err)
	}
	existing := string(listed)
	for _, r := range []struct{ proto, set string }{{"ip", setV4}, {"ip6", setV6}} {
		body := []string{r.proto, "saddr", "@" + r.set, "drop"}
		// HEURISTIC: nft has no "add this rule only if absent", so we match the
		// way nft 0.9.x/1.0.x renders the rule in `list chain`. If a future nft
		// prints it differently this check misses and Start appends a duplicate
		// rule on every daemon start (harmless for filtering, ugly in the
		// ruleset). Worth revisiting if nft ever grows a stable rule handle API.
		if strings.Contains(existing, strings.Join(body, " ")) {
			continue
		}
		argv := append([]string{"nft", "add", "rule", nftFamily, nftTable, n.hook}, body...)
		if _, err := n.exec(ctx, false, argv...); err != nil {
			return fmt.Errorf("adding nft rule (%s): %w", Quote(argv), err)
		}
		n.log.Info("installed nft rule", "hook", n.hook, "set", r.set)
	}
	return nil
}

func nftSet(b model.Ban) string {
	if b.Family() == model.IPv6 {
		return setV6
	}
	return setV4
}

// Ban adds the address to the set. A re-ban of an address already in the set
// reports "File exists"; that is the desired end state, so it counts as
// success rather than a failure the Executor would pointlessly retry — which
// is the normal path when Restore re-applies live bans after a restart.
func (n *nft) Ban(ctx context.Context, b model.Ban) error {
	argv := []string{"nft", "add", "element", nftFamily, nftTable, nftSet(b), "{ " + addrString(b) + " }"}
	if _, err := n.exec(ctx, false, argv...); err != nil {
		if ExitCode(err) > 0 && stderrContains(err, nftExists...) {
			return nil
		}
		return fmt.Errorf("adding %s to nft set: %w", b.IP, err)
	}
	return nil
}

// Unban deletes the element, tolerating one that is already gone.
func (n *nft) Unban(ctx context.Context, b model.Ban) error {
	argv := []string{"nft", "delete", "element", nftFamily, nftTable, nftSet(b), "{ " + addrString(b) + " }"}
	if _, err := n.exec(ctx, false, argv...); err != nil {
		if ExitCode(err) > 0 && stderrContains(err, nftNotFound...) {
			n.log.Debug("unban: nft element already absent", "ip", b.IP)
			return nil
		}
		return fmt.Errorf("deleting %s from nft set: %w", b.IP, err)
	}
	return nil
}

// Stop leaves the table in place so bans survive a restart.
func (n *nft) Stop(context.Context) error { return nil }
