// Package model holds the small set of types shared across Banhammer's
// packages. It exists to keep source, store, ban and action decoupled from one
// another (and free of import cycles); it must never import any other
// banhammer package.
package model

import (
	"net/netip"
	"time"
)

// Event is a single log line handed from a Source into the pipeline.
//
// Raw may reference a reader's internal buffer and is only valid until the
// consumer returns; anything retaining it past that must copy it first.
type Event struct {
	Monitor string
	Raw     []byte
	Recv    time.Time
}

// Checkpoint records how far a Source has consumed a given file, so that a
// restart resumes instead of replaying history.
type Checkpoint struct {
	Path   string `json:"path"`
	Dev    uint64 `json:"dev"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// SameFile reports whether c and other refer to the same underlying file,
// which is how rotation is detected: a rotated log keeps its path but changes
// its inode.
func (c Checkpoint) SameFile(other Checkpoint) bool {
	return c.Dev == other.Dev && c.Inode == other.Inode
}

// Ban is one active or historical ban of a single address.
type Ban struct {
	IP      netip.Addr `json:"ip"`
	Monitor string     `json:"monitor"`
	At      time.Time  `json:"at"`
	Until   time.Time  `json:"until"`
	Count   int        `json:"count"`   // hits that triggered this ban
	Offense int        `json:"offense"` // 1 for a first offense, n for the nth

	// Matched names the rule that triggered the ban — the operator-written
	// pattern from the monitor's config, not the log line itself — and feeds
	// the {matched} action template variable.
	//
	// Raw log text is deliberately NOT stored here: it is attacker-controlled,
	// it would be persisted verbatim to bans.json, and it would be pasted into
	// a command line. Empty when there is no rule, e.g. for a manual ban.
	Matched string `json:"matched,omitempty"`
}

// Expired reports whether the ban's term has elapsed as of now.
func (b Ban) Expired(now time.Time) bool { return !now.Before(b.Until) }

// BanEvent is the durable record that a ban was issued: who, by which monitor,
// and when. It is what the statistics ledger keeps once the ban itself has
// expired and been forgotten by the ban manager.
//
// It is deliberately a projection of Ban rather than the Ban itself: a ledger
// entry lives for weeks, so every field costs memory for weeks, and nothing a
// statistic needs is lost by dropping the expiry and the hit count.
type BanEvent struct {
	IP      netip.Addr `json:"ip"`
	Monitor string     `json:"monitor"`
	At      time.Time  `json:"at"`

	// Line is the log line that crossed the threshold, or "" when there is
	// none (a manual ban, capture disabled, or an old event whose line was
	// dropped to stay within the ledger's byte budget).
	//
	// This is the one place attacker-written text is kept, and it is kept
	// here rather than on Ban on purpose: Ban is substituted into command
	// templates, a BanEvent only ever reaches a display. The ledger
	// sanitises the line to printable UTF-8 and bounds its length before
	// storing it, so a consumer may print it, but should still treat it as
	// data, never as markup or as a command.
	Line string `json:"line,omitempty"`
}

// Event converts a ban into its ledger record.
func (b Ban) Event() BanEvent {
	return BanEvent{IP: b.IP, Monitor: b.Monitor, At: b.At}
}

// Family returns the address family of the banned IP, as used to pick between
// iptables and ip6tables.
func (b Ban) Family() Family {
	if b.IP.Is4() || b.IP.Is4In6() {
		return IPv4
	}
	return IPv6
}

// Family distinguishes the two IP versions throughout the firewall layer.
type Family int

const (
	IPv4 Family = iota
	IPv6
)

func (f Family) String() string {
	if f == IPv6 {
		return "inet6"
	}
	return "inet"
}
