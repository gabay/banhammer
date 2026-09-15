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

	// Matched carries the log text (or pattern) that triggered the ban, for the
	// {matched} action template variable. It is attacker-controlled data: it
	// must never reach a shell, and consumers should treat it as untrusted and
	// bound its length. Empty when unknown, e.g. for a manual ban.
	Matched string `json:"matched,omitempty"`
}

// Expired reports whether the ban's term has elapsed as of now.
func (b Ban) Expired(now time.Time) bool { return !now.Before(b.Until) }

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
