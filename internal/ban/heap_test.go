package ban

import (
	"net/netip"
	"testing"
	"time"
)

func TestBanHeapOrdering(t *testing.T) {
	t.Parallel()
	h := newBanHeap()
	ips := []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}
	for i, s := range ips {
		// Insert out of order: 3 expires last, 1 first.
		h.schedule(netip.MustParseAddr(s), epoch.Add(time.Duration(len(ips)-i)*time.Minute))
	}
	if h.Len() != 3 {
		t.Fatalf("Len = %d, want 3", h.Len())
	}
	var got []string
	for {
		e, ok := h.popHead()
		if !ok {
			break
		}
		got = append(got, e.ip.String())
	}
	want := []string{"10.0.0.2", "10.0.0.1", "10.0.0.3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pop order = %v, want %v", got, want)
		}
	}
	if _, ok := h.peek(); ok {
		t.Error("peek on an empty heap reported an entry")
	}
	if _, ok := h.popHead(); ok {
		t.Error("popHead on an empty heap reported an entry")
	}
}

// TestBanHeapExtendInPlace is the anti-stale-entry guarantee: re-scheduling an
// IP must move its existing entry, never add a second one.
func TestBanHeapExtendInPlace(t *testing.T) {
	t.Parallel()
	h := newBanHeap()
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	h.schedule(a, epoch.Add(time.Minute))
	h.schedule(b, epoch.Add(2*time.Minute))
	for i := range 100 {
		h.schedule(a, epoch.Add(time.Duration(i+3)*time.Minute))
	}
	if h.Len() != 2 {
		t.Fatalf("Len = %d after 100 extensions, want 2", h.Len())
	}
	head, _ := h.peek()
	if head.ip != b {
		t.Errorf("head = %v, want %v after a was pushed past it", head.ip, b)
	}
	// Extending backwards (shortening) must also be honoured.
	h.schedule(a, epoch)
	head, _ = h.peek()
	if head.ip != a {
		t.Errorf("head = %v, want %v after a was pulled forward", head.ip, a)
	}
}

func TestBanHeapRemove(t *testing.T) {
	t.Parallel()
	h := newBanHeap()
	a := netip.MustParseAddr("10.0.0.1")
	b := netip.MustParseAddr("10.0.0.2")
	h.schedule(a, epoch.Add(time.Minute))
	h.schedule(b, epoch.Add(2*time.Minute))
	h.remove(a)
	h.remove(a) // removing twice must be harmless
	h.remove(netip.MustParseAddr("10.0.0.9"))
	if h.Len() != 1 {
		t.Fatalf("Len = %d, want 1", h.Len())
	}
	head, _ := h.peek()
	if head.ip != b {
		t.Errorf("head = %v, want %v", head.ip, b)
	}
	if _, ok := h.index[a]; ok {
		t.Error("removed entry still present in the index")
	}
}

// TestBanHeapInvariant hammers the heap with a mixed workload and checks that
// pops come out in non-decreasing order and the index stays consistent.
func TestBanHeapInvariant(t *testing.T) {
	t.Parallel()
	h := newBanHeap()
	const n = 500
	for i := range n {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		h.schedule(ip, epoch.Add(time.Duration((i*7919)%n)*time.Second))
	}
	for i := range n / 2 { // reschedule half of them
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		h.schedule(ip, epoch.Add(time.Duration((i*104729)%n)*time.Second))
	}
	if h.Len() != n {
		t.Fatalf("Len = %d, want %d", h.Len(), n)
	}
	prev := time.Time{}
	for {
		e, ok := h.popHead()
		if !ok {
			break
		}
		if e.until.Before(prev) {
			t.Fatalf("pop out of order: %v before %v", e.until, prev)
		}
		prev = e.until
	}
	if len(h.index) != 0 {
		t.Errorf("index has %d leftovers after draining", len(h.index))
	}
}
