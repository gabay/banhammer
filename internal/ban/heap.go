package ban

import (
	"container/heap"
	"net/netip"
	"time"
)

// entry is one scheduled unban. index is maintained by the heap so that a ban
// whose Until moves (an extension) can be repaired in place with heap.Fix
// instead of being re-pushed, which would leave stale entries behind.
type entry struct {
	ip    netip.Addr
	until time.Time
	index int
}

// banHeap is a min-heap of pending unbans ordered by Until, with a side index
// so that lookup/extend/remove of a specific IP is O(1)/O(log n) rather than a
// linear scan. It holds *at most one entry per IP*: schedule() on an IP that is
// already present updates the existing entry, so the heap can never accumulate
// stale duplicates for a repeatedly extended ban.
//
// Not goroutine-safe; the Manager's mutex covers it.
type banHeap struct {
	items []*entry
	index map[netip.Addr]*entry
}

func newBanHeap() *banHeap {
	return &banHeap{index: make(map[netip.Addr]*entry)}
}

// The heap.Interface methods are implementation detail; callers use schedule,
// remove, peek and popHead instead.

func (h *banHeap) Len() int { return len(h.items) }

// Less orders by expiry only. Ties are broken arbitrarily (see the Manager doc
// comment: no ordering guarantee among bans sharing an Until).
func (h *banHeap) Less(i, j int) bool { return h.items[i].until.Before(h.items[j].until) }

func (h *banHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.items[i].index = i
	h.items[j].index = j
}

func (h *banHeap) Push(x any) {
	e := x.(*entry)
	e.index = len(h.items)
	h.items = append(h.items, e)
}

func (h *banHeap) Pop() any {
	old := h.items
	n := len(old)
	e := old[n-1]
	old[n-1] = nil // let the entry be collected
	e.index = -1
	h.items = old[:n-1]
	return e
}

// schedule inserts ip's unban deadline, or moves an existing one.
func (h *banHeap) schedule(ip netip.Addr, until time.Time) {
	if e, ok := h.index[ip]; ok {
		if e.until.Equal(until) {
			return
		}
		e.until = until
		heap.Fix(h, e.index)
		return
	}
	e := &entry{ip: ip, until: until}
	h.index[ip] = e
	heap.Push(h, e)
}

// remove drops ip's pending unban, if any.
func (h *banHeap) remove(ip netip.Addr) {
	e, ok := h.index[ip]
	if !ok {
		return
	}
	delete(h.index, ip)
	heap.Remove(h, e.index)
}

// peek returns the earliest pending unban without removing it.
func (h *banHeap) peek() (*entry, bool) {
	if len(h.items) == 0 {
		return nil, false
	}
	return h.items[0], true
}

// popHead removes and returns the earliest pending unban.
func (h *banHeap) popHead() (*entry, bool) {
	if len(h.items) == 0 {
		return nil, false
	}
	e := heap.Pop(h).(*entry)
	delete(h.index, e.ip)
	return e, true
}
