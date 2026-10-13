package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test-only MMDB encoder -------------------------------------------------
//
// Nothing can be downloaded in tests, so a minimal writer for the MaxMind DB
// format lives here. It produces a tree with the given record size, a data
// section with one country record per distinct country (the "iso_code" key
// is a pointer to a shared string so the pointer path is exercised), the
// 16-byte separator and a metadata block.

type mmEntry struct {
	prefix netip.Prefix
	cc     string
	// registeredOnly emits registered_country instead of country, which is
	// what GeoLite2 does for addresses whose location is unknown.
	registeredOnly bool
}

type mmRecord struct {
	child *mmNode
	data  int // offset into the data section, -1 for none
}

type mmNode struct {
	rec   [2]mmRecord
	index uint32
}

type mmBuilder struct {
	recordSize int
	ipVersion  int
	major      int
	root       *mmNode
	nodeCount  uint32
	data       []byte
	dataOffset map[string]int
}

func newMMNode() *mmNode {
	return &mmNode{rec: [2]mmRecord{{data: -1}, {data: -1}}}
}

func newMMBuilder(recordSize, ipVersion int, entries []mmEntry) *mmBuilder {
	b := &mmBuilder{
		recordSize: recordSize,
		ipVersion:  ipVersion,
		major:      2,
		root:       newMMNode(),
		dataOffset: map[string]int{},
	}
	// Shared string at offset 0, referenced by pointer from every record.
	b.data = encString("iso_code")
	for _, e := range entries {
		b.insert(e)
	}
	b.number(b.root)
	return b
}

func (b *mmBuilder) recordFor(e mmEntry) int {
	key := e.cc
	if e.registeredOnly {
		key += "/registered"
	}
	if off, ok := b.dataOffset[key]; ok {
		return off
	}
	outer := "country"
	if e.registeredOnly {
		outer = "registered_country"
	}
	var rec []byte
	rec = append(rec, encMapHeader(1)...)
	rec = append(rec, encString(outer)...)
	rec = append(rec, encMapHeader(2)...)
	rec = append(rec, encPointer(0)...) // "iso_code"
	rec = append(rec, encString(e.cc)...)
	rec = append(rec, encString("names")...)
	rec = append(rec, encMapHeader(1)...)
	rec = append(rec, encString("en")...)
	rec = append(rec, encString(Name(e.cc))...)
	off := len(b.data)
	b.data = append(b.data, rec...)
	b.dataOffset[key] = off
	return off
}

func (b *mmBuilder) insert(e mmEntry) {
	addr := e.prefix.Addr()
	var bits [16]byte
	length := e.prefix.Bits()
	switch {
	case addr.Is4() && b.ipVersion == 6:
		a4 := addr.As4()
		copy(bits[12:], a4[:])
		length += 96
	case addr.Is4():
		a4 := addr.As4()
		copy(bits[:], a4[:])
	default:
		bits = addr.As16()
	}
	off := b.recordFor(e)
	cur := b.root
	for i := 0; i < length-1; i++ {
		bit := int(bits[i/8]>>(7-uint(i%8))) & 1
		r := &cur.rec[bit]
		if r.child == nil {
			r.child = newMMNode()
			if r.data >= 0 {
				// A shorter prefix already covers this subtree; push its
				// data down so the longer prefix can carve out its piece.
				r.child.rec[0].data = r.data
				r.child.rec[1].data = r.data
				r.data = -1
			}
		}
		cur = r.child
	}
	last := int(bits[(length-1)/8]>>(7-uint((length-1)%8))) & 1
	cur.rec[last] = mmRecord{data: off}
}

func (b *mmBuilder) number(n *mmNode) {
	n.index = b.nodeCount
	b.nodeCount++
	for _, r := range n.rec {
		if r.child != nil {
			b.number(r.child)
		}
	}
}

func (b *mmBuilder) recordValue(r mmRecord) uint32 {
	switch {
	case r.child != nil:
		return r.child.index
	case r.data >= 0:
		return b.nodeCount + dataSeparatorLen + uint32(r.data)
	}
	return b.nodeCount
}

func (b *mmBuilder) writeTree(n *mmNode, out *[]byte) {
	l, r := b.recordValue(n.rec[0]), b.recordValue(n.rec[1])
	switch b.recordSize {
	case 24:
		*out = append(*out, byte(l>>16), byte(l>>8), byte(l), byte(r>>16), byte(r>>8), byte(r))
	case 28:
		*out = append(*out, byte(l>>16), byte(l>>8), byte(l), byte(l>>24)<<4|byte(r>>24)&0x0f, byte(r>>16), byte(r>>8), byte(r))
	case 32:
		*out = binary.BigEndian.AppendUint32(*out, l)
		*out = binary.BigEndian.AppendUint32(*out, r)
	}
	for _, rec := range n.rec {
		if rec.child != nil {
			b.writeTree(rec.child, out)
		}
	}
}

func (b *mmBuilder) bytes() []byte {
	var out []byte
	b.writeTree(b.root, &out)
	out = append(out, make([]byte, dataSeparatorLen)...)
	out = append(out, b.data...)
	out = append(out, metadataMarker...)
	out = append(out, encMapHeader(7)...)
	out = append(out, encString("binary_format_major_version")...)
	out = append(out, encUint(5, uint64(b.major))...)
	out = append(out, encString("binary_format_minor_version")...)
	out = append(out, encUint(5, 0)...)
	out = append(out, encString("build_epoch")...)
	out = append(out, encUint(9, 1700000000)...)
	out = append(out, encString("database_type")...)
	out = append(out, encString("Test-Country")...)
	out = append(out, encString("ip_version")...)
	out = append(out, encUint(5, uint64(b.ipVersion))...)
	out = append(out, encString("node_count")...)
	out = append(out, encUint(6, uint64(b.nodeCount))...)
	out = append(out, encString("record_size")...)
	out = append(out, encUint(5, uint64(b.recordSize))...)
	return out
}

func encCtrl(typ, size int) []byte {
	var out []byte
	var sizeBits int
	var extra []byte
	switch {
	case size < 29:
		sizeBits = size
	case size < 285:
		sizeBits, extra = 29, []byte{byte(size - 29)}
	case size < 65821:
		sizeBits, extra = 30, binary.BigEndian.AppendUint16(nil, uint16(size-285))
	default:
		n := size - 65821
		sizeBits, extra = 31, []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	}
	if typ <= 7 {
		out = append(out, byte(typ<<5|sizeBits))
	} else {
		out = append(out, byte(sizeBits), byte(typ-7))
	}
	return append(out, extra...)
}

func encString(s string) []byte { return append(encCtrl(2, len(s)), s...) }

func encMapHeader(n int) []byte { return encCtrl(7, n) }

func encUint(typ int, v uint64) []byte {
	var payload []byte
	for v > 0 {
		payload = append([]byte{byte(v)}, payload...)
		v >>= 8
	}
	return append(encCtrl(typ, len(payload)), payload...)
}

// encPointer picks the smallest of the four pointer encodings for target.
func encPointer(target int) []byte {
	switch {
	case target < 1<<11:
		return []byte{0x20 | byte(target>>8), byte(target)}
	case target-2048 < 1<<19:
		v := target - 2048
		return []byte{0x28 | byte(v>>16), byte(v >> 8), byte(v)}
	case target-526336 < 1<<27:
		v := target - 526336
		return []byte{0x30 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return append([]byte{0x38}, binary.BigEndian.AppendUint32(nil, uint32(target))...)
}

// --- tests ------------------------------------------------------------------

var testEntries = []mmEntry{
	{prefix: netip.MustParsePrefix("1.0.0.0/24"), cc: "AU"},
	{prefix: netip.MustParsePrefix("10.0.0.0/8"), cc: "DE"},
	{prefix: netip.MustParsePrefix("10.1.0.0/16"), cc: "FR"}, // carved out of DE
	{prefix: netip.MustParsePrefix("192.168.1.128/25"), cc: "US"},
	{prefix: netip.MustParsePrefix("203.0.113.7/32"), cc: "JP"},
	{prefix: netip.MustParsePrefix("2001:db8::/32"), cc: "DE"}, // shares DE record
	{prefix: netip.MustParsePrefix("2a00::/12"), cc: "NL", registeredOnly: true},
}

var lookupCases = []struct {
	name string
	ip   string
	want string
	ok   bool
}{
	{"v4 hit", "1.0.0.1", "AU", true},
	{"v4 first address of prefix", "1.0.0.0", "AU", true},
	{"v4 last address of prefix", "1.0.0.255", "AU", true},
	{"v4 just past prefix", "1.0.1.0", "", false},
	{"v4 just before prefix", "0.255.255.255", "", false},
	{"v4 broad prefix", "10.200.3.4", "DE", true},
	{"v4 nested prefix wins", "10.1.2.3", "FR", true},
	{"v4 nested prefix boundary", "10.2.0.0", "DE", true},
	{"v4 offset prefix", "192.168.1.200", "US", true},
	{"v4 offset prefix miss low half", "192.168.1.127", "", false},
	{"v4 host route", "203.0.113.7", "JP", true},
	{"v4 host route neighbour", "203.0.113.8", "", false},
	{"v4-mapped v6 input", "::ffff:1.0.0.1", "AU", true},
	{"v6 hit", "2001:db8::1", "DE", true},
	{"v6 last address", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "DE", true},
	{"v6 miss", "2001:db9::1", "", false},
	{"v6 registered_country fallback", "2a01::1", "NL", true},
	{"loopback", "::1", "", false},
	{"unspecified v6", "::", "", false},
	{"unspecified v4", "0.0.0.0", "", false},
	// The spec places IPv4 at ::/96 in an IPv6 tree, so the IPv4-compatible
	// form resolves too; that is a property of the format, not a bug.
	{"v4-compatible v6 input", "::1.0.0.1", "AU", true},
}

func TestMMDBLookup(t *testing.T) {
	t.Parallel()
	for _, rs := range []int{24, 28, 32} {
		b := newMMBuilder(rs, 6, testEntries)
		db, err := parseMMDB(b.bytes())
		if err != nil {
			t.Fatalf("record size %d: parse: %v", rs, err)
		}
		for _, tc := range lookupCases {
			got, ok := db.Country(netip.MustParseAddr(tc.ip))
			if got != tc.want || ok != tc.ok {
				t.Errorf("record size %d: %s: Country(%s) = %q,%v; want %q,%v", rs, tc.name, tc.ip, got, ok, tc.want, tc.ok)
			}
		}
	}
}

func TestMMDBIPv4Tree(t *testing.T) {
	t.Parallel()
	var v4 []mmEntry
	for _, e := range testEntries {
		if e.prefix.Addr().Is4() {
			v4 = append(v4, e)
		}
	}
	db, err := parseMMDB(newMMBuilder(28, 4, v4).bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range lookupCases {
		ip := netip.MustParseAddr(tc.ip)
		want, wantOK := tc.want, tc.ok
		if ip.Unmap().Is6() {
			want, wantOK = "", false // no IPv6 in a v4 tree
		}
		got, ok := db.Country(ip)
		if got != want || ok != wantOK {
			t.Errorf("%s: Country(%s) = %q,%v; want %q,%v", tc.name, tc.ip, got, ok, want, wantOK)
		}
	}
}

func TestMMDBNoIPv4Prefixes(t *testing.T) {
	t.Parallel()
	db, err := parseMMDB(newMMBuilder(28, 6, testEntries[5:]).bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := db.Country(netip.MustParseAddr("1.0.0.1")); ok {
		t.Errorf("Country(1.0.0.1) = %q,true; want miss", got)
	}
	if got, ok := db.Country(netip.MustParseAddr("2001:db8::1")); !ok || got != "DE" {
		t.Errorf("Country(2001:db8::1) = %q,%v; want DE,true", got, ok)
	}
}

func TestMMDBNeverPanics(t *testing.T) {
	t.Parallel()
	db, err := parseMMDB(newMMBuilder(28, 6, testEntries).bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{
		{},
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("::ffff:10.1.2.3").WithZone("x"),
		netip.AddrFrom16([16]byte{0xff}),
	} {
		db.Country(ip) // must not panic
	}
	if got, ok := db.Country(netip.MustParseAddr("::ffff:10.1.2.3").WithZone("x")); !ok || got != "FR" {
		t.Errorf("zoned v4-mapped lookup = %q,%v; want FR,true", got, ok)
	}
}

func TestMMDBConcurrent(t *testing.T) {
	t.Parallel()
	db, err := parseMMDB(newMMBuilder(28, 6, testEntries).bytes())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tc := range lookupCases {
				got, ok := db.Country(netip.MustParseAddr(tc.ip))
				if got != tc.want || ok != tc.ok {
					t.Errorf("%s: got %q,%v", tc.name, got, ok)
				}
			}
		}()
	}
	wg.Wait()
}

func TestMMDBMalformed(t *testing.T) {
	t.Parallel()
	good := newMMBuilder(28, 6, testEntries).bytes()
	markerAt := bytes.LastIndex(good, metadataMarker)
	tests := []struct {
		name    string
		buf     func() []byte
		wantErr string
	}{
		{"empty", func() []byte { return nil }, "metadata marker"},
		{"truncated before marker", func() []byte { return good[:len(good)/2] }, "metadata marker"},
		{"metadata only, tree missing", func() []byte { return good[markerAt:] }, "does not fit"},
		{"metadata truncated", func() []byte { return good[:len(good)-3] }, "decode metadata"},
		{"wrong major version", func() []byte {
			b := newMMBuilder(28, 6, testEntries)
			b.major = 3
			return b.bytes()
		}, "major version 3"},
		{"not a map", func() []byte {
			return append(append([]byte(nil), metadataMarker...), encString("hi")...)
		}, "not a map"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMMDB(tc.buf())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestMMDBPointerLoop replaces the data section with a pointer to itself; the
// lookup must come back empty rather than spin.
func TestMMDBPointerLoop(t *testing.T) {
	t.Parallel()
	b := newMMBuilder(28, 6, []mmEntry{{prefix: netip.MustParsePrefix("1.0.0.0/24"), cc: "AU"}})
	// Every tree record points at offset len("iso_code" string) == the record;
	// overwrite the record with a self-pointer, keeping the length.
	off := b.dataOffset["AU"]
	loop := encPointer(off)
	copy(b.data[off:], loop)
	db, err := parseMMDB(b.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := db.Country(netip.MustParseAddr("1.0.0.1")); ok {
		t.Errorf("Country = %q,true; want miss on looping pointer", got)
	}
	// And a record that is not a map at all.
	copy(b.data[off:], encString("x"))
	db, err = parseMMDB(b.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := db.Country(netip.MustParseAddr("1.0.0.1")); ok {
		t.Errorf("Country = %q,true; want miss on non-map record", got)
	}
}

func TestDecoderValues(t *testing.T) {
	t.Parallel()
	// Pointer targets: a string at offset 0 so pointer encodings have
	// something to land on. fwd pads the data so that a pointer placed after
	// the padding must use a larger encoding to reach a string after itself.
	str := encString("target")
	str = str[:len(str):len(str)] // appends below must copy, not alias
	pad := func(n int) []byte { return append(encCtrl(4, n), make([]byte, n)...) }
	fwd := func(padN int) ([]byte, int) {
		data := append(append([]byte(nil), str...), pad(padN)...)
		off := len(data)
		p := encPointer(off + len(encPointer(off)))
		return append(append(data, p...), str...), off
	}
	fwd1, off1 := fwd(2048)
	fwd2, off2 := fwd(526336)
	tests := []struct {
		name string
		data []byte
		off  int
		want any
		err  string
	}{
		{"uint16", encUint(5, 0xbeef), 0, uint64(0xbeef), ""},
		{"uint32", encUint(6, 0xdeadbeef), 0, uint64(0xdeadbeef), ""},
		{"uint64", encUint(9, 1<<40), 0, uint64(1 << 40), ""},
		{"uint zero", encUint(6, 0), 0, uint64(0), ""},
		{"int32 negative", append(encCtrl(8, 4), 0xff, 0xff, 0xff, 0xfe), 0, int32(-2), ""},
		{"double", append(encCtrl(3, 8), 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18), 0, 3.141592653589793, ""},
		{"float", append(encCtrl(15, 4), 0x3f, 0x80, 0, 0), 0, float32(1), ""},
		{"bool true", encCtrl(14, 1), 0, true, ""},
		{"bool false", encCtrl(14, 0), 0, false, ""},
		{"bytes", append(encCtrl(4, 2), 1, 2), 0, []byte{1, 2}, ""},
		{"uint128", append(encCtrl(10, 1), 9), 0, []byte{9}, ""},
		{"long string (29+)", encString(strings.Repeat("a", 100)), 0, strings.Repeat("a", 100), ""},
		{"longer string (285+)", encString(strings.Repeat("b", 300)), 0, strings.Repeat("b", 300), ""},
		{"longest string (65821+)", encString(strings.Repeat("c", 70000)), 0, strings.Repeat("c", 70000), ""},
		{"array", append(append(encCtrl(11, 2), encString("a")...), encUint(5, 1)...), 0, []any{"a", uint64(1)}, ""},
		{"map", append(append(encMapHeader(1), encString("k")...), encString("v")...), 0, map[string]any{"k": "v"}, ""},
		{"pointer size 0", append(str, encPointer(0)...), len(str), "target", ""},
		{"pointer size 1", fwd1, off1, "target", ""},
		{"pointer size 2", fwd2, off2, "target", ""},
		// Size-3 pointers are absolute, so a non-minimal one can reach 0.
		{"pointer size 3", append(str, 0x38, 0, 0, 0, 0), len(str), "target", ""},
		{"pointer to pointer", append(append(str, encPointer(0)...), encPointer(len(str))...), len(str) + 2, "target", ""},
		{"pointer loop", encPointer(0), 0, nil, "pointer chain"},
		{"pointer out of range", encPointer(500), 0, nil, "truncated"},
		{"truncated payload", encCtrl(2, 5), 0, nil, "truncated"},
		{"truncated control", nil, 0, nil, "truncated"},
		{"offset past end", encString("x"), 10, nil, "truncated"},
		{"map key not string", append(append(encMapHeader(1), encUint(5, 1)...), encString("v")...), 0, nil, "not a string"},
		{"cache container", encCtrl(12, 0), 0, nil, "cache container"},
		{"end marker", encCtrl(13, 0), 0, nil, "end marker"},
		{"oversized uint", append(encCtrl(9, 9), make([]byte, 9)...), 0, nil, "size 9"},
		{"unknown type", encCtrl(20, 0), 0, nil, "unknown data type"},
		{"too deep", bytes.Repeat(encCtrl(11, 1), maxDecodeDepth+2), 0, nil, "too deeply"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := decoder{data: tc.data}
			got, _, err := dec.decode(tc.off, 0, 0)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v; want containing %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalAny(got, tc.want) {
				t.Fatalf("got %#v; want %#v", got, tc.want)
			}
		})
	}
}

func equalAny(a, b any) bool {
	switch x := a.(type) {
	case []byte:
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalAny(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if !equalAny(v, y[k]) {
				return false
			}
		}
		return true
	}
	return a == b
}

func TestOpenMMDB(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, newMMBuilder(28, 6, testEntries).bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := db.Country(netip.MustParseAddr("10.1.2.3")); !ok || got != "FR" {
		t.Errorf("Country = %q,%v; want FR,true", got, ok)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	_, err = Open(filepath.Join(dir, "missing.mmdb"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open missing: err = %v; want ErrNotExist", err)
	}
	if err != nil && !strings.Contains(err.Error(), "missing.mmdb") {
		t.Errorf("Open missing: error %q should name the path", err)
	}

	bad := filepath.Join(dir, "bad.MMDB")
	if err := os.WriteFile(bad, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); err == nil || !strings.Contains(err.Error(), "metadata marker") {
		t.Errorf("Open garbage: err = %v; want metadata marker error", err)
	}
}

// TestDecoderSharedPointers is the regression test for the hop cap: MaxMind's
// writer deduplicates every string and sub-map, so a real GeoLite2 record is
// reached through dozens of *independent* pointers. Those must not add up to
// a "chain". MaxMind's own test databases need ~60 pointers per record; this
// uses 200 to leave no doubt.
func TestDecoderSharedPointers(t *testing.T) {
	t.Parallel()
	const n = 200
	str := encString("shared")
	data := append([]byte(nil), str...)
	start := len(data)
	data = append(data, encCtrl(11, n)...) // array of n pointers to the one string
	for range n {
		data = append(data, encPointer(0)...)
	}
	dec := decoder{data: data}
	got, _, err := dec.decode(start, 0, 0)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr, ok := got.([]any)
	if !ok || len(arr) != n || arr[0] != "shared" || arr[n-1] != "shared" {
		t.Fatalf("got %T len %d", got, len(arr))
	}
}

// TestDecoderFanOutBomb: a map whose two values both point back at the map
// itself is legal TLV, and within the depth limit alone it would cost 2^32
// decodes. The per-record value budget must cut it off.
func TestDecoderFanOutBomb(t *testing.T) {
	t.Parallel()
	// map(2) { "a": ptr(0), "b": ptr(0) } at offset 0.
	data := encMapHeader(2)
	data = append(data, encString("a")...)
	data = append(data, encPointer(0)...)
	data = append(data, encString("b")...)
	data = append(data, encPointer(0)...)
	dec := decoder{data: data}
	done := make(chan error, 1)
	go func() {
		_, _, err := dec.decode(0, 0, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a self-referential map decoded successfully")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("decoder did not give up on a fan-out bomb")
	}
}

// TestDecoderSizeHintClamped: a map header claiming 16M entries in a 4-byte
// file must not allocate for 16M entries before failing.
func TestDecoderSizeHintClamped(t *testing.T) {
	t.Parallel()
	data := append(encCtrl(7, 31), 0xff, 0xff, 0xff) // size = 65821 + 2^24-1
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	dec := decoder{data: data}
	if _, _, err := dec.decode(0, 0, 0); err == nil {
		t.Fatal("expected an error")
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("decoding a 4-byte file allocated %d bytes", grew)
	}
}
