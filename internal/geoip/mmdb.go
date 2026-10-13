package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
)

// MaxMind DB on-disk layout (https://maxmind.github.io/MaxMind-DB/):
//
//	[search tree][16 zero bytes][data section][metadata marker][metadata map]
//
// The tree is a binary trie over address bits; each node holds two records of
// record_size bits. A record either names another node, says "not found"
// (== node_count) or points into the data section. Data is a self-describing
// type-length-value encoding that may contain pointers back into itself.

var metadataMarker = []byte("\xab\xcd\xefMaxMind.com")

const (
	// The spec guarantees the metadata lives within the last 128 KiB.
	metadataSearchWindow = 128 << 10
	dataSeparatorLen     = 16
	// Deeply nested data is a sign of a malicious or corrupt file, not a
	// country record; a country record is three maps deep.
	maxDecodeDepth = 32
)

type mmdbDB struct {
	buf        []byte
	nodeCount  uint32
	recordSize uint32
	ipVersion  uint32
	treeSize   int
	// data is the data section (buf after the tree and separator); pointers
	// are resolved relative to it.
	data []byte
	// ipv4Start is the node reached after 96 zero bits in an IPv6 tree, so
	// IPv4 lookups skip straight to it instead of walking 96 nodes each time.
	ipv4Start uint32
}

func openMMDB(path string) (*mmdbDB, error) {
	buf, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return parseMMDB(buf)
}

func parseMMDB(buf []byte) (*mmdbDB, error) {
	from := len(buf) - metadataSearchWindow
	if from < 0 {
		from = 0
	}
	idx := bytes.LastIndex(buf[from:], metadataMarker)
	if idx < 0 {
		return nil, errors.New("metadata marker not found; not a MaxMind DB file")
	}
	metaStart := from + idx + len(metadataMarker)
	// Metadata has no pointers, so decode it against itself.
	dec := decoder{data: buf[metaStart:]}
	v, _, err := dec.decode(0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	meta, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("metadata is not a map")
	}
	major, _ := asUint(meta["binary_format_major_version"])
	if major != 2 {
		return nil, fmt.Errorf("unsupported binary format major version %d (want 2)", major)
	}
	db := &mmdbDB{buf: buf}
	if db.nodeCount, ok = asUint(meta["node_count"]); !ok || db.nodeCount == 0 {
		return nil, errors.New("metadata: missing or zero node_count")
	}
	if db.recordSize, ok = asUint(meta["record_size"]); !ok {
		return nil, errors.New("metadata: missing record_size")
	}
	switch db.recordSize {
	case 24, 28, 32:
	default:
		return nil, fmt.Errorf("metadata: unsupported record_size %d", db.recordSize)
	}
	if db.ipVersion, ok = asUint(meta["ip_version"]); !ok || (db.ipVersion != 4 && db.ipVersion != 6) {
		return nil, fmt.Errorf("metadata: unsupported ip_version %v", meta["ip_version"])
	}
	treeSize := uint64(db.nodeCount) * uint64(db.recordSize) / 4 // two records per node, bits/8
	if treeSize+dataSeparatorLen > uint64(metaStart-len(metadataMarker)) {
		return nil, fmt.Errorf("search tree (%d bytes) does not fit in file", treeSize)
	}
	db.treeSize = int(treeSize)
	db.data = buf[db.treeSize+dataSeparatorLen : metaStart-len(metadataMarker)]
	if db.ipVersion == 6 {
		node := uint32(0)
		for i := 0; i < 96 && node < db.nodeCount; i++ {
			node = db.record(node, 0)
		}
		db.ipv4Start = node
	}
	return db, nil
}

// asUint accepts any integer type the decoder produces, because MaxMind
// writers are free to pick the narrowest encoding for each metadata field.
func asUint(v any) (uint32, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxUint32 {
			return 0, false
		}
		return uint32(n), true
	case int32:
		if n < 0 {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}

// record reads record `side` (0 = left, 1 = right) of the given node. The
// caller guarantees node < nodeCount, which parseMMDB verified fits in buf.
func (db *mmdbDB) record(node uint32, side int) uint32 {
	switch db.recordSize {
	case 24:
		off := int(node)*6 + side*3
		b := db.buf[off : off+3]
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	case 28:
		off := int(node) * 7
		b := db.buf[off : off+7]
		if side == 0 {
			return uint32(b[3]>>4)<<24 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		}
		return uint32(b[3]&0x0f)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
	default: // 32
		off := int(node)*8 + side*4
		return binary.BigEndian.Uint32(db.buf[off : off+4])
	}
}

// Country implements DB.
func (db *mmdbDB) Country(ip netip.Addr) (string, bool) {
	ip = normalize(ip)
	if !ip.IsValid() {
		return "", false
	}
	var node uint32
	var bits []byte
	if ip.Is4() {
		if db.ipVersion == 6 {
			node = db.ipv4Start
		}
		a := ip.As4()
		bits = a[:]
	} else {
		if db.ipVersion == 4 {
			return "", false
		}
		a := ip.As16()
		bits = a[:]
	}
	for _, b := range bits {
		for i := 7; i >= 0; i-- {
			if node >= db.nodeCount {
				break
			}
			node = db.record(node, int(b>>uint(i))&1)
		}
	}
	if node <= db.nodeCount {
		return "", false
	}
	off := int(node-db.nodeCount) - dataSeparatorLen
	if off < 0 || off >= len(db.data) {
		return "", false
	}
	dec := decoder{data: db.data}
	v, _, err := dec.decode(off, 0, 0)
	if err != nil {
		return "", false
	}
	return countryFromRecord(v)
}

// countryFromRecord prefers country over registered_country, matching what
// MaxMind's own clients display: country is where the address is used,
// registered_country where it was allocated.
func countryFromRecord(v any) (string, bool) {
	rec, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	for _, key := range []string{"country", "registered_country"} {
		if m, ok := rec[key].(map[string]any); ok {
			if code, ok := m["iso_code"].(string); ok && code != "" {
				return code, true
			}
		}
	}
	return "", false
}

// Close implements DB. The file was read into memory, so there is nothing to
// release: the buffer is collected once the last reference is dropped.
//
// It deliberately does not nil the buffers. The daemon swaps databases on a
// reload and closes the old one while a status request may still be looking
// something up in it; clearing the slices under that reader would be a data
// race, and returning "not found" from a half-cleared database is not worth
// the few megabytes freed a moment earlier.
func (db *mmdbDB) Close() error { return nil }

// decoder reads the MaxMind data section's TLV encoding.
type decoder struct {
	data []byte
	// values counts every value decoded for one record. Depth alone does
	// not bound the work: a map whose entries all point back at itself is
	// legal TLV and fans out exponentially within maxDecodeDepth. A country
	// record is a few dozen values; the budget is generous, not tight.
	values int
}

// maxRecordValues bounds the work spent on one record; see decoder.values.
const maxRecordValues = 1 << 14

// maxPointerHops bounds a chain of pointers to pointers. The spec forbids
// them outright; one level of tolerance costs nothing, and the cap is what
// turns a self-pointing record into an error instead of a hang. It is a
// chain length, not a per-record total: a deduplicated GeoLite2 record is
// reached through dozens of independent pointers, and counting those would
// make real databases fail silently.
const maxPointerHops = 4

var errTruncated = errors.New("data section truncated")

// decode returns the value at off, the offset just past it, and an error for
// anything malformed. Pointers return the offset after the pointer itself,
// not after its target, which is what the containing map or array needs.
// hops is the number of pointers followed consecutively to reach off.
func (d *decoder) decode(off, depth, hops int) (any, int, error) {
	if depth > maxDecodeDepth {
		return nil, 0, errors.New("data nested too deeply")
	}
	d.values++
	if d.values > maxRecordValues {
		return nil, 0, errors.New("record is implausibly large")
	}
	if off < 0 || off >= len(d.data) {
		return nil, 0, errTruncated
	}
	ctrl := d.data[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 0 { // extended type
		if off >= len(d.data) {
			return nil, 0, errTruncated
		}
		typ = 7 + int(d.data[off])
		off++
	}
	if typ == 1 {
		return d.pointer(ctrl, off, depth, hops)
	}
	size := int(ctrl & 0x1f)
	switch {
	case size < 29:
	case size == 29:
		if off >= len(d.data) {
			return nil, 0, errTruncated
		}
		size = 29 + int(d.data[off])
		off++
	case size == 30:
		if off+2 > len(d.data) {
			return nil, 0, errTruncated
		}
		size = 285 + int(binary.BigEndian.Uint16(d.data[off:]))
		off += 2
	default:
		if off+3 > len(d.data) {
			return nil, 0, errTruncated
		}
		size = 65821 + int(uint32(d.data[off])<<16|uint32(d.data[off+1])<<8|uint32(d.data[off+2]))
		off += 3
	}
	switch typ {
	case 7: // map
		// The size field is attacker-controlled; every entry needs at
		// least one byte, so the remaining data bounds the capacity hint.
		m := make(map[string]any, min(size, len(d.data)-off))
		for i := 0; i < size; i++ {
			k, next, err := d.decode(off, depth+1, 0)
			if err != nil {
				return nil, 0, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, 0, fmt.Errorf("map key is %T, not a string", k)
			}
			v, next, err := d.decode(next, depth+1, 0)
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			off = next
		}
		return m, off, nil
	case 11: // array
		a := make([]any, 0, min(size, len(d.data)-off))
		for i := 0; i < size; i++ {
			v, next, err := d.decode(off, depth+1, 0)
			if err != nil {
				return nil, 0, err
			}
			a = append(a, v)
			off = next
		}
		return a, off, nil
	case 14: // boolean, stored in the size field
		return size != 0, off, nil
	}
	if off+size > len(d.data) {
		return nil, 0, errTruncated
	}
	payload := d.data[off : off+size]
	off += size
	switch typ {
	case 2:
		return string(payload), off, nil
	case 3:
		if size != 8 {
			return nil, 0, fmt.Errorf("double has size %d", size)
		}
		return math.Float64frombits(binary.BigEndian.Uint64(payload)), off, nil
	case 4:
		return append([]byte(nil), payload...), off, nil
	case 5, 6, 9:
		if size > 8 {
			return nil, 0, fmt.Errorf("unsigned integer has size %d", size)
		}
		var n uint64
		for _, b := range payload {
			n = n<<8 | uint64(b)
		}
		return n, off, nil
	case 8:
		if size > 4 {
			return nil, 0, fmt.Errorf("int32 has size %d", size)
		}
		var n uint32
		for _, b := range payload {
			n = n<<8 | uint32(b)
		}
		return int32(n), off, nil
	case 10:
		if size > 16 {
			return nil, 0, fmt.Errorf("uint128 has size %d", size)
		}
		return append([]byte(nil), payload...), off, nil
	case 12:
		return nil, 0, errors.New("data cache container is not supported")
	case 13:
		return nil, 0, errors.New("unexpected end marker")
	case 15:
		if size != 4 {
			return nil, 0, fmt.Errorf("float has size %d", size)
		}
		return math.Float32frombits(binary.BigEndian.Uint32(payload)), off, nil
	}
	return nil, 0, fmt.Errorf("unknown data type %d", typ)
}

// pointer resolves a type-1 value. The four encodings pack the pointer size
// into bits 3-4 of the control byte and the high value bits into bits 0-2.
func (d *decoder) pointer(ctrl byte, off, depth, hops int) (any, int, error) {
	if hops >= maxPointerHops {
		return nil, 0, errors.New("pointer chain too long")
	}
	psize := int(ctrl>>3) & 0x3
	vbits := int(ctrl & 0x7)
	n := psize + 1
	if off+n > len(d.data) {
		return nil, 0, errTruncated
	}
	var target int
	switch psize {
	case 0:
		target = vbits<<8 | int(d.data[off])
	case 1:
		target = vbits<<16 | int(d.data[off])<<8 | int(d.data[off+1]) + 2048
	case 2:
		target = vbits<<24 | int(d.data[off])<<16 | int(d.data[off+1])<<8 | int(d.data[off+2]) + 526336
	default:
		target = int(binary.BigEndian.Uint32(d.data[off:]))
	}
	// A pointer hop does not count as nesting, only as a hop.
	v, _, err := d.decode(target, depth, hops+1)
	if err != nil {
		return nil, 0, err
	}
	return v, off + n, nil
}
