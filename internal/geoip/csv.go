package geoip

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// csvRange is one `start,end,cc` line. cc is interned so that the ~500k rows
// of a DB-IP lite file share ~250 strings instead of each owning a copy.
type csvRange struct {
	lo, hi netip.Addr
	cc     string
}

type csvDB struct {
	v4, v6 []csvRange
}

func openCSV(path string) (*csvDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}
	// The same cap the mmdb path applies, but on the *decompressed* stream:
	// a gzip bomb, or a mistaken path to a log file, must fail with an error
	// rather than with the OOM killer.
	lr := &io.LimitedReader{R: r, N: maxFileSize + 1}
	db, err := parseCSV(lr)
	if lr.N == 0 {
		// Checked before the parse error: a cut-off last line would
		// otherwise be reported as a bad address, which sends the operator
		// looking at the wrong thing.
		return nil, fmt.Errorf("file is larger than the %d byte limit", maxFileSize)
	}
	return db, err
}

// parseCSV is deliberately not encoding/csv: the files are three plain
// columns, and a hand parser lets us report the line number of a bad address
// and tolerate the header/comment/quote variations between publishers.
func parseCSV(r io.Reader) (*csvDB, error) {
	db := &csvDB{}
	intern := make(map[string]string, 256)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, ",")
		if len(fields) < 3 {
			return nil, fmt.Errorf("line %d: want at least 3 comma-separated fields, got %d", line, len(fields))
		}
		for i := range fields {
			fields[i] = strings.Trim(strings.TrimSpace(fields[i]), `"`)
		}
		lo, err := netip.ParseAddr(fields[0])
		if err != nil {
			// A header ("start_ip,end_ip,country") is the only legitimate
			// non-address first column; it never looks like an address and
			// only appears before any data row.
			if len(db.v4)+len(db.v6) == 0 && !strings.ContainsAny(fields[0], ".:") {
				continue
			}
			return nil, fmt.Errorf("line %d: bad start address %q: %w", line, fields[0], err)
		}
		hi, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: bad end address %q: %w", line, fields[1], err)
		}
		lo, hi = normalize(lo), normalize(hi)
		if lo.Is4() != hi.Is4() {
			return nil, fmt.Errorf("line %d: range %s-%s mixes address families", line, lo, hi)
		}
		if hi.Less(lo) {
			return nil, fmt.Errorf("line %d: range %s-%s is reversed", line, lo, hi)
		}
		cc := strings.ToUpper(fields[2])
		if cc == "" {
			return nil, fmt.Errorf("line %d: empty country code", line)
		}
		if s, ok := intern[cc]; ok {
			cc = s
		} else {
			intern[cc] = cc
		}
		rg := csvRange{lo: lo, hi: hi, cc: cc}
		if lo.Is4() {
			db.v4 = append(db.v4, rg)
		} else {
			db.v6 = append(db.v6, rg)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line, err)
	}
	if len(db.v4)+len(db.v6) == 0 {
		return nil, errors.New("no usable ranges")
	}
	db.v4 = dedupe(db.v4)
	db.v6 = dedupe(db.v6)
	return db, nil
}

// dedupe sorts ranges by start and drops any range that begins inside the
// previous one. Published files are non-overlapping, so this only matters for
// hand-edited input; first-range-wins is the simplest rule that keeps lookups
// deterministic and binary search sound.
func dedupe(rs []csvRange) []csvRange {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].lo.Less(rs[j].lo) })
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 && !out[n-1].hi.Less(r.lo) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Country implements DB.
func (db *csvDB) Country(ip netip.Addr) (string, bool) {
	ip = normalize(ip)
	if !ip.IsValid() {
		return "", false
	}
	rs := db.v6
	if ip.Is4() {
		rs = db.v4
	}
	// First range whose start is after ip; the candidate is the one before it.
	i := sort.Search(len(rs), func(i int) bool { return ip.Less(rs[i].lo) })
	if i == 0 {
		return "", false
	}
	if r := rs[i-1]; !r.hi.Less(ip) {
		return r.cc, true
	}
	return "", false
}

// Close implements DB; the file is fully parsed at Open and already closed.
func (db *csvDB) Close() error { return nil }
