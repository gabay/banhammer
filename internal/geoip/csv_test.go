package geoip

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// unsafeStringData exposes a string's backing pointer so a test can check
// that interning actually shares storage rather than merely producing equal
// values.
func unsafeStringData(s string) *byte { return unsafe.StringData(s) }

const sampleCSV = `# DB-IP style sample
start_ip,end_ip,country
"1.0.0.0","1.0.0.255","AU"
10.0.0.0,10.255.255.255,de

192.168.1.128 , 192.168.1.255 , US
203.0.113.7,203.0.113.7,JP
2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE
2a00::,2a0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff,NL
`

var csvLookupCases = []struct {
	name string
	ip   string
	want string
	ok   bool
}{
	{"quoted range hit", "1.0.0.1", "AU", true},
	{"first address", "1.0.0.0", "AU", true},
	{"last address", "1.0.0.255", "AU", true},
	{"just past", "1.0.1.0", "", false},
	{"just before", "0.255.255.255", "", false},
	{"lower-case code upper-cased", "10.20.30.40", "DE", true},
	{"padded fields", "192.168.1.200", "US", true},
	{"padded fields miss", "192.168.1.127", "", false},
	{"single address range", "203.0.113.7", "JP", true},
	{"single address neighbour", "203.0.113.8", "", false},
	{"v4-mapped input", "::ffff:1.0.0.1", "AU", true},
	{"v6 hit", "2001:db8::1", "DE", true},
	{"v6 end", "2a0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "NL", true},
	{"v6 miss", "2001:db9::", "", false},
	{"loopback", "::1", "", false},
	{"v4 in v6 space but not mapped", "::1.0.0.1", "", false},
}

func TestCSVLookup(t *testing.T) {
	t.Parallel()
	variants := map[string]string{
		"lf":   sampleCSV,
		"crlf": strings.ReplaceAll(sampleCSV, "\n", "\r\n"),
	}
	for name, text := range variants {
		db, err := parseCSV(strings.NewReader(text))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		for _, tc := range csvLookupCases {
			got, ok := db.Country(netip.MustParseAddr(tc.ip))
			if got != tc.want || ok != tc.ok {
				t.Errorf("%s: %s: Country(%s) = %q,%v; want %q,%v", name, tc.name, tc.ip, got, ok, tc.want, tc.ok)
			}
		}
	}
}

func TestCSVNeverPanics(t *testing.T) {
	t.Parallel()
	db, err := parseCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		if got, ok := db.Country(ip); ok {
			t.Errorf("Country(%v) = %q,true; want miss", ip, got)
		}
	}
	if got, ok := db.Country(netip.MustParseAddr("::ffff:10.1.2.3").WithZone("x")); !ok || got != "DE" {
		t.Errorf("zoned v4-mapped lookup = %q,%v; want DE,true", got, ok)
	}
	empty := &csvDB{}
	if got, ok := empty.Country(netip.MustParseAddr("1.1.1.1")); ok {
		t.Errorf("empty db returned %q", got)
	}
}

// TestCSVOverlap pins the documented rule: ranges are sorted by start and a
// range that starts inside an earlier one is dropped entirely.
func TestCSVOverlap(t *testing.T) {
	t.Parallel()
	db, err := parseCSV(strings.NewReader(`
10.0.0.128,10.0.1.0,DE
10.0.0.0,10.0.0.255,US
10.0.1.1,10.0.1.1,FR
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip   string
		want string
		ok   bool
	}{
		{"10.0.0.1", "US", true},
		{"10.0.0.200", "US", true},
		{"10.0.1.0", "", false}, // belonged only to the dropped DE range
		{"10.0.1.1", "FR", true},
	}
	for _, tc := range tests {
		got, ok := db.Country(netip.MustParseAddr(tc.ip))
		if got != tc.want || ok != tc.ok {
			t.Errorf("Country(%s) = %q,%v; want %q,%v", tc.ip, got, ok, tc.want, tc.ok)
		}
	}
	if len(db.v4) != 2 {
		t.Errorf("kept %d ranges; want 2", len(db.v4))
	}
}

func TestCSVInternsCodes(t *testing.T) {
	t.Parallel()
	db, err := parseCSV(strings.NewReader("1.0.0.0,1.0.0.255,DE\n2.0.0.0,2.0.0.255,de\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := db.v4[0].cc, db.v4[1].cc
	if a != "DE" || b != "DE" {
		t.Fatalf("codes = %q, %q; want DE, DE", a, b)
	}
	if unsafeStringData(a) != unsafeStringData(b) {
		t.Error("equal country codes are not interned to one string")
	}
}

func TestCSVErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "no usable ranges"},
		{"only header", "start,end,cc\n", "no usable ranges"},
		{"only comments", "# a\n\n# b\n", "no usable ranges"},
		{"bad start ip", "1.0.0.0,1.0.0.255,AU\n\n1.2.3,1.2.3.4,US\n", "line 3: bad start address \"1.2.3\""},
		{"bad end ip", "1.0.0.0,1.0.0.x,AU\n", "line 1: bad end address"},
		{"header after data", "1.0.0.0,1.0.0.255,AU\nstart,end,cc\n", "line 2: bad start address"},
		{"too few fields", "1.0.0.0,1.0.0.255\n", "line 1: want at least 3"},
		{"mixed families", "1.0.0.0,::1,AU\n", "line 1: range 1.0.0.0-::1 mixes"},
		{"reversed", "1.0.0.255,1.0.0.0,AU\n", "line 1: range 1.0.0.255-1.0.0.0 is reversed"},
		{"empty code", "1.0.0.0,1.0.0.255,\n", "line 1: empty country code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCSV(strings.NewReader(tc.input))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
		})
	}
}

func TestCSVConcurrent(t *testing.T) {
	t.Parallel()
	db, err := parseCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tc := range csvLookupCases {
				if got, ok := db.Country(netip.MustParseAddr(tc.ip)); got != tc.want || ok != tc.ok {
					t.Errorf("%s: got %q,%v", tc.name, got, ok)
				}
			}
		}()
	}
	wg.Wait()
}

func TestOpenCSV(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	plain := filepath.Join(dir, "dbip-country-lite.csv")
	if err := os.WriteFile(plain, []byte(sampleCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write([]byte(sampleCSV)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "dbip-country-lite.csv.gz")
	if err := os.WriteFile(gzPath, gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	noExt := filepath.Join(dir, "ranges")
	if err := os.WriteFile(noExt, []byte(sampleCSV), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{plain, gzPath, noExt} {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("Open(%s): %v", path, err)
		}
		if got, ok := db.Country(netip.MustParseAddr("2001:db8::1")); !ok || got != "DE" {
			t.Errorf("Open(%s): Country = %q,%v; want DE,true", path, got, ok)
		}
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}

	badGz := filepath.Join(dir, "bad.csv.gz")
	if err := os.WriteFile(badGz, []byte("definitely not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(badGz); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("Open(bad gz): err = %v; want gzip error", err)
	}

	_, err := Open(filepath.Join(dir, "missing.csv"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open missing: err = %v; want ErrNotExist", err)
	}

	bad := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(bad, []byte("start,end,cc\n1.0.0.0,nope,AU\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "bad.csv") {
		t.Errorf("Open(bad csv): err = %v; want line number and path", err)
	}
}
