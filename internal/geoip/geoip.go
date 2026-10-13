// Package geoip maps IP addresses to ISO 3166-1 country codes for display.
//
// The database is optional: when none is configured nothing in banhammer
// changes except that bans are shown without a country. It is only ever
// consulted to decorate output (status listings, notifications), never to
// decide whether an address is banned, so a stale or inaccurate database
// degrades cosmetics rather than security.
//
// Both readers are hand-rolled on purpose. The project's dependency policy
// (see docs/ARCHITECTURE.md) allows exactly fsnotify, cobra, yaml.v3 and
// x/sys; pulling in a MaxMind reader for a cosmetic feature would be a design
// decision we are not willing to make. The MaxMind DB format is small and
// stable, and the subset needed to extract a country code fits comfortably in
// a few hundred lines.
package geoip

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// DB answers "which country is this address in?".
type DB interface {
	// Country returns the ISO 3166-1 alpha-2 code (upper case, e.g. "DE") for ip.
	// ok is false when the address is not in the database. Must be safe for
	// concurrent use and must never panic on any netip.Addr (invalid, zone,
	// 4-in-6 mapped — unmap before looking up).
	Country(ip netip.Addr) (code string, ok bool)
	// Close releases the underlying file, if any.
	Close() error
}

// Open loads a country database. The format is chosen by file extension:
//
//	.mmdb          MaxMind DB (GeoLite2-Country, GeoIP2-Country, DB-IP country mmdb)
//	anything else  CSV with lines `start_ip,end_ip,country_code`
//	               (DB-IP "dbip-country-lite" and sapics/ip-location-db
//	               "geolite2-country" / "dbip-country" CSVs). Also accept .csv.gz.
//
// It returns a descriptive error for a missing or unparseable file.
func Open(path string) (DB, error) {
	if strings.EqualFold(filepath.Ext(path), ".mmdb") {
		db, err := openMMDB(path)
		if err != nil {
			return nil, fmt.Errorf("geoip: open mmdb %q: %w", path, err)
		}
		return db, nil
	}
	db, err := openCSV(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open csv %q: %w", path, err)
	}
	return db, nil
}

// Name returns the English short name for an ISO 3166-1 alpha-2 code, or ""
// if unknown.
func Name(code string) string {
	return names[strings.ToUpper(code)]
}

// Flag returns the regional-indicator emoji for an alpha-2 code ("US" -> "🇺🇸"),
// or "" for anything that is not two ASCII letters.
func Flag(code string) string {
	if len(code) != 2 {
		return ""
	}
	var out [8]byte
	buf := out[:0]
	for i := 0; i < 2; i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case c >= 'A' && c <= 'Z':
		default:
			return ""
		}
		// Regional indicator symbols start at U+1F1E6 for 'A'.
		buf = append(buf, string(rune(0x1F1E6+int(c-'A')))...)
	}
	return string(buf)
}

// normalize folds the shapes of netip.Addr that callers may hand us into the
// one the lookup tables understand: zones are dropped and IPv4-mapped IPv6
// addresses become plain IPv4, since both databases key IPv4 ranges by the
// 4-byte form.
func normalize(ip netip.Addr) netip.Addr {
	return ip.Unmap().WithZone("")
}

// readFile reads a database into memory with a hard cap. A country database
// is a few megabytes, so a whole-file read is simpler than mmap and the cap
// turns a mistaken path (say, a log file) into a clear error instead of an
// OOM.
const maxFileSize = 256 << 20

func readFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("file is %d bytes, larger than the %d byte limit", fi.Size(), maxFileSize)
	}
	return os.ReadFile(path)
}
