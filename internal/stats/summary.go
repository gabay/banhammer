package stats

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"banhammer/internal/model"
)

// Window names, in the order they are reported. They are what the page and
// the CLI print, so they are short.
const (
	WindowHour  = "1h"
	WindowDay   = "24h"
	WindowWeek  = "7d"
	WindowMonth = "30d"
)

// windows are the reporting windows, shortest first.
var windows = []struct {
	name string
	d    time.Duration
}{
	{WindowHour, time.Hour},
	{WindowDay, 24 * time.Hour},
	{WindowWeek, 7 * 24 * time.Hour},
	{WindowMonth, 30 * 24 * time.Hour},
}

// Sentinel country codes. "ZZ" is ISO 3166's user-assigned code for "unknown
// or unspecified", which is exactly what an address the database does not
// cover is. The empty code is the roll-up of countries past the top-N cut.
const (
	CountryUnknown = "ZZ"
	CountryOther   = ""
)

// Summary is everything the status page and `banhammer status` show that
// comes from the ledger rather than from the live ban table. It is part of
// the control-socket wire format, so field names are stable.
type Summary struct {
	// GeneratedAt is the instant the summary describes; every window and
	// bucket is relative to it.
	GeneratedAt time.Time `json:"generated_at"`
	// Retention is how far back the ledger remembers, in seconds. Windows
	// longer than this are reported but necessarily incomplete.
	RetentionSeconds int64 `json:"retention_seconds"`
	// Events is how many bans the ledger currently holds.
	Events int `json:"events"`
	// Timezone names the location hour-of-day and day buckets were computed
	// in: the daemon's local zone, which is where the operator reads logs.
	Timezone string `json:"timezone"`

	Windows []Window `json:"windows"`
	// BansPerHour covers the last 24 clock hours, oldest first, each bucket
	// starting on the hour. BansPerDay covers the last 30 calendar days,
	// oldest first, each starting at local midnight.
	BansPerHour []Bucket `json:"bans_per_hour"`
	BansPerDay  []Bucket `json:"bans_per_day"`
	// ByHourOfDay and ByWeekday are distributions over the whole ledger.
	// ByWeekday is indexed Sunday=0, as time.Weekday is.
	ByHourOfDay [24]int `json:"by_hour_of_day"`
	ByWeekday   [7]int  `json:"by_weekday"`

	Monitors []MonitorSummary `json:"monitors"`
	// TopOffenders are the addresses banned most often within retention.
	TopOffenders []Offender `json:"top_offenders"`
	// RepeatOffenders counts addresses banned more than once within retention.
	RepeatOffenders int `json:"repeat_offenders"`
	// UniqueOffenders counts distinct addresses banned within retention.
	UniqueOffenders int `json:"unique_offenders"`

	// Families splits the *active* bans by address family.
	Families Families `json:"families"`

	// GeoEnabled says whether a country database was configured. When false
	// the country lists are empty and IPCountries is nil, rather than being
	// full of "unknown".
	GeoEnabled bool `json:"geo_enabled"`
	// Countries ranks the countries of every ban within retention;
	// ActiveCountries does the same for the bans in force right now.
	Countries       []Country `json:"countries,omitempty"`
	ActiveCountries []Country `json:"active_countries,omitempty"`
	// IPCountries maps each address that appears in the active bans or the
	// top offenders to its country code, so a renderer can label rows
	// without a database of its own.
	IPCountries map[string]string `json:"ip_countries,omitempty"`
	// Samples maps each address in the active bans or the top offenders to
	// the most recent log line that got it banned, when the ledger has one.
	Samples map[string]Sample `json:"samples,omitempty"`
}

// Sample is one offending log line, already sanitised by the ledger (see
// SanitizeLine): printable UTF-8, at most MaxLineBytes, no control
// characters. Still attacker-written text; render it as text.
type Sample struct {
	Line    string    `json:"line"`
	Monitor string    `json:"monitor"`
	At      time.Time `json:"at"`
}

// Window is the ban count over one trailing period.
type Window struct {
	Name      string `json:"name"`
	Seconds   int64  `json:"seconds"`
	Bans      int    `json:"bans"`
	UniqueIPs int    `json:"unique_ips"`
}

// Bucket is one bar of a timeline.
type Bucket struct {
	Start time.Time `json:"start"`
	Bans  int       `json:"bans"`
}

// MonitorSummary is one monitor's row: live bans plus bans per window.
type MonitorSummary struct {
	Name   string `json:"name"`
	Active int    `json:"active"`
	// Bans is keyed by window name (WindowDay etc.).
	Bans map[string]int `json:"bans"`
}

// Offender is one row of the repeat-offender table.
type Offender struct {
	IP      netip.Addr `json:"ip"`
	Bans    int        `json:"bans"`
	LastAt  time.Time  `json:"last_at"`
	Country string     `json:"country,omitempty"`
	// Monitors lists which monitors banned this address, sorted.
	Monitors []string `json:"monitors"`
}

// Family split of active bans.
type Families struct {
	IPv4 int `json:"ipv4"`
	IPv6 int `json:"ipv6"`
}

// Country is one bar of a geography chart. Name is the English short name
// when the summariser was given a namer, else empty; Code is "ZZ" for
// addresses the database did not know and "" for the "other" roll-up.
type Country struct {
	Code string `json:"code"`
	Name string `json:"name,omitempty"`
	Bans int    `json:"bans"`
}

// SummaryOptions tunes Summarize. Zero values are sensible.
type SummaryOptions struct {
	// Retention is reported in the summary; it does not filter events (the
	// ledger already did).
	Retention time.Duration
	// Location for hour-of-day and calendar-day bucketing. Default time.Local.
	Location *time.Location
	// Geo answers country lookups. nil disables geography.
	Geo Lookup
	// CountryName turns a code into a display name. nil leaves names empty.
	CountryName func(code string) string
	// TopN bounds the offender and country lists. Default 10.
	TopN int
}

// Summarize computes a Summary from a ledger snapshot and the bans currently
// in force. It is a pure function of its inputs — nothing here touches a
// clock or a lock — so it is cheap to test and safe to call from any
// goroutine. Cost is O(events); at the ledger's cap that is a few
// milliseconds, and the web server caches the result anyway.
func Summarize(events []model.BanEvent, active []model.Ban, now time.Time, o SummaryOptions) Summary {
	loc := o.Location
	if loc == nil {
		loc = time.Local
	}
	topN := o.TopN
	if topN <= 0 {
		topN = 10
	}
	name := o.CountryName
	if name == nil {
		name = func(string) string { return "" }
	}
	nowLoc := now.In(loc)

	s := Summary{
		GeneratedAt:      now,
		RetentionSeconds: int64(o.Retention / time.Second),
		Events:           len(events),
		Timezone:         zoneName(nowLoc),
		GeoEnabled:       o.Geo != nil,
	}

	// --- windows -------------------------------------------------------
	bansIn := make([]int, len(windows))
	perMonitor := make(map[string]*MonitorSummary)
	monitorRow := func(m string) *MonitorSummary {
		row, ok := perMonitor[m]
		if !ok {
			row = &MonitorSummary{Name: m, Bans: make(map[string]int, len(windows))}
			for _, w := range windows {
				row.Bans[w.name] = 0
			}
			perMonitor[m] = row
		}
		return row
	}

	// --- timelines -----------------------------------------------------
	// The local hour boundary is found by hand rather than with Truncate,
	// which works on absolute time and is a zone-offset off in any location
	// whose offset is not a whole number of hours.
	hourStart := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day(), nowLoc.Hour(), 0, 0, 0, loc)
	firstHour := hourStart.Add(-23 * time.Hour)
	s.BansPerHour = make([]Bucket, 24)
	for i := range s.BansPerHour {
		s.BansPerHour[i].Start = firstHour.Add(time.Duration(i) * time.Hour)
	}
	// Day buckets are keyed by calendar date, not by instant. On a day whose
	// midnight does not exist (zones that spring forward at 00:00: Santiago,
	// Asunción, Havana, Beirut) time.Date normalises 00:00 to 23:00 the day
	// before, so two "midnights" computed by different routes need not be
	// the same instant — but they are the same date.
	type ymd struct{ y, m, d int }
	dayIndex := make(map[ymd]int, 30)
	s.BansPerDay = make([]Bucket, 30)
	for i := range s.BansPerDay {
		// The date is derived at noon, which exists on every day in every
		// zone; the bucket's start is then that date's midnight (or the
		// instant the zone calls midnight). AddDate from one anchor would
		// carry a 23:00 anchor into every other day, and a multiple of 24h
		// is wrong across any DST change.
		noon := time.Date(nowLoc.Year(), nowLoc.Month(), nowLoc.Day()-(29-i), 12, 0, 0, 0, loc)
		s.BansPerDay[i].Start = time.Date(noon.Year(), noon.Month(), noon.Day(), 0, 0, 0, 0, loc)
		dayIndex[ymd{noon.Year(), int(noon.Month()), noon.Day()}] = i
	}

	// --- offenders -----------------------------------------------------
	// One value-typed map for everything per address. The ledger can hold
	// 100k events, and a pointer plus a monitor set per address turned a
	// summary into a 700k-allocation, 75 MB affair; the monitor lists are
	// only needed for the handful of addresses that make the top N, and are
	// collected for those in a second pass.
	type offAcc struct {
		bans int
		last time.Time
	}
	offenders := make(map[netip.Addr]offAcc)

	for _, e := range events {
		age := now.Sub(e.At)
		if age < 0 {
			age = 0 // a clock step; count it as "just now" rather than drop it
		}
		for i, w := range windows {
			if age <= w.d {
				bansIn[i]++
				monitorRow(e.Monitor).Bans[w.name]++
			}
		}
		// Both bounds are checked explicitly: a negative duration divided by
		// an hour truncates towards zero, so an event one second before the
		// first bucket would otherwise land in it.
		if !e.At.Before(firstHour) && e.At.Before(hourStart.Add(time.Hour)) {
			s.BansPerHour[int(e.At.Sub(firstHour)/time.Hour)].Bans++
		}
		local := e.At.In(loc)
		if i, ok := dayIndex[ymd{local.Year(), int(local.Month()), local.Day()}]; ok {
			s.BansPerDay[i].Bans++
		}
		s.ByHourOfDay[local.Hour()]++
		s.ByWeekday[local.Weekday()]++

		acc := offenders[e.IP]
		acc.bans++
		if e.At.After(acc.last) {
			acc.last = e.At
		}
		offenders[e.IP] = acc
	}

	// An address is "in" a window if its most recent ban is, so unique
	// counts fall out of the per-address accumulator without a set per
	// window.
	s.Windows = make([]Window, len(windows))
	for i, w := range windows {
		s.Windows[i] = Window{Name: w.name, Seconds: int64(w.d / time.Second), Bans: bansIn[i]}
	}
	for _, acc := range offenders {
		age := max(now.Sub(acc.last), 0)
		for i, w := range windows {
			if age <= w.d {
				s.Windows[i].UniqueIPs++
			}
		}
	}

	// --- active bans ---------------------------------------------------
	for _, b := range active {
		monitorRow(b.Monitor).Active++
		if b.Family() == model.IPv4 {
			s.Families.IPv4++
		} else {
			s.Families.IPv6++
		}
	}
	s.Monitors = make([]MonitorSummary, 0, len(perMonitor))
	for _, name := range slices.Sorted(maps.Keys(perMonitor)) {
		s.Monitors = append(s.Monitors, *perMonitor[name])
	}

	// --- offenders -----------------------------------------------------
	s.UniqueOffenders = len(offenders)
	all := make([]Offender, 0, len(offenders))
	for ip, acc := range offenders {
		if acc.bans > 1 {
			s.RepeatOffenders++
		}
		all = append(all, Offender{IP: ip, Bans: acc.bans, LastAt: acc.last})
	}
	slices.SortFunc(all, func(a, b Offender) int {
		if c := cmp.Compare(b.Bans, a.Bans); c != 0 {
			return c
		}
		if c := b.LastAt.Compare(a.LastAt); c != 0 {
			return c
		}
		return a.IP.Compare(b.IP)
	})
	s.TopOffenders = all[:min(topN, len(all)):min(topN, len(all))]
	if len(s.TopOffenders) > 0 {
		topMonitors := make(map[netip.Addr]map[string]struct{}, len(s.TopOffenders))
		for _, o := range s.TopOffenders {
			topMonitors[o.IP] = make(map[string]struct{}, 1)
		}
		for _, e := range events {
			if set, ok := topMonitors[e.IP]; ok {
				set[e.Monitor] = struct{}{}
			}
		}
		for i := range s.TopOffenders {
			s.TopOffenders[i].Monitors = slices.Sorted(maps.Keys(topMonitors[s.TopOffenders[i].IP]))
		}
	}

	// --- samples -------------------------------------------------------
	// The newest line per address, for the addresses someone will look at.
	// Chosen by timestamp, not by position: the ledger keeps events in time
	// order, but Summarize promises not to depend on it.
	wanted := make(map[netip.Addr]struct{}, len(active)+len(s.TopOffenders))
	for _, b := range active {
		wanted[b.IP] = struct{}{}
	}
	for _, o := range s.TopOffenders {
		wanted[o.IP] = struct{}{}
	}
	for _, e := range events {
		if e.Line == "" {
			continue
		}
		if _, want := wanted[e.IP]; !want {
			continue
		}
		key := e.IP.String()
		if cur, ok := s.Samples[key]; ok && !e.At.After(cur.At) {
			continue
		}
		if s.Samples == nil {
			s.Samples = make(map[string]Sample)
		}
		s.Samples[key] = Sample{Line: e.Line, Monitor: e.Monitor, At: e.At}
	}

	// --- geography -----------------------------------------------------
	if o.Geo != nil {
		s.IPCountries = make(map[string]string, len(active)+len(s.TopOffenders))
		lookup := func(ip netip.Addr) string {
			code, ok := o.Geo.Country(ip)
			if !ok || code == "" {
				return CountryUnknown
			}
			return code
		}
		// Per distinct address, not per event: a database lookup is cheap,
		// but one per event at the ledger's cap is still 100k of them.
		byIP := make(map[netip.Addr]string, len(offenders))
		for ip := range offenders {
			byIP[ip] = lookup(ip)
		}
		all := make(map[string]int)
		for _, e := range events {
			all[byIP[e.IP]]++
		}
		s.Countries = rankCountries(all, topN, name)

		live := make(map[string]int)
		for _, b := range active {
			code, ok := byIP[b.IP]
			if !ok {
				code = lookup(b.IP)
				byIP[b.IP] = code
			}
			live[code]++
			s.IPCountries[b.IP.String()] = code
		}
		s.ActiveCountries = rankCountries(live, topN, name)
		for i := range s.TopOffenders {
			code := byIP[s.TopOffenders[i].IP]
			s.TopOffenders[i].Country = code
			s.IPCountries[s.TopOffenders[i].IP.String()] = code
		}
	}
	return s
}

// zoneName names the zone a time is expressed in: "UTC", "CEST", or a
// numeric offset when the zone has no abbreviation. It is not
// Location.String(), which is the literal "Local" for the daemon's own zone
// and would tell a remote reader of --json nothing.
func zoneName(t time.Time) string {
	name, off := t.Zone()
	if name == "" || name[0] == '+' || name[0] == '-' {
		sign := '+'
		if off < 0 {
			sign, off = '-', -off
		}
		return fmt.Sprintf("UTC%c%02d:%02d", sign, off/3600, off%3600/60)
	}
	return name
}

// rankCountries turns a code→count map into a sorted top-N list with the
// remainder rolled into CountryOther. Unknown is ranked like any other
// country: on a host with no database coverage it is the honest answer.
func rankCountries(counts map[string]int, topN int, name func(string) string) []Country {
	if len(counts) == 0 {
		return nil
	}
	out := make([]Country, 0, len(counts))
	for code, n := range counts {
		out = append(out, Country{Code: code, Bans: n})
	}
	slices.SortFunc(out, func(a, b Country) int {
		if c := cmp.Compare(b.Bans, a.Bans); c != 0 {
			return c
		}
		return cmp.Compare(a.Code, b.Code)
	})
	if len(out) > topN {
		other := Country{Code: CountryOther, Name: "Other"}
		for _, c := range out[topN:] {
			other.Bans += c.Bans
		}
		out = append(out[:topN], other)
	}
	for i := range out {
		switch out[i].Code {
		case CountryUnknown:
			out[i].Name = "Unknown"
		case CountryOther:
		default:
			out[i].Name = name(out[i].Code)
		}
	}
	return out
}
