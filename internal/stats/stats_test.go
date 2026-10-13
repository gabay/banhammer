package stats

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"banhammer/internal/model"
)

var epoch = time.Date(2024, 3, 15, 12, 30, 0, 0, time.UTC)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func ban(t *testing.T, ip, monitor string, at time.Time) model.Ban {
	t.Helper()
	return model.Ban{IP: addr(t, ip), Monitor: monitor, At: at, Until: at.Add(time.Hour), Count: 5, Offense: 1}
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func newTestLedger(o Options) (*Ledger, *fixedClock) {
	clk := &fixedClock{t: epoch}
	o.Now = clk.Now
	return NewLedger(o), clk
}

func TestLedgerRecordAndSnapshot(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{})
	if l.Dirty() {
		t.Fatal("a fresh ledger must not be dirty")
	}
	l.Record(ban(t, "203.0.113.1", "sshd", epoch.Add(-time.Hour)))
	l.Record(ban(t, "203.0.113.2", "nginx", epoch.Add(-time.Minute)))
	if !l.Dirty() {
		t.Fatal("Record must mark the ledger dirty")
	}
	got := l.Snapshot()
	if len(got) != 2 || got[0].IP != addr(t, "203.0.113.1") || got[1].Monitor != "nginx" {
		t.Fatalf("Snapshot = %+v", got)
	}
	if got[0].At != epoch.Add(-time.Hour) {
		t.Errorf("event keeps the ban's own timestamp, got %v", got[0].At)
	}

	// Snapshot is a copy.
	got[0].Monitor = "mutated"
	if l.Snapshot()[0].Monitor != "sshd" {
		t.Error("Snapshot aliases ledger state")
	}
}

func TestLedgerIgnoresUnusableBans(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{})
	l.Record(model.Ban{Monitor: "x", At: epoch}) // no address
	l.Record(model.Ban{IP: addr(t, "1.1.1.1")})  // no timestamp
	if l.Len() != 0 || l.Dirty() {
		t.Fatalf("unusable bans were recorded: len=%d dirty=%v", l.Len(), l.Dirty())
	}
}

func TestLedgerKeepsTimeOrder(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{})
	l.Record(ban(t, "1.1.1.1", "a", epoch.Add(-2*time.Hour)))
	l.Record(ban(t, "2.2.2.2", "a", epoch.Add(-time.Hour)))
	l.Record(ban(t, "3.3.3.3", "a", epoch.Add(-3*time.Hour))) // late arrival
	got := l.Snapshot()
	want := []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"}
	for i, w := range want {
		if got[i].IP != addr(t, w) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLedgerPrunesByRetention(t *testing.T) {
	t.Parallel()
	l, clk := newTestLedger(Options{Retention: 24 * time.Hour})
	l.Record(ban(t, "1.1.1.1", "a", epoch.Add(-23*time.Hour)))
	l.Record(ban(t, "2.2.2.2", "a", epoch))
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
	clk.t = epoch.Add(2 * time.Hour) // first event is now 25h old
	got := l.Snapshot()
	if len(got) != 1 || got[0].IP != addr(t, "2.2.2.2") {
		t.Fatalf("after retention Snapshot = %+v, want only 2.2.2.2", got)
	}
	// Exactly at the boundary is pruned too (not After cutoff).
	clk.t = epoch.Add(24 * time.Hour)
	if n := len(l.Snapshot()); n != 0 {
		t.Errorf("event exactly retention old survived: %d left", n)
	}
}

func TestLedgerCapsEvents(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{MaxEvents: 3})
	for i := range 5 {
		l.Record(ban(t, "1.1.1.1", "a", epoch.Add(time.Duration(i)*time.Minute)))
	}
	got := l.Snapshot()
	if len(got) != 3 {
		t.Fatalf("Len = %d, want cap 3", len(got))
	}
	if got[0].At != epoch.Add(2*time.Minute) {
		t.Errorf("the oldest must be dropped first; head is %v", got[0].At)
	}
}

func TestLedgerRestore(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{Retention: 24 * time.Hour})
	l.Record(ban(t, "9.9.9.9", "live", epoch))
	if _, ok := l.Flushed(); !ok {
		t.Fatal("expected pending state before restore")
	}
	l.Restore([]model.BanEvent{
		{IP: addr(t, "1.1.1.1"), Monitor: "a", At: epoch.Add(-time.Hour)},
		{IP: addr(t, "2.2.2.2"), Monitor: "a", At: epoch.Add(-48 * time.Hour)}, // past retention
		{Monitor: "junk", At: epoch},                                           // invalid
		{IP: addr(t, "3.3.3.3"), Monitor: "a", At: epoch.Add(-2 * time.Hour)},
	})
	got := l.Snapshot()
	want := []string{"3.3.3.3", "1.1.1.1", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("Snapshot = %+v, want %v", got, want)
	}
	for i, w := range want {
		if got[i].IP != addr(t, w) {
			t.Fatalf("Snapshot order = %+v, want %v", got, want)
		}
	}
	if l.Dirty() {
		t.Error("Restore of already-persisted events must not dirty the ledger")
	}
}

func TestLedgerFlushedAndMarkDirty(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{})
	if ev, ok := l.Flushed(); ok || ev != nil {
		t.Fatal("Flushed on a clean ledger must report nothing")
	}
	l.Record(ban(t, "1.1.1.1", "a", epoch))
	ev, ok := l.Flushed()
	if !ok || len(ev) != 1 {
		t.Fatalf("Flushed = %v, %v", ev, ok)
	}
	if l.Dirty() {
		t.Error("Flushed must clear the dirty flag")
	}
	l.MarkDirty()
	if ev, ok := l.Flushed(); !ok || len(ev) != 1 {
		t.Errorf("after MarkDirty Flushed = %v, %v; want the events again", ev, ok)
	}
}

func TestLedgerDefaults(t *testing.T) {
	t.Parallel()
	l := NewLedger(Options{})
	if l.Retention() != 30*24*time.Hour {
		t.Errorf("default retention = %v", l.Retention())
	}
	if l.maxEvents != DefaultMaxEvents {
		t.Errorf("default cap = %d", l.maxEvents)
	}
	if l.now == nil {
		t.Error("nil clock")
	}
}

// --- Summarize ---------------------------------------------------------

type fakeGeo map[string]string

func (g fakeGeo) Country(ip netip.Addr) (string, bool) {
	code, ok := g[ip.String()]
	return code, ok
}

func fakeName(code string) string {
	return map[string]string{"DE": "Germany", "CN": "China", "US": "United States"}[code]
}

func events(t *testing.T, specs ...struct {
	ip, mon string
	ago     time.Duration
}) []model.BanEvent {
	t.Helper()
	out := make([]model.BanEvent, 0, len(specs))
	for _, s := range specs {
		out = append(out, model.BanEvent{IP: addr(t, s.ip), Monitor: s.mon, At: epoch.Add(-s.ago)})
	}
	return out
}

type spec = struct {
	ip, mon string
	ago     time.Duration
}

func windowByName(t *testing.T, s Summary, name string) Window {
	t.Helper()
	for _, w := range s.Windows {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("window %q missing from %+v", name, s.Windows)
	return Window{}
}

func TestSummarizeWindows(t *testing.T) {
	t.Parallel()
	ev := events(t,
		spec{"1.1.1.1", "sshd", 10 * time.Minute},
		spec{"1.1.1.1", "sshd", 50 * time.Minute},
		spec{"2.2.2.2", "sshd", 3 * time.Hour},
		spec{"3.3.3.3", "nginx", 3 * 24 * time.Hour},
		spec{"4.4.4.4", "nginx", 20 * 24 * time.Hour},
		spec{"5.5.5.5", "nginx", 40 * 24 * time.Hour}, // outside every window
	)
	s := Summarize(ev, nil, epoch, SummaryOptions{Location: time.UTC, Retention: 45 * 24 * time.Hour})

	want := map[string][2]int{WindowHour: {2, 1}, WindowDay: {3, 2}, WindowWeek: {4, 3}, WindowMonth: {5, 4}}
	for name, w := range want {
		got := windowByName(t, s, name)
		if got.Bans != w[0] || got.UniqueIPs != w[1] {
			t.Errorf("%s: bans=%d unique=%d, want %d/%d", name, got.Bans, got.UniqueIPs, w[0], w[1])
		}
	}
	if s.Events != 6 || s.UniqueOffenders != 5 || s.RepeatOffenders != 1 {
		t.Errorf("Events=%d Unique=%d Repeat=%d", s.Events, s.UniqueOffenders, s.RepeatOffenders)
	}
	if s.RetentionSeconds != 45*24*3600 {
		t.Errorf("RetentionSeconds = %d", s.RetentionSeconds)
	}
	if s.Timezone != "UTC" {
		t.Errorf("Timezone = %q", s.Timezone)
	}
	if !s.GeneratedAt.Equal(epoch) {
		t.Errorf("GeneratedAt = %v", s.GeneratedAt)
	}
	if s.GeoEnabled || s.Countries != nil || s.IPCountries != nil {
		t.Errorf("geography must be absent without a database: %+v", s)
	}
}

func TestSummarizeMonitors(t *testing.T) {
	t.Parallel()
	ev := events(t,
		spec{"1.1.1.1", "sshd", time.Minute},
		spec{"2.2.2.2", "sshd", 2 * 24 * time.Hour},
		spec{"3.3.3.3", "nginx", 10 * 24 * time.Hour},
	)
	active := []model.Ban{
		ban(t, "1.1.1.1", "sshd", epoch.Add(-time.Minute)),
		ban(t, "2001:db8::1", "sshd", epoch.Add(-time.Minute)),
		ban(t, "9.9.9.9", "manual", epoch),
	}
	s := Summarize(ev, active, epoch, SummaryOptions{Location: time.UTC})

	if len(s.Monitors) != 3 {
		t.Fatalf("Monitors = %+v, want manual, nginx, sshd", s.Monitors)
	}
	names := []string{s.Monitors[0].Name, s.Monitors[1].Name, s.Monitors[2].Name}
	if !slices.Equal(names, []string{"manual", "nginx", "sshd"}) {
		t.Errorf("monitor order = %v", names)
	}
	sshd := s.Monitors[2]
	if sshd.Active != 2 || sshd.Bans[WindowDay] != 1 || sshd.Bans[WindowWeek] != 2 || sshd.Bans[WindowMonth] != 2 {
		t.Errorf("sshd row = %+v", sshd)
	}
	manual := s.Monitors[0]
	if manual.Active != 1 || manual.Bans[WindowMonth] != 0 {
		t.Errorf("manual row = %+v (a monitor with only live bans still gets zeroed windows)", manual)
	}
	if s.Families.IPv4 != 2 || s.Families.IPv6 != 1 {
		t.Errorf("Families = %+v", s.Families)
	}
}

func TestSummarizeTimelines(t *testing.T) {
	t.Parallel()
	// Use a zone with a non-whole-hour offset to catch Truncate mistakes.
	loc := time.FixedZone("IST", 5*3600+30*60)
	now := time.Date(2024, 3, 15, 10, 45, 0, 0, loc) // 10:45 local
	mk := func(ip string, at time.Time) model.BanEvent {
		return model.BanEvent{IP: addr(t, ip), Monitor: "m", At: at}
	}
	ev := []model.BanEvent{
		mk("1.1.1.1", now), // this hour, today
		mk("2.2.2.2", time.Date(2024, 3, 15, 10, 0, 0, 0, loc)),      // this hour, exactly on the hour
		mk("3.3.3.3", time.Date(2024, 3, 15, 9, 59, 59, 0, loc)),     // previous hour
		mk("4.4.4.4", time.Date(2024, 3, 14, 11, 0, 0, 0, loc)),      // oldest hour bucket (23h ago on the hour)
		mk("5.5.5.5", time.Date(2024, 3, 14, 10, 59, 59, 0, loc)),    // just outside the 24 hourly buckets, but yesterday
		mk("6.6.6.6", time.Date(2024, 2, 15, 0, 0, 0, 0, loc)),       // first day bucket (29 days ago)
		mk("7.7.7.7", time.Date(2024, 2, 14, 23, 59, 59, 0, loc)),    // outside the daily buckets
		mk("8.8.8.8", time.Date(2024, 3, 15, 23, 0, 0, 0, time.UTC)), // future in UTC terms? no: 04:30 next day local -> outside
	}
	s := Summarize(ev, nil, now, SummaryOptions{Location: loc})

	if len(s.BansPerHour) != 24 || len(s.BansPerDay) != 30 {
		t.Fatalf("bucket counts %d/%d", len(s.BansPerHour), len(s.BansPerDay))
	}
	if got := s.BansPerHour[23].Start; !got.Equal(time.Date(2024, 3, 15, 10, 0, 0, 0, loc)) {
		t.Errorf("last hourly bucket starts %v, want 10:00 local", got)
	}
	if got := s.BansPerHour[0].Start; !got.Equal(time.Date(2024, 3, 14, 11, 0, 0, 0, loc)) {
		t.Errorf("first hourly bucket starts %v, want yesterday 11:00 local", got)
	}
	if s.BansPerHour[23].Bans != 2 || s.BansPerHour[22].Bans != 1 || s.BansPerHour[0].Bans != 1 {
		t.Errorf("hourly = %+v", s.BansPerHour)
	}
	var hourly int
	for _, b := range s.BansPerHour {
		hourly += b.Bans
	}
	if hourly != 4 {
		t.Errorf("hourly total = %d, want 4", hourly)
	}

	if got := s.BansPerDay[29].Start; !got.Equal(time.Date(2024, 3, 15, 0, 0, 0, 0, loc)) {
		t.Errorf("last daily bucket starts %v, want local midnight today", got)
	}
	if got := s.BansPerDay[0].Start; !got.Equal(time.Date(2024, 2, 15, 0, 0, 0, 0, loc)) {
		t.Errorf("first daily bucket starts %v, want 29 days ago", got)
	}
	if s.BansPerDay[29].Bans != 3 || s.BansPerDay[28].Bans != 2 || s.BansPerDay[0].Bans != 1 {
		t.Errorf("daily = today %d, yesterday %d, first %d", s.BansPerDay[29].Bans, s.BansPerDay[28].Bans, s.BansPerDay[0].Bans)
	}
	var daily int
	for _, b := range s.BansPerDay {
		daily += b.Bans
	}
	if daily != 6 {
		t.Errorf("daily total = %d, want 6", daily)
	}

	// Hour-of-day and weekday are over everything, in local time: hour 10
	// has now, 10:00 today and 10:59 yesterday.
	if s.ByHourOfDay[10] != 3 || s.ByHourOfDay[9] != 1 || s.ByHourOfDay[11] != 1 || s.ByHourOfDay[0] != 1 || s.ByHourOfDay[4] != 1 {
		t.Errorf("ByHourOfDay = %v", s.ByHourOfDay)
	}
	var total int
	for _, n := range s.ByHourOfDay {
		total += n
	}
	if total != len(ev) {
		t.Errorf("ByHourOfDay sums to %d, want %d", total, len(ev))
	}
	// 2024-03-15 is a Friday, 03-14 a Thursday, 02-15 a Thursday, 02-14 Wednesday,
	// 03-16 (the UTC 23:00 event, local 04:30 next day) a Saturday.
	if s.ByWeekday[time.Friday] != 3 || s.ByWeekday[time.Thursday] != 3 || s.ByWeekday[time.Wednesday] != 1 || s.ByWeekday[time.Saturday] != 1 {
		t.Errorf("ByWeekday = %v", s.ByWeekday)
	}
}

// TestSummarizeDailyBucketsSurviveDST: the day a clock changes is 23 or 25
// hours long; buckets must still be anchored to midnight, not to now-24h*k.
func TestSummarizeDailyBucketsSurviveDST(t *testing.T) {
	t.Parallel()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("tzdata unavailable:", err)
	}
	now := time.Date(2024, 4, 5, 12, 0, 0, 0, loc) // DST began 2024-03-31
	s := Summarize(nil, nil, now, SummaryOptions{Location: loc})
	for i, b := range s.BansPerDay {
		if b.Start.Hour() != 0 || b.Start.Minute() != 0 {
			t.Errorf("bucket %d starts at %v, not midnight", i, b.Start)
		}
	}
	if !s.BansPerDay[0].Start.Equal(time.Date(2024, 3, 7, 0, 0, 0, 0, loc)) {
		t.Errorf("first bucket = %v", s.BansPerDay[0].Start)
	}
}

// TestSummarizeDailyBucketsWhenMidnightDoesNotExist: Chile springs forward
// at 00:00, so on 2024-09-08 there is no local midnight and time.Date(…,0,0)
// normalises to 23:00 the day before. Buckets must still be keyed by calendar
// date, and an event on any of the 30 days must land in exactly one bucket.
func TestSummarizeDailyBucketsWhenMidnightDoesNotExist(t *testing.T) {
	t.Parallel()
	loc, err := time.LoadLocation("America/Santiago")
	if err != nil {
		t.Skip("tzdata unavailable:", err)
	}
	now := time.Date(2024, 9, 8, 15, 0, 0, 0, loc) // the transition day
	mk := func(y int, m time.Month, d, h int) model.BanEvent {
		return model.BanEvent{IP: addr(t, "1.1.1.1"), Monitor: "m", At: time.Date(y, m, d, h, 0, 0, 0, loc)}
	}
	ev := []model.BanEvent{
		mk(2024, 9, 8, 14), // today
		mk(2024, 9, 8, 1),  // today, first hour after the gap
		mk(2024, 9, 7, 23), // yesterday, the instant "today 00:00" normalises to
		mk(2024, 9, 7, 2),  // yesterday
		mk(2024, 8, 29, 9), // ten days ago
		mk(2024, 8, 10, 9), // first bucket (29 days ago)
	}
	s := Summarize(ev, nil, now, SummaryOptions{Location: loc})
	total := 0
	for _, b := range s.BansPerDay {
		total += b.Bans
	}
	if total != len(ev) {
		t.Fatalf("daily buckets hold %d of %d events: %+v", total, len(ev), s.BansPerDay)
	}
	if s.BansPerDay[29].Bans != 2 || s.BansPerDay[28].Bans != 2 || s.BansPerDay[19].Bans != 1 || s.BansPerDay[0].Bans != 1 {
		t.Errorf("today %d, yesterday %d, 10d ago %d, first %d", s.BansPerDay[29].Bans, s.BansPerDay[28].Bans, s.BansPerDay[19].Bans, s.BansPerDay[0].Bans)
	}
	// Every bucket start is on its own calendar day, in order.
	for i := 1; i < len(s.BansPerDay); i++ {
		if !s.BansPerDay[i].Start.After(s.BansPerDay[i-1].Start) {
			t.Errorf("bucket %d (%v) does not follow bucket %d (%v)", i, s.BansPerDay[i].Start, i-1, s.BansPerDay[i-1].Start)
		}
	}
}

func TestSummarizeTopOffenders(t *testing.T) {
	t.Parallel()
	ev := events(t,
		spec{"1.1.1.1", "sshd", time.Hour},
		spec{"1.1.1.1", "nginx", 2 * time.Hour},
		spec{"1.1.1.1", "sshd", 3 * time.Hour},
		spec{"2.2.2.2", "sshd", time.Minute},
		spec{"2.2.2.2", "sshd", 5 * time.Hour},
		spec{"3.3.3.3", "sshd", 10 * time.Hour},
		spec{"4.4.4.4", "sshd", 10 * time.Minute},
	)
	s := Summarize(ev, nil, epoch, SummaryOptions{Location: time.UTC, TopN: 3})
	if len(s.TopOffenders) != 3 {
		t.Fatalf("TopOffenders = %+v, want 3", s.TopOffenders)
	}
	top := s.TopOffenders[0]
	if top.IP != addr(t, "1.1.1.1") || top.Bans != 3 || !top.LastAt.Equal(epoch.Add(-time.Hour)) || !slices.Equal(top.Monitors, []string{"nginx", "sshd"}) {
		t.Errorf("top = %+v", top)
	}
	if s.TopOffenders[1].IP != addr(t, "2.2.2.2") {
		t.Errorf("second = %+v", s.TopOffenders[1])
	}
	// Tie on count (1 each) broken by most recent first.
	if s.TopOffenders[2].IP != addr(t, "4.4.4.4") {
		t.Errorf("third = %+v, want the more recent single offender", s.TopOffenders[2])
	}
	if s.RepeatOffenders != 2 || s.UniqueOffenders != 4 {
		t.Errorf("Repeat=%d Unique=%d", s.RepeatOffenders, s.UniqueOffenders)
	}
}

func TestSummarizeGeography(t *testing.T) {
	t.Parallel()
	geo := fakeGeo{"1.1.1.1": "DE", "2.2.2.2": "CN", "3.3.3.3": "CN", "4.4.4.4": "US", "2001:db8::1": "DE"}
	ev := events(t,
		spec{"1.1.1.1", "sshd", time.Hour},
		spec{"2.2.2.2", "sshd", time.Hour},
		spec{"3.3.3.3", "sshd", time.Hour},
		spec{"4.4.4.4", "sshd", time.Hour},
		spec{"5.5.5.5", "sshd", time.Hour}, // not in the database
		spec{"2.2.2.2", "sshd", 2 * time.Hour},
	)
	active := []model.Ban{
		ban(t, "2001:db8::1", "sshd", epoch),
		ban(t, "5.5.5.5", "sshd", epoch),
		ban(t, "2.2.2.2", "sshd", epoch),
	}
	s := Summarize(ev, active, epoch, SummaryOptions{Location: time.UTC, Geo: geo, CountryName: fakeName, TopN: 2})

	if !s.GeoEnabled {
		t.Fatal("GeoEnabled must be set when a database is given")
	}
	// Over retention: CN 3, DE 1, US 1, ZZ 1 -> top 2 is CN, DE; other = 2.
	wantAll := []Country{{"CN", "China", 3}, {"DE", "Germany", 1}, {CountryOther, "Other", 2}}
	if !slices.Equal(s.Countries, wantAll) {
		t.Errorf("Countries = %+v, want %+v", s.Countries, wantAll)
	}
	// Active: CN 1, DE 1, ZZ 1 -> sorted by count then code: CN, DE, then other=1.
	wantActive := []Country{{"CN", "China", 1}, {"DE", "Germany", 1}, {CountryOther, "Other", 1}}
	if !slices.Equal(s.ActiveCountries, wantActive) {
		t.Errorf("ActiveCountries = %+v, want %+v", s.ActiveCountries, wantActive)
	}
	if s.IPCountries["2001:db8::1"] != "DE" || s.IPCountries["5.5.5.5"] != CountryUnknown || s.IPCountries["2.2.2.2"] != "CN" {
		t.Errorf("IPCountries = %v", s.IPCountries)
	}
	if s.TopOffenders[0].IP != addr(t, "2.2.2.2") || s.TopOffenders[0].Country != "CN" {
		t.Errorf("top offender = %+v", s.TopOffenders[0])
	}
	if _, ok := s.IPCountries[s.TopOffenders[1].IP.String()]; !ok {
		t.Error("top offenders must be present in IPCountries")
	}
}

func TestSummarizeUnknownRanksAsCountry(t *testing.T) {
	t.Parallel()
	ev := events(t, spec{"5.5.5.5", "sshd", time.Hour}, spec{"6.6.6.6", "sshd", time.Hour})
	s := Summarize(ev, nil, epoch, SummaryOptions{Location: time.UTC, Geo: fakeGeo{}, CountryName: fakeName})
	want := []Country{{CountryUnknown, "Unknown", 2}}
	if !slices.Equal(s.Countries, want) {
		t.Errorf("Countries = %+v, want %+v", s.Countries, want)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	t.Parallel()
	s := Summarize(nil, nil, epoch, SummaryOptions{Location: time.UTC})
	if len(s.Windows) != 4 || len(s.BansPerHour) != 24 || len(s.BansPerDay) != 30 {
		t.Errorf("empty summary lost its shape: %+v", s)
	}
	if s.Monitors == nil || len(s.Monitors) != 0 {
		t.Errorf("Monitors = %#v, want empty non-nil", s.Monitors)
	}
	if len(s.TopOffenders) != 0 {
		t.Errorf("TopOffenders = %+v", s.TopOffenders)
	}
}

func TestSummarizeFutureEventCountsAsNow(t *testing.T) {
	t.Parallel()
	// A ban stamped slightly in the future (clock step between the ban
	// manager and the summariser) belongs in every window, not in none.
	ev := []model.BanEvent{{IP: addr(t, "1.1.1.1"), Monitor: "m", At: epoch.Add(2 * time.Second)}}
	s := Summarize(ev, nil, epoch, SummaryOptions{Location: time.UTC})
	if windowByName(t, s, WindowHour).Bans != 1 {
		t.Errorf("future event dropped from the 1h window: %+v", s.Windows)
	}
}

func BenchmarkSummarize(b *testing.B) {
	ev := make([]model.BanEvent, DefaultMaxEvents)
	for i := range ev {
		ev[i] = model.BanEvent{
			IP:      netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1}),
			Monitor: "sshd",
			At:      epoch.Add(-time.Duration(i) * 20 * time.Second),
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		Summarize(ev, nil, epoch, SummaryOptions{Location: time.UTC})
	}
}

func TestLedgerSetRetention(t *testing.T) {
	t.Parallel()
	l, _ := newTestLedger(Options{Retention: 48 * time.Hour})
	l.Record(ban(t, "1.1.1.1", "a", epoch.Add(-30*time.Hour)))
	l.Record(ban(t, "2.2.2.2", "a", epoch.Add(-time.Hour)))
	l.SetRetention(0) // ignored
	if l.Retention() != 48*time.Hour || l.Len() != 2 {
		t.Fatalf("SetRetention(0) changed state: %v, %d", l.Retention(), l.Len())
	}
	l.SetRetention(24 * time.Hour)
	if l.Retention() != 24*time.Hour {
		t.Errorf("Retention = %v", l.Retention())
	}
	if got := l.Snapshot(); len(got) != 1 || got[0].IP != addr(t, "2.2.2.2") {
		t.Errorf("shrinking retention must prune at once; got %+v", got)
	}
}
