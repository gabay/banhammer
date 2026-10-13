package web

import (
	_ "embed"
	"fmt"
	"html/template"
	"maps"
	"slices"
	"strings"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/stats"
)

//go:embed page.html
var pageSource string

// page is parsed once at init; a template that does not parse is a build
// error in disguise and should fail the first test, not the first request.
var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"n": fmtInt,
}).Parse(pageSource))

// view is what the template sees. Everything is pre-formatted here so the
// template stays declarative, and so that the only values reaching it are
// strings and integers that html/template escapes by context. None of the
// package's "trusted content" types is ever constructed: nothing the daemon
// shows is trusted markup, and a test greps the source to keep it that way.
type view struct {
	GeneratedAt string
	Uptime      string
	Refresh     int // seconds; 0 disables the meta refresh
	Timezone    string
	Retention   string
	Events      int

	Cards []card
	Warn  []string

	HasHistory bool
	Hourly     chart
	Daily      chart
	HourOfDay  chart
	Weekday    chart

	GeoEnabled      bool
	ActiveCountries []countryRow
	AllCountries    []countryRow

	Monitors  []monitorRow
	Offenders []offenderRow
	Bans      []banRow
	// BansTotal is the number of active bans; BansOmitted how many of them
	// the table leaves out once it hits maxBanRows.
	BansTotal   int
	BansOmitted int

	RepeatOffenders int
	UniqueOffenders int
}

type card struct {
	Value string
	Label string
	Sub   string
	Warn  bool
}

// chart is a CSS bar chart: each bar's height is a percentage of the tallest.
type chart struct {
	Bars  []bar
	Max   int
	Total int
}

type bar struct {
	Pct     int // 0..100 of Max; a non-zero value is never shown shorter than 2
	Value   int
	Label   string // short axis label; empty to skip
	Title   string // tooltip
	Current bool   // the bucket "now" falls in
}

type countryRow struct {
	Flag string
	Code string
	Name string
	Bans int
	Pct  int
}

type monitorRow struct {
	Name, Type, Target string
	Tracked, Active    int
	Day, Week, Month   int
	HasHistory         bool
}

type offenderRow struct {
	IP       string
	Flag     string
	Code     string
	Country  string
	Bans     int
	LastAt   string
	LastAgo  string
	Monitors string
}

type banRow struct {
	IP      string
	Flag    string
	Code    string
	Country string
	Monitor string
	Offense int
	Count   int
	At      string
	Expires string
	Matched string
}

// maxBanRows bounds the active-bans table. An ipset deployment can hold
// 100k+ bans, and a page with one row each is tens of megabytes rendered once
// a second under load; nobody reads row 50 000 anyway. The list is sorted by
// expiry, so what is shown is what is about to change. /status.json is the
// complete list.
const maxBanRows = 500

// buildView turns a status response into the page's view model.
func buildView(resp control.StatusResponse, now time.Time, loc *time.Location, refresh time.Duration, countryName func(string) string) view {
	if loc == nil {
		loc = time.Local
	}
	nowLoc := now.In(loc)
	v := view{
		GeneratedAt: fmtTime(nowLoc),
		Uptime:      humanDuration(resp.Uptime),
		Refresh:     int(refresh / time.Second),
		Timezone:    zoneName(nowLoc),
	}

	h := resp.History
	v.HasHistory = h != nil
	codeOf := func(ip string) string {
		if h == nil || h.IPCountries == nil {
			return ""
		}
		return h.IPCountries[ip]
	}
	label := func(code string) (flag, name string) {
		switch code {
		case "":
			return "", ""
		case stats.CountryUnknown:
			return "", "Unknown"
		}
		return flagOf(code), countryName(code)
	}

	// --- cards ---------------------------------------------------------
	active := len(resp.Bans)
	activeSub := ""
	if h != nil {
		activeSub = fmt.Sprintf("%s IPv4 · %s IPv6", fmtInt(h.Families.IPv4), fmtInt(h.Families.IPv6))
	}
	v.Cards = append(v.Cards, card{Value: fmtInt(active), Label: "active bans", Sub: activeSub})
	if h != nil {
		for _, w := range h.Windows {
			if w.Name == stats.WindowHour {
				continue // the 24h chart shows it; four cards of windows is one too many
			}
			v.Cards = append(v.Cards, card{
				Value: fmtInt(w.Bans),
				Label: "bans · last " + w.Name,
				Sub:   fmtInt(w.UniqueIPs) + " unique",
			})
		}
		v.Retention = humanDuration(time.Duration(h.RetentionSeconds) * time.Second)
		v.Events = h.Events
		v.RepeatOffenders = h.RepeatOffenders
		v.UniqueOffenders = h.UniqueOffenders
	}
	st := resp.Stats
	v.Cards = append(v.Cards,
		card{Value: fmtInt(int(st.LinesRead)), Label: "lines read", Sub: fmtInt(int(st.Matches)) + " matched"},
		card{Value: fmtInt(int(st.TrackedIPs)), Label: "tracked IPs", Sub: "below threshold"},
		card{Value: fmtInt(int(st.BansTotal)), Label: "bans since start", Sub: fmtInt(int(st.UnbansTotal)) + " lifted"},
	)
	errs := card{Value: fmtInt(int(st.ActionErrors)), Label: "action errors", Sub: fmtInt(int(st.DecodeErrors)) + " decode errors"}
	if st.ActionErrors > 0 {
		errs.Warn = true
		v.Warn = append(v.Warn, fmt.Sprintf("%s firewall action(s) failed since start — check the daemon log.", fmtInt(int(st.ActionErrors))))
	}
	if st.LinesDropped > 0 {
		v.Warn = append(v.Warn, fmt.Sprintf("%s log line(s) were dropped under load; consider raising queue_size.", fmtInt(int(st.LinesDropped))))
	}
	v.Cards = append(v.Cards, errs)

	// --- charts --------------------------------------------------------
	if h != nil {
		v.Hourly = timeline(h.BansPerHour, loc, now, time.Hour, func(t time.Time) string {
			if t.Hour()%6 == 0 {
				return t.Format("15:04")
			}
			return ""
		}, func(t time.Time) string { return t.Format("Mon 15:04") + " – " + t.Add(time.Hour).Format("15:04") })
		v.Daily = timeline(h.BansPerDay, loc, now, 24*time.Hour, func(t time.Time) string {
			if t.Day() == 1 || t.Weekday() == time.Monday {
				return t.Format("Jan 2")
			}
			return ""
		}, func(t time.Time) string { return t.Format("Mon, Jan 2") })

		hod := make([]bar, 24)
		for i, n := range h.ByHourOfDay {
			hod[i] = bar{Value: n, Title: fmt.Sprintf("%02d:00 – %02d:59", i, i), Current: i == nowLoc.Hour()}
			if i%6 == 0 {
				hod[i].Label = fmt.Sprintf("%02d", i)
			}
		}
		v.HourOfDay = scale(hod)

		wd := make([]bar, 7)
		for i, n := range h.ByWeekday {
			day := time.Weekday(i)
			wd[i] = bar{Value: n, Label: day.String()[:3], Title: day.String(), Current: day == nowLoc.Weekday()}
		}
		v.Weekday = scale(wd)

		v.GeoEnabled = h.GeoEnabled
		v.ActiveCountries = countries(h.ActiveCountries)
		v.AllCountries = countries(h.Countries)
	}

	// --- tables --------------------------------------------------------
	byMonitor := make(map[string]stats.MonitorSummary)
	if h != nil {
		for _, m := range h.Monitors {
			byMonitor[m.Name] = m
		}
	}
	for _, m := range resp.Monitors {
		row := monitorRow{Name: m.Name, Type: m.Type, Target: m.Target, Tracked: m.TrackedIPs, HasHistory: h != nil}
		if hs, ok := byMonitor[m.Name]; ok {
			row.Active = hs.Active
			row.Day = hs.Bans[stats.WindowDay]
			row.Week = hs.Bans[stats.WindowWeek]
			row.Month = hs.Bans[stats.WindowMonth]
			delete(byMonitor, m.Name)
		}
		v.Monitors = append(v.Monitors, row)
	}
	// Monitors that only exist in history (renamed, removed, or "manual").
	for _, name := range slices.Sorted(maps.Keys(byMonitor)) {
		hs := byMonitor[name]
		v.Monitors = append(v.Monitors, monitorRow{
			Name: name, Type: "—", Target: "not in current config", HasHistory: true,
			Active: hs.Active, Day: hs.Bans[stats.WindowDay], Week: hs.Bans[stats.WindowWeek], Month: hs.Bans[stats.WindowMonth],
		})
	}

	if h != nil {
		for _, o := range h.TopOffenders {
			flag, name := label(o.Country)
			v.Offenders = append(v.Offenders, offenderRow{
				IP:       o.IP.String(),
				Flag:     flag,
				Code:     o.Country,
				Country:  name,
				Bans:     o.Bans,
				LastAt:   fmtTime(o.LastAt.In(loc)),
				LastAgo:  humanDuration(now.Sub(o.LastAt)) + " ago",
				Monitors: strings.Join(o.Monitors, ", "),
			})
		}
	}

	v.BansTotal = len(resp.Bans)
	shown := resp.Bans
	if len(shown) > maxBanRows {
		shown = shown[:maxBanRows]
		v.BansOmitted = len(resp.Bans) - maxBanRows
	}
	for _, b := range shown {
		ip := b.IP.String()
		code := codeOf(ip)
		flag, name := label(code)
		expires := "expired"
		if left := b.Until.Sub(now); left > 0 {
			expires = "in " + humanDuration(left)
		}
		monitor := b.Monitor
		if monitor == "" {
			monitor = "—"
		}
		v.Bans = append(v.Bans, banRow{
			IP:      ip,
			Flag:    flag,
			Code:    code,
			Country: name,
			Monitor: monitor,
			Offense: b.Offense,
			Count:   b.Count,
			At:      fmtTime(b.At.In(loc)),
			Expires: expires,
			Matched: b.Matched,
		})
	}
	return v
}

// timeline turns ledger buckets into bars with axis labels and tooltips.
func timeline(buckets []stats.Bucket, loc *time.Location, now time.Time, width time.Duration, axis, tip func(time.Time) string) chart {
	bars := make([]bar, len(buckets))
	for i, b := range buckets {
		start := b.Start.In(loc)
		bars[i] = bar{
			Value:   b.Bans,
			Label:   axis(start),
			Title:   tip(start),
			Current: !now.Before(b.Start) && now.Before(b.Start.Add(width)),
		}
	}
	// The daily chart's last bucket is "today", which the width test above
	// handles; the DST caveat (23/25 h days) only shifts the Current flag by
	// an hour at the edge, which no one will notice on a bar chart.
	return scale(bars)
}

// scale fills in percentages. A bar with any bans at all is drawn at least
// 2% tall so that "one ban on a quiet day" is visible next to a spike.
func scale(bars []bar) chart {
	c := chart{Bars: bars}
	for _, b := range bars {
		c.Total += b.Value
		c.Max = max(c.Max, b.Value)
	}
	for i := range bars {
		if c.Max > 0 && bars[i].Value > 0 {
			bars[i].Pct = max(2, bars[i].Value*100/c.Max)
		}
		if bars[i].Title != "" {
			bars[i].Title = fmt.Sprintf("%s: %s", bars[i].Title, plural(bars[i].Value, "ban"))
		}
	}
	return c
}

func countries(cs []stats.Country) []countryRow {
	if len(cs) == 0 {
		return nil
	}
	maxBans := 0
	for _, c := range cs {
		maxBans = max(maxBans, c.Bans)
	}
	rows := make([]countryRow, 0, len(cs))
	for _, c := range cs {
		row := countryRow{Code: c.Code, Name: c.Name, Bans: c.Bans}
		switch c.Code {
		case stats.CountryOther:
			row.Code = "…"
		case stats.CountryUnknown:
			row.Code = "??"
		default:
			row.Flag = flagOf(c.Code)
		}
		if row.Name == "" {
			row.Name = c.Code
		}
		if maxBans > 0 {
			row.Pct = max(1, c.Bans*100/maxBans)
		}
		rows = append(rows, row)
	}
	return rows
}

// flagOf is the regional-indicator rendering of an ISO alpha-2 code. It is
// repeated here rather than imported from geoip so that this package depends
// only on the wire types; four lines is cheaper than a dependency edge.
func flagOf(code string) string {
	if len(code) != 2 {
		return ""
	}
	a, b := code[0]&^0x20, code[1]&^0x20 // upper-case ASCII
	if a < 'A' || a > 'Z' || b < 'A' || b > 'Z' {
		return ""
	}
	return string([]rune{rune(0x1F1E6 + int(a-'A')), rune(0x1F1E6 + int(b-'A'))})
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05")
}

// zoneName is "UTC", "CEST", or a numeric offset when the zone has no
// abbreviation worth printing.
func zoneName(t time.Time) string {
	name, off := t.Zone()
	if name == "" || strings.HasPrefix(name, "+") || strings.HasPrefix(name, "-") {
		return fmt.Sprintf("UTC%+03d:%02d", off/3600, abs(off%3600)/60)
	}
	return name
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// humanDuration renders a duration the way an operator reads one: up to two
// units, largest first, no fractions, and no trailing zero unit. "3d 4h",
// "30d", "4h 12m", "12m 5s", "5s".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int(d / time.Minute)
	secs := int((d - time.Duration(mins)*time.Minute) / time.Second)
	two := func(a int, au string, b int, bu string) string {
		if b == 0 {
			return fmt.Sprintf("%d%s", a, au)
		}
		return fmt.Sprintf("%d%s %d%s", a, au, b, bu)
	}
	switch {
	case days > 0:
		return two(days, "d", hours, "h")
	case hours > 0:
		return two(hours, "h", mins, "m")
	case mins > 0:
		return two(mins, "m", secs, "s")
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

// fmtInt groups thousands with a thin space, which reads as a number rather
// than as a list the way commas can in some locales.
func fmtInt(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	if len(s) <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
	}
	for i := head; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteString("\u202f")
		}
		b.WriteString(s[i : i+3])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmtInt(n) + " " + noun + "s"
}
