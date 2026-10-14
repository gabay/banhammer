package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/geoip"
	"banhammer/internal/stats"
	"github.com/spf13/cobra"
)

func newStatusCmd(root *rootFlags) *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Query daemon status, active bans, and pipeline metrics",
		Long:  "Status connects to the running daemon via the Unix domain control socket and displays daemon uptime, operational counters, monitored inputs, and active bans.",
		RunE: func(cmd *cobra.Command, args []string) error {
			socketPath, err := resolveSocketPath(root.socket, root.config)
			if err != nil {
				return err
			}
			client := control.NewClient(socketPath)

			resp, err := client.Status(cmd.Context())
			if err != nil {
				return daemonError("get daemon status", socketPath, err)
			}

			if jsonOutput {
				data, err := json.MarshalIndent(resp, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal json status: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Daemon Uptime: %s\n\n", resp.Uptime.Round(time.Second))

			fmt.Fprintln(out, "Counters:")
			fmt.Fprintf(out, "  Lines Read:     %d\n", resp.Stats.LinesRead)
			fmt.Fprintf(out, "  Lines Dropped:  %d\n", resp.Stats.LinesDropped)
			fmt.Fprintf(out, "  Matches:        %d\n", resp.Stats.Matches)
			fmt.Fprintf(out, "  Tracked IPs:    %d\n", resp.Stats.TrackedIPs)
			// The ban list below is the authoritative answer for "how many are
			// banned right now", so it is counted rather than trusting the
			// gauge, which a scrape may not have refreshed.
			fmt.Fprintf(out, "  Active Bans:    %d\n", len(resp.Bans))
			fmt.Fprintf(out, "  Total Bans:     %d\n", resp.Stats.BansTotal)
			fmt.Fprintf(out, "  Total Unbans:   %d\n", resp.Stats.UnbansTotal)
			fmt.Fprintf(out, "  Action Errors:  %d\n", resp.Stats.ActionErrors)
			fmt.Fprintf(out, "  Decode Errors:  %d\n\n", resp.Stats.DecodeErrors)

			fmt.Fprintln(out, "Monitors:")
			if len(resp.Monitors) == 0 {
				fmt.Fprintln(out, "  (none)")
			} else {
				w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  NAME\tTYPE\tTARGET\tTRACKED IPS")
				for _, m := range resp.Monitors {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%d\n", m.Name, m.Type, m.Target, m.TrackedIPs)
				}
				w.Flush()
			}

			if resp.History != nil {
				printHistory(out, resp.History)
			}

			fmt.Fprintln(out, "\nActive Bans:")
			if len(resp.Bans) == 0 {
				fmt.Fprintln(out, "  (none)")
			} else {
				w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  IP\tMONITOR\tOFFENSE\tCOUNT\tBANNED AT\tEXPIRES IN")
				for _, b := range resp.Bans {
					expiresIn := time.Until(b.Until).Round(time.Second)
					if expiresIn < 0 {
						expiresIn = 0
					}
					fmt.Fprintf(w, "  %s\t%s\t%d\t%d\t%s\t%s\n",
						b.IP, b.Monitor, b.Offense, b.Count,
						b.At.Format("2006-01-02 15:04:05"), expiresIn)
					// The offending line goes on its own row, outside the
					// column grid: it is long, and a tab in it would be
					// read by tabwriter as a cell boundary. The ledger has
					// already replaced control characters, so it is safe
					// to print to a terminal.
					if resp.History != nil {
						if s, ok := resp.History.Samples[b.IP.String()]; ok {
							fmt.Fprintf(w, "    ↳ %s\n", s.Line)
						}
					}
				}
				w.Flush()
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output status in JSON format")

	return cmd
}

// printHistory renders the ledger statistics. It shows what fits on a
// terminal — the windows, the per-monitor split, the worst offenders and the
// top countries — and leaves the timelines to the web page and to --json.
func printHistory(out io.Writer, h *stats.Summary) {
	fmt.Fprintf(out, "\nHistory (last %s, %d events):\n", shortDuration(time.Duration(h.RetentionSeconds)*time.Second), h.Events)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  WINDOW\tBANS\tUNIQUE IPS")
	for _, win := range h.Windows {
		fmt.Fprintf(w, "  %s\t%d\t%d\n", win.Name, win.Bans, win.UniqueIPs)
	}
	w.Flush()
	fmt.Fprintf(out, "  Repeat offenders: %d of %d addresses banned more than once\n", h.RepeatOffenders, h.UniqueOffenders)

	if len(h.Monitors) > 0 {
		fmt.Fprintln(out, "\n  Bans by monitor:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "    MONITOR\tACTIVE\t24H\t7D\t30D")
		for _, m := range h.Monitors {
			fmt.Fprintf(w, "    %s\t%d\t%d\t%d\t%d\n", m.Name, m.Active,
				m.Bans[stats.WindowDay], m.Bans[stats.WindowWeek], m.Bans[stats.WindowMonth])
		}
		w.Flush()
	}

	if len(h.TopOffenders) > 0 {
		fmt.Fprintln(out, "\n  Top offenders:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		if h.GeoEnabled {
			fmt.Fprintln(w, "    IP\tCOUNTRY\tBANS\tLAST BANNED\tMONITORS")
		} else {
			fmt.Fprintln(w, "    IP\tBANS\tLAST BANNED\tMONITORS")
		}
		for _, o := range h.TopOffenders {
			last := o.LastAt.Local().Format("2006-01-02 15:04:05")
			if h.GeoEnabled {
				fmt.Fprintf(w, "    %s\t%s\t%d\t%s\t%s\n", o.IP, countryLabel(o.Country), o.Bans, last, strings.Join(o.Monitors, ","))
			} else {
				fmt.Fprintf(w, "    %s\t%d\t%s\t%s\n", o.IP, o.Bans, last, strings.Join(o.Monitors, ","))
			}
		}
		w.Flush()
	}

	if h.GeoEnabled && len(h.Countries) > 0 {
		fmt.Fprintln(out, "\n  Top countries:")
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "    COUNTRY\tBANS\tACTIVE")
		active := make(map[string]int, len(h.ActiveCountries))
		for _, c := range h.ActiveCountries {
			active[c.Code] = c.Bans
		}
		for _, c := range h.Countries {
			name := c.Name
			if name == "" {
				name = countryLabel(c.Code)
			} else if c.Code != stats.CountryOther && c.Code != stats.CountryUnknown {
				name = fmt.Sprintf("%s (%s)", name, c.Code)
			}
			fmt.Fprintf(w, "    %s\t%d\t%d\n", name, c.Bans, active[c.Code])
		}
		w.Flush()
	}

	// Compact sparkline of the last 24 hours, oldest first. Eight block
	// glyphs are enough to see the shape of a night's brute-forcing.
	if total := sum(h.BansPerHour); total > 0 {
		fmt.Fprintf(out, "\n  Last 24h: %s  (%d bans, peak %d/h)\n", sparkline(h.BansPerHour), total, peak(h.BansPerHour))
	}
	if total := sum(h.BansPerDay); total > 0 {
		fmt.Fprintf(out, "  Last 30d: %s  (%d bans, peak %d/day)\n", sparkline(h.BansPerDay), total, peak(h.BansPerDay))
	}
}

// countryLabel renders a code for the terminal, where there are no flags.
func countryLabel(code string) string {
	switch code {
	case "":
		return "-"
	case stats.CountryUnknown:
		return "unknown"
	}
	if name := geoip.Name(code); name != "" {
		return fmt.Sprintf("%s (%s)", name, code)
	}
	return code
}

var sparks = []rune("▁▂▃▄▅▆▇█")

func sparkline(buckets []stats.Bucket) string {
	top := peak(buckets)
	var b strings.Builder
	for _, bk := range buckets {
		if bk.Bans == 0 || top == 0 {
			b.WriteRune(' ')
			continue
		}
		// Map 1..top onto the eight glyphs so that the smallest non-zero
		// bucket is ▁ and the peak is █; a zero bucket is a space.
		i := len(sparks) - 1
		if top > 1 {
			i = (bk.Bans - 1) * (len(sparks) - 1) / (top - 1)
		}
		b.WriteRune(sparks[min(max(i, 0), len(sparks)-1)])
	}
	return b.String()
}

func sum(buckets []stats.Bucket) int {
	n := 0
	for _, b := range buckets {
		n += b.Bans
	}
	return n
}

func peak(buckets []stats.Bucket) int {
	n := 0
	for _, b := range buckets {
		n = max(n, b.Bans)
	}
	return n
}

// shortDuration prints whole days or hours: "30d", "36h", "90m".
func shortDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		return d.String()
	}
}
