package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"time"

	"banhammer/internal/ban"
	"banhammer/internal/config"
	"banhammer/internal/rule"
	"banhammer/internal/window"
	"github.com/spf13/cobra"
)

// simStart is the epoch of the simulated timeline. A fixed, obviously
// artificial date keeps output reproducible and makes it plain that these
// timestamps are the simulator's, not the log's.
var simStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestCmd(root *rootFlags) *cobra.Command {
	var (
		monitor string
		file    string
		rate    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Simulate regex matching and ban timeline against sample logs",
		Long: "Test is the regex authoring simulator: it processes sample log files line-by-line, displays per-line verdicts and extracted IPs, " +
			"and simulates a sliding-window ban timeline including when each ban would be lifted.\n\n" +
			"The clock is synthetic. Timestamps inside the log are not parsed: the simulation starts at " + simStart.Format(time.RFC3339) +
			" and advances by --rate for every line read, so a file replayed at the default 1s/line compresses a week of real traffic into minutes " +
			"and will report bans that the daemon would never have issued. Match --rate to the sample's real average line spacing for a realistic timeline.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if root.config == "" {
				return errors.New("configuration file required (-c, --config)")
			}
			if rate <= 0 {
				return fmt.Errorf("invalid --rate %s: must be positive", rate)
			}

			cfg, err := config.Load(root.config)
			if err != nil {
				return fmt.Errorf("load config %q: %w", root.config, err)
			}

			mon, ok := cfg.Monitors[monitor]
			if !ok {
				return fmt.Errorf("monitor %q not found in configuration", monitor)
			}

			spec := rule.Spec{
				Format:       mon.Format,
				Line:         mon.Match.Line,
				Fields:       mon.Match.Fields,
				IgnoreLine:   mon.Ignore.Line,
				IgnoreFields: mon.Ignore.Fields,
				IPField:      mon.IPField,
				Contains:     mon.Contains,
			}
			set, err := rule.Compile(spec)
			if err != nil {
				return fmt.Errorf("compile rules for monitor %q: %w", monitor, err)
			}

			// The allowlist is what stops the daemon banning 127.0.0.1; a
			// simulator that ignores it predicts bans that would never happen.
			// A Manager with no enforcer and no persister is exactly the
			// read-only allowlist oracle we want here.
			allowLog := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn}))
			allow := ban.NewManager(ban.Options{
				Allowlist:  cfg.Allowlist,
				AllowLocal: cfg.AllowLocal,
				Log:        allowLog,
			})

			simTime := simStart
			nowFunc := func() time.Time { return simTime }
			tracker := window.New(mon.Threshold, mon.Window, mon.MaxTracked, nowFunc)

			var r io.Reader
			if file == "-" {
				r = cmd.InOrStdin()
			} else {
				f, err := os.Open(file)
				if err != nil {
					return fmt.Errorf("open sample file %q: %w", file, err)
				}
				defer f.Close()
				r = f
			}

			reader := bufio.NewReader(r)
			out := cmd.OutOrStdout()
			var (
				linesRead     int
				linesMatched  int
				bansTriggered int
				bansLifted    int
				allowlisted   int
				distinctIPs   = make(map[netip.Addr]struct{})
				// active maps a banned address to the moment the simulated
				// daemon would lift its ban.
				active = make(map[netip.Addr]time.Time)
			)

			stamp := func() string { return simTime.Format(time.RFC3339) }

			// expire lifts every ban whose simulated deadline has passed. The
			// map is walked in sorted order so the timeline is reproducible.
			expire := func() {
				due := make([]netip.Addr, 0, len(active))
				for ip, until := range active {
					if !simTime.Before(until) {
						due = append(due, ip)
					}
				}
				slices.SortFunc(due, func(a, b netip.Addr) int { return a.Compare(b) })
				for _, ip := range due {
					delete(active, ip)
					bansLifted++
					fmt.Fprintf(out, "[%s] [UNBAN] %s ban expired\n", stamp(), ip)
				}
			}

			fmt.Fprintf(out, "Simulating monitor %q: threshold %d in %s, bantime %s.\n",
				monitor, mon.Threshold, mon.Window, mon.Bantime)
			fmt.Fprintf(out, "Synthetic clock from %s, +%s per line (log timestamps are not parsed).\n\n",
				simStart.Format(time.RFC3339), rate)

			for {
				line, err := reader.ReadBytes('\n')
				if len(line) == 0 && err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return fmt.Errorf("read sample file: %w", err)
				}
				line = bytes.TrimRight(line, "\r\n")
				linesRead++

				simTime = simTime.Add(rate)
				expire()

				res, outcome := set.Match(line)
				switch outcome {
				case rule.OutcomeMatch:
					linesMatched++
					distinctIPs[res.IP] = struct{}{}
					if allow.Allowed(res.IP) {
						allowlisted++
						fmt.Fprintf(out, "[%s] line %d: allowlisted  ip=%s  pattern=%q\n", stamp(), linesRead, res.IP, res.Pattern)
						break
					}
					fmt.Fprintf(out, "[%s] line %d: match  ip=%s  pattern=%q\n", stamp(), linesRead, res.IP, res.Pattern)
					count, triggered := tracker.Hit(res.IP)
					if !triggered {
						break
					}
					until, banned := active[res.IP]
					switch {
					case banned && mon.OnRepeat == "extend":
						until = simTime.Add(mon.Bantime)
						active[res.IP] = until
						fmt.Fprintf(out, "[%s] [BAN] %s extended (count=%d) until %s\n", stamp(), res.IP, count, until.Format(time.RFC3339))
					case banned:
						fmt.Fprintf(out, "[%s] [BAN] %s already banned until %s (on_repeat=%s)\n", stamp(), res.IP, until.Format(time.RFC3339), mon.OnRepeat)
					default:
						bansTriggered++
						until = simTime.Add(mon.Bantime)
						active[res.IP] = until
						fmt.Fprintf(out, "[%s] [BAN] %s triggered (count=%d) until %s\n", stamp(), res.IP, count, until.Format(time.RFC3339))
					}
				case rule.OutcomeNoMatch:
					fmt.Fprintf(out, "[%s] line %d: no-match\n", stamp(), linesRead)
				case rule.OutcomeIgnored:
					fmt.Fprintf(out, "[%s] line %d: ignored  pattern=%q\n", stamp(), linesRead, res.Pattern)
				case rule.OutcomeDecodeError:
					fmt.Fprintf(out, "[%s] line %d: error (decode error)\n", stamp(), linesRead)
				case rule.OutcomeNoIP:
					fmt.Fprintf(out, "[%s] line %d: error (no IP extracted)  pattern=%q\n", stamp(), linesRead, res.Pattern)
				}

				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return fmt.Errorf("read sample file: %w", err)
				}
			}

			fmt.Fprintf(out, "\n--- Summary ---\n")
			fmt.Fprintf(out, "Simulated span: %s to %s\n", simStart.Format(time.RFC3339), simTime.Format(time.RFC3339))
			fmt.Fprintf(out, "Lines read:     %d\n", linesRead)
			fmt.Fprintf(out, "Lines matched:  %d\n", linesMatched)
			fmt.Fprintf(out, "Allowlisted:    %d\n", allowlisted)
			fmt.Fprintf(out, "Bans triggered: %d\n", bansTriggered)
			fmt.Fprintf(out, "Bans expired:   %d\n", bansLifted)
			fmt.Fprintf(out, "Still banned:   %d\n", len(active))
			fmt.Fprintf(out, "Distinct IPs:   %d\n", len(distinctIPs))

			if len(active) > 0 {
				stillBanned := make([]netip.Addr, 0, len(active))
				for ip := range active {
					stillBanned = append(stillBanned, ip)
				}
				slices.SortFunc(stillBanned, func(a, b netip.Addr) int { return a.Compare(b) })
				fmt.Fprintln(out, "\nStill banned at end of simulation:")
				for _, ip := range stillBanned {
					fmt.Fprintf(out, "  %s until %s\n", ip, active[ip].Format(time.RFC3339))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&monitor, "monitor", "m", "", "monitor name to test (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "sample log file path, or '-' for stdin (required)")
	cmd.Flags().DurationVar(&rate, "rate", time.Second, "simulated time between consecutive log lines")

	// Cobra enforces these; the command body only checks -c, which is a
	// persistent flag and cannot be marked required on this subcommand alone.
	_ = cmd.MarkFlagRequired("monitor")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}
