package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"banhammer/internal/config"
	"banhammer/internal/rule"
	"banhammer/internal/window"
	"github.com/spf13/cobra"
)

func newTestCmd(root *rootFlags) *cobra.Command {
	var (
		monitor string
		file    string
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Simulate regex matching and ban timeline against sample logs",
		Long:  "Test is the regex authoring simulator: it processes sample log files line-by-line, displays per-line verdicts and extracted IPs, and simulates sliding-window ban triggers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if root.config == "" {
				return errors.New("configuration file required (-c, --config)")
			}
			if monitor == "" {
				return errors.New("monitor name required (-m, --monitor)")
			}
			if file == "" {
				return errors.New("sample log file required (-f, --file)")
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

			simTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
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
				distinctIPs   = make(map[netip.Addr]struct{})
			)

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

				simTime = simTime.Add(time.Second)

				res, outcome := set.Match(line)
				switch outcome {
				case rule.OutcomeMatch:
					linesMatched++
					distinctIPs[res.IP] = struct{}{}
					fmt.Fprintf(out, "line %d: match  ip=%s  pattern=%q\n", linesRead, res.IP, res.Pattern)
					count, triggered := tracker.Hit(res.IP)
					if triggered {
						bansTriggered++
						fmt.Fprintf(out, "[BAN] %s triggered (count=%d)\n", res.IP, count)
					}
				case rule.OutcomeNoMatch:
					fmt.Fprintf(out, "line %d: no-match\n", linesRead)
				case rule.OutcomeIgnored:
					fmt.Fprintf(out, "line %d: ignored  pattern=%q\n", linesRead, res.Pattern)
				case rule.OutcomeDecodeError:
					fmt.Fprintf(out, "line %d: error (decode error)\n", linesRead)
				case rule.OutcomeNoIP:
					fmt.Fprintf(out, "line %d: error (no IP extracted)  pattern=%q\n", linesRead, res.Pattern)
				}

				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return fmt.Errorf("read sample file: %w", err)
				}
			}

			fmt.Fprintf(out, "\n--- Summary ---\n")
			fmt.Fprintf(out, "Lines read:     %d\n", linesRead)
			fmt.Fprintf(out, "Lines matched:  %d\n", linesMatched)
			fmt.Fprintf(out, "Bans triggered: %d\n", bansTriggered)
			fmt.Fprintf(out, "Distinct IPs:   %d\n", len(distinctIPs))

			return nil
		},
	}

	cmd.Flags().StringVarP(&monitor, "monitor", "m", "", "monitor name to test (required)")
	cmd.Flags().StringVarP(&file, "file", "f", "", "sample log file path, or '-' for stdin (required)")

	_ = cmd.MarkFlagRequired("monitor")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}
