package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"banhammer/internal/control"
	"github.com/spf13/cobra"
)

func newStatusCmd(root *rootFlags) *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Query daemon status, active bans, and pipeline metrics",
		Long:  "Status connects to the running daemon via the Unix domain control socket and displays daemon uptime, operational counters, monitored inputs, and active bans.",
		RunE: func(cmd *cobra.Command, args []string) error {
			socketPath := resolveSocketPath(root.socket, root.config)
			client := control.NewClient(socketPath)

			resp, err := client.Status(cmd.Context())
			if err != nil {
				return fmt.Errorf("get daemon status: %w", err)
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
				}
				w.Flush()
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output status in JSON format")

	return cmd
}
