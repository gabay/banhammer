package main

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"banhammer/internal/control"
	"github.com/spf13/cobra"
)

func newBanCmd(root *rootFlags) *cobra.Command {
	var (
		monitor string
		timeStr string
	)

	cmd := &cobra.Command{
		Use:   "ban <ip>",
		Short: "Manually ban an IP address",
		Long:  "Ban instructs the running daemon to immediately ban an IP address across firewall rules for the specified duration.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip, err := netip.ParseAddr(args[0])
			if err != nil {
				return fmt.Errorf("invalid IP address %q: %w", args[0], err)
			}

			dur, err := time.ParseDuration(timeStr)
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", timeStr, err)
			}
			if dur <= 0 {
				return errors.New("ban duration must be positive")
			}

			socketPath := resolveSocketPath(root.socket, root.config)
			client := control.NewClient(socketPath)

			if err := client.Ban(cmd.Context(), ip, monitor, dur); err != nil {
				return fmt.Errorf("ban %s: %w", ip, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "banned %s for %s (monitor: %s)\n", ip, timeStr, monitor)
			return nil
		},
	}

	cmd.Flags().StringVarP(&monitor, "monitor", "m", "manual", "monitor name for the ban policy")
	cmd.Flags().StringVarP(&timeStr, "time", "t", "1h", "ban duration (e.g. 30m, 1h, 24h)")

	return cmd
}
