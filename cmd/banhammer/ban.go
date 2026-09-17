package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"banhammer/internal/control"
	"banhammer/internal/model"
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
		Long: "Ban instructs the running daemon to immediately ban an IP address across firewall rules. " +
			"Without --time the monitor's configured bantime applies.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip, err := netip.ParseAddr(args[0])
			if err != nil {
				return fmt.Errorf("invalid IP address %q: %w", args[0], err)
			}

			// A zero duration is the documented "use the monitor's bantime"
			// signal, supported end to end by control.Service, Client.Ban and
			// the server's dispatch. Defaulting --time to a literal 1h made
			// that path unreachable and quietly overrode `bantime: 24h`.
			var dur time.Duration
			if timeStr != "" {
				dur, err = time.ParseDuration(timeStr)
				if err != nil {
					return fmt.Errorf("invalid duration %q: %w", timeStr, err)
				}
				if dur <= 0 {
					return errors.New("ban duration must be positive; omit --time to use the monitor's bantime")
				}
			}

			socketPath, err := resolveSocketPath(root.socket, root.config)
			if err != nil {
				return err
			}
			client := control.NewClient(socketPath)

			if err := client.Ban(cmd.Context(), ip, monitor, dur); err != nil {
				return fmt.Errorf("ban %s: %w", ip, err)
			}

			out := cmd.OutOrStdout()
			if applied, ok := appliedBan(cmd.Context(), client, ip); ok {
				// Report what the daemon recorded, not what was typed: with no
				// --time only the daemon knows the monitor's bantime, and it
				// may have extended an existing ban rather than shortening it.
				fmt.Fprintf(out, "banned %s for %s (monitor: %s, until %s)\n",
					ip,
					applied.Until.Sub(applied.At).Round(time.Second),
					applied.Monitor,
					applied.Until.Format(time.RFC3339))
				return nil
			}
			fmt.Fprintf(out, "banned %s\n", ip)
			return nil
		},
	}

	cmd.Flags().StringVarP(&monitor, "monitor", "m", "manual", "monitor name for the ban policy")
	cmd.Flags().StringVarP(&timeStr, "time", "t", "", "ban duration (e.g. 30m, 1h, 24h); default: the monitor's bantime")

	return cmd
}

// appliedBan looks the freshly created ban up in the daemon's status so the
// CLI can print the duration that actually took effect. The ban itself has
// already succeeded, so a failure here is not worth an error — the caller
// falls back to a shorter message.
func appliedBan(ctx context.Context, client *control.Client, ip netip.Addr) (model.Ban, bool) {
	resp, err := client.Status(ctx)
	if err != nil {
		return model.Ban{}, false
	}
	for _, b := range resp.Bans {
		if b.IP == ip {
			return b, true
		}
	}
	return model.Ban{}, false
}
