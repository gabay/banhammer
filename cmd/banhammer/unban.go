package main

import (
	"errors"
	"fmt"
	"net/netip"

	"banhammer/internal/control"
	"github.com/spf13/cobra"
)

func newUnbanCmd(root *rootFlags) *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "unban <ip> | --all",
		Short: "Manually unban an IP address or all active bans",
		Long:  "Unban removes an active firewall drop rule for the specified IP address, or lifts all active bans when --all is supplied.",
		RunE: func(cmd *cobra.Command, args []string) error {
			socketPath, err := resolveSocketPath(root.socket, root.config)
			if err != nil {
				return err
			}
			client := control.NewClient(socketPath)

			if all {
				if len(args) > 0 {
					return errors.New("cannot specify an IP address with --all")
				}
				if err := client.UnbanAll(cmd.Context()); err != nil {
					return fmt.Errorf("unban all: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "unbanned all IPs")
				return nil
			}

			if len(args) != 1 {
				return errors.New("unban requires an IP address or --all")
			}

			ip, err := netip.ParseAddr(args[0])
			if err != nil {
				return fmt.Errorf("invalid IP address %q: %w", args[0], err)
			}

			if err := client.Unban(cmd.Context(), ip); err != nil {
				return fmt.Errorf("unban %s: %w", ip, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "unbanned %s\n", ip)
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "unban all active bans")

	return cmd
}
