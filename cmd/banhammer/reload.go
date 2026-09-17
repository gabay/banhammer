package main

import (
	"fmt"

	"banhammer/internal/control"
	"github.com/spf13/cobra"
)

func newReloadCmd(root *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload daemon configuration dynamically",
		Long:  "Reload sends a command to the running banhammer daemon instructing it to re-read its configuration file and update rule sets without restarting.",
		RunE: func(cmd *cobra.Command, args []string) error {
			socketPath, err := resolveSocketPath(root.socket, root.config)
			if err != nil {
				return err
			}
			client := control.NewClient(socketPath)

			if err := client.Reload(cmd.Context()); err != nil {
				return daemonError("reload daemon", socketPath, err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), "daemon configuration reloaded")
			return nil
		},
	}

	return cmd
}
