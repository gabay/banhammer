package main

import (
	"errors"
	"fmt"

	"banhammer/internal/config"
	"github.com/spf13/cobra"
)

func newCheckCmd(root *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate configuration and print effective settings",
		Long:  "Check validates the banhammer configuration file for syntax errors, missing fields, or conflicting rules, and prints the fully resolved configuration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if root.config == "" {
				return errors.New("configuration file required (-c, --config)")
			}

			cfg, err := config.Load(root.config)
			if err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}

			fmt.Fprint(cmd.OutOrStdout(), cfg.String())
			return nil
		},
	}

	return cmd
}
