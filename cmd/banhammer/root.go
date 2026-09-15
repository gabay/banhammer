package main

import (
	"os"
	"path/filepath"

	"banhammer/internal/config"
	"github.com/spf13/cobra"
)

// rootFlags holds persistent flags shared across banhammer subcommands.
type rootFlags struct {
	config string
	socket string
}

// NewRootCmd constructs the primary banhammer CLI command tree.
func NewRootCmd() *cobra.Command {
	flags := &rootFlags{}

	rootCmd := &cobra.Command{
		Use:   "banhammer",
		Short: "Banhammer intrusion prevention system",
		Long:  "Banhammer is a high-performance intrusion prevention daemon and CLI tool that scans logs for abusive patterns and enforces firewall bans.",
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVarP(&flags.config, "config", "c", "", "path to configuration file")
	rootCmd.PersistentFlags().StringVar(&flags.socket, "socket", "", "override control unix socket path")

	rootCmd.AddCommand(newRunCmd(flags))
	rootCmd.AddCommand(newCheckCmd(flags))
	rootCmd.AddCommand(newTestCmd(flags))
	rootCmd.AddCommand(newStatusCmd(flags))
	rootCmd.AddCommand(newBanCmd(flags))
	rootCmd.AddCommand(newUnbanCmd(flags))
	rootCmd.AddCommand(newReloadCmd(flags))

	return rootCmd
}

// defaultControlSocketPath returns the standard control socket path.
// Matches daemon.defaultControlSocketPath.
func defaultControlSocketPath(stateDir string) string {
	if os.Geteuid() == 0 {
		return "/run/banhammer.sock"
	}
	if stateDir == "" {
		stateDir = "/var/lib/banhammer"
	}
	return filepath.Join(stateDir, "control.sock")
}

// resolveSocketPath resolves the Unix domain socket path using:
// 1. Explicit socket flag
// 2. Config path state_dir (if provided and valid)
// 3. Standard config files (/etc/banhammer/config.yaml, ./config.yaml)
// 4. Default fallback location
func resolveSocketPath(socketFlag, configPath string) string {
	if socketFlag != "" {
		return socketFlag
	}
	if configPath != "" {
		if cfg, err := config.Load(configPath); err == nil && cfg.StateDir != "" {
			return defaultControlSocketPath(cfg.StateDir)
		}
	}
	for _, p := range []string{"/etc/banhammer/config.yaml", "./config.yaml"} {
		if cfg, err := config.Load(p); err == nil && cfg.StateDir != "" {
			return defaultControlSocketPath(cfg.StateDir)
		}
	}
	return defaultControlSocketPath("")
}
