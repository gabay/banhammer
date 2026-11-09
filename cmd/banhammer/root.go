package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"banhammer/internal/config"
	"github.com/spf13/cobra"
)

// version is the build stamp reported by `banhammer --version`. Release builds
// override it with -ldflags="-X main.version=v1.2.3".
var version = "dev"

// rootFlags holds persistent flags shared across banhammer subcommands.
type rootFlags struct {
	config string
	socket string
}

// NewRootCmd constructs the primary banhammer CLI command tree.
func NewRootCmd() *cobra.Command {
	flags := &rootFlags{}

	rootCmd := &cobra.Command{
		Use:          "banhammer",
		Short:        "Banhammer intrusion prevention system",
		Long:         "Banhammer is a high-performance intrusion prevention daemon and CLI tool that scans logs for abusive patterns and enforces firewall bans.",
		SilenceUsage: true,
		Version:      version,
	}

	rootCmd.PersistentFlags().StringVarP(&flags.config, "config", "c", os.Getenv("CONFIG"), "path to configuration file")
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
//
// This must stay identical to daemon.defaultControlSocketPath — the CLI and
// the daemon have to meet at the same path or every management command talks
// to nothing. As root that is /run/banhammer/control.sock, a subdirectory the
// packaged unit creates with RuntimeDirectory=banhammer, because
// ProtectSystem=strict leaves /run itself read-only. The agreement is pinned
// by TestDefaultSocketPathMatchesDaemon.
func defaultControlSocketPath(stateDir string) string {
	if os.Geteuid() == 0 {
		return "/run/banhammer/control.sock"
	}
	if stateDir == "" {
		stateDir = "/var/lib/banhammer"
	}
	return filepath.Join(stateDir, "control.sock")
}

// resolveSocketPath resolves the Unix domain socket path using:
//  1. Explicit --socket flag
//  2. state_dir from the config file named by -c
//  3. state_dir from the standard config locations
//  4. The built-in default
//
// An explicitly requested config that cannot be loaded is an error rather than
// a reason to fall through: silently searching on would point `banhammer unban
// --all -c broken.yaml` at whatever daemon owns the default socket, which is
// very likely not the one the operator meant.
func resolveSocketPath(socketFlag, configPath string) (string, error) {
	if socketFlag != "" {
		return socketFlag, nil
	}
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			return "", fmt.Errorf("load config %q: %w", configPath, err)
		}
		return defaultControlSocketPath(cfg.StateDir), nil
	}
	for _, p := range []string{"/etc/banhammer/config.yaml", "./config.yaml"} {
		if cfg, err := config.Load(p); err == nil && cfg.StateDir != "" {
			return defaultControlSocketPath(cfg.StateDir), nil
		}
	}
	return defaultControlSocketPath(""), nil
}

// daemonError decorates a control-plane failure.
//
// "dial unix /run/banhammer/control.sock: connect: no such file or directory"
// is an accurate answer to the wrong question; what the operator needs to know
// is that nothing is listening. Everything else (a server-side rejection, a
// timeout) is passed through unchanged.
func daemonError(op, socketPath string, err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("banhammer does not appear to be running (socket %s): %w", socketPath, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}
