package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"banhammer/internal/config"
	"banhammer/internal/daemon"
	"github.com/spf13/cobra"
)

func newRunCmd(root *rootFlags) *cobra.Command {
	var (
		dryRun    bool
		stateDir  string
		logFormat string
		logLevel  string
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the banhammer intrusion prevention daemon",
		Long:  "Run starts the continuous intrusion prevention daemon, monitoring log sources, aggregating offenses, and enforcing firewall bans.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, err := resolveRunConfigFile(root.config)
			if err != nil {
				return err
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config %q: %w", cfgPath, err)
			}

			// config.Load has already validated cfg.StateDir; an override
			// assigned after the fact skips that, so the one rule state_dir
			// has (see internal/config/validate.go) is enforced here too.
			if cmd.Flags().Changed("state-dir") {
				if strings.TrimSpace(stateDir) == "" {
					return errors.New("--state-dir must not be empty")
				}
				cfg.StateDir = stateDir
			}

			logFmt := strings.ToLower(logFormat)
			if !cmd.Flags().Changed("log-format") && cfg.LogFormat != "" {
				logFmt = strings.ToLower(cfg.LogFormat)
			}
			if logFmt != "text" && logFmt != "json" {
				return fmt.Errorf("invalid log format %q: must be text or json", logFmt)
			}

			var level slog.Level
			switch strings.ToLower(logLevel) {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "warn", "warning":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				return fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", logLevel)
			}

			var handler slog.Handler
			handlerOpts := &slog.HandlerOptions{Level: level}
			if logFmt == "json" {
				handler = slog.NewJSONHandler(cmd.ErrOrStderr(), handlerOpts)
			} else {
				handler = slog.NewTextHandler(cmd.ErrOrStderr(), handlerOpts)
			}
			logger := slog.New(handler)

			daemonOpts := []daemon.Option{
				daemon.WithLogger(logger),
				daemon.WithConfigPath(cfgPath),
			}
			if dryRun {
				daemonOpts = append(daemonOpts, daemon.WithDryRun(true))
			}
			if root.socket != "" {
				daemonOpts = append(daemonOpts, daemon.WithControlSocket(root.socket))
			}

			d, err := daemon.New(cfg, daemonOpts...)
			if err != nil {
				return fmt.Errorf("initialize daemon: %w", err)
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			sigCh := make(chan os.Signal, 2)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigCh)

			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case sig, ok := <-sigCh:
						if !ok {
							return
						}
						switch sig {
						case syscall.SIGHUP:
							logger.Info("received SIGHUP, reloading configuration")
							// Success is logged by daemon.Reload; saying it
							// again here just doubles every reload in the
							// journal.
							if err := d.Reload(nil); err != nil {
								logger.Error("configuration reload failed", "err", err)
							}
						case syscall.SIGINT, syscall.SIGTERM:
							logger.Info("received shutdown signal", "signal", sig.String())
							cancel()
							return
						}
					}
				}
			}()

			if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("daemon error: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "run action backend in dry-run mode")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "override state directory")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "log format (text|json)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level (debug|info|warn|error)")

	return cmd
}

// resolveRunConfigFile locates the configuration file, defaulting to standard locations.
func resolveRunConfigFile(path string) (string, error) {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("config file %q: %w", path, err)
		}
		return path, nil
	}
	for _, p := range []string{"/etc/banhammer/config.yaml", "./config.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("no configuration file specified and neither /etc/banhammer/config.yaml nor ./config.yaml exists")
}
