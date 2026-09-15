package action

import (
	"context"
	"log/slog"
	"slices"
	"strings"
)

// dryRunner is the --dry-run implementation. It is a Runner decorator rather
// than a Backend decorator on purpose: wrapping at this level means *no*
// backend, present or future, can reach the host firewall when dry-run is on,
// and what gets logged is the exact argv that would have been executed —
// shell-quoted so an operator can paste it straight into a terminal to check
// it by hand.
type dryRunner struct {
	log *slog.Logger
}

// newDryRunner takes the Runner it replaces only to make the call site read as
// a wrapper; it deliberately never delegates, so nothing can execute.
func newDryRunner(_ Runner, log *slog.Logger) Runner {
	return &dryRunner{log: log}
}

// Run logs the command and pretends it succeeded.
//
// Existence checks ("iptables -C ...") are the one exception: they are
// answered "absent" so the backend goes on to log the bootstrap commands it
// would run. Dry-run therefore shows the full set-up for a clean host, which
// is what someone validating a config wants to see.
func (d *dryRunner) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	line := Quote(argv)
	if shell {
		// Mirror execRunner: in shell mode the elements are joined and handed
		// to sh, so that is what we print.
		line = "sh -c " + shellQuote(strings.Join(argv, " "))
	}
	d.log.Info("dry-run: would execute", "cmd", line)

	if slices.Contains(argv, "-C") {
		return nil, &CmdError{
			Argv:     argv,
			ExitCode: 1,
			Stderr:   "dry-run: assumed absent",
		}
	}
	return nil, nil
}
