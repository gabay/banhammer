package action

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// bootstrap is the command sequence a clean host produces for one binary.
func bootstrap(bin string) [][]string {
	return [][]string{
		{bin, "--wait", "-V"},
		{bin, "--wait", "-t", "filter", "-N", "BANHAMMER"},
		{bin, "--wait", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
		{bin, "--wait", "-t", "filter", "-I", "INPUT", "-j", "BANHAMMER"},
	}
}

func TestIPTablesStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler func(argv []string, shell bool) ([]byte, error)
		want    [][]string
		wantErr bool
		// v6off asserts that the IPv6 path was disabled but startup survived.
		v6off bool
	}{
		{
			name: "clean host creates chain and jump for both families",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "-C") {
					return nil, exitErr(1, "iptables: Bad rule (does a matching rule exist in that chain?).")
				}
				return nil, nil
			},
			want: append(bootstrap("iptables"), bootstrap("ip6tables")...),
		},
		{
			name: "restart is idempotent: chain exists, jump present",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "-N") {
					return nil, exitErr(1, "iptables: Chain already exists.")
				}
				return nil, nil // -C succeeds => jump already installed
			},
			want: [][]string{
				{"iptables", "--wait", "-V"},
				{"iptables", "--wait", "-t", "filter", "-N", "BANHAMMER"},
				{"iptables", "--wait", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
				{"ip6tables", "--wait", "-V"},
				{"ip6tables", "--wait", "-t", "filter", "-N", "BANHAMMER"},
				{"ip6tables", "--wait", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
			},
		},
		{
			name: "ancient iptables without --wait",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "--wait") {
					return nil, exitErr(2, "iptables v1.4.7: unknown option `--wait'")
				}
				if hasArg(argv, "-C") {
					return nil, exitErr(1, "iptables: Bad rule (does a matching rule exist in that chain?).")
				}
				return nil, nil
			},
			want: [][]string{
				{"iptables", "--wait", "-V"},
				{"iptables", "-t", "filter", "-N", "BANHAMMER"},
				{"iptables", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
				{"iptables", "-t", "filter", "-I", "INPUT", "-j", "BANHAMMER"},
				{"ip6tables", "--wait", "-V"},
				{"ip6tables", "-t", "filter", "-N", "BANHAMMER"},
				{"ip6tables", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
				{"ip6tables", "-t", "filter", "-I", "INPUT", "-j", "BANHAMMER"},
			},
		},
		{
			name: "host without IPv6 still starts",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if strings.HasPrefix(argv[0], "ip6tables") {
					return nil, &CmdError{Argv: argv, ExitCode: -1, Err: errors.New("exec: \"ip6tables\": executable file not found in $PATH")}
				}
				if hasArg(argv, "-C") {
					return nil, exitErr(1, "iptables: Bad rule (does a matching rule exist in that chain?).")
				}
				return nil, nil
			},
			want: append(bootstrap("iptables"), [][]string{
				{"ip6tables", "--wait", "-V"},
				{"ip6tables", "-t", "filter", "-N", "BANHAMMER"},
			}...),
			v6off: true,
		},
		{
			name: "IPv4 chain creation failure is fatal",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "-N") {
					return nil, exitErr(3, "iptables: Permission denied (you must be root).")
				}
				return nil, nil
			},
			want: [][]string{
				{"iptables", "--wait", "-V"},
				{"iptables", "--wait", "-t", "filter", "-N", "BANHAMMER"},
			},
			wantErr: true,
		},
		{
			name: "check command failing to execute is fatal, not 'absent'",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "-C") {
					// ExitCode -1: the binary never ran. Treating that as
					// "rule absent" would hide a broken install.
					return nil, &CmdError{Argv: argv, ExitCode: -1, Err: errors.New("fork/exec: no such file")}
				}
				return nil, nil
			},
			want: [][]string{
				{"iptables", "--wait", "-V"},
				{"iptables", "--wait", "-t", "filter", "-N", "BANHAMMER"},
				{"iptables", "--wait", "-t", "filter", "-C", "INPUT", "-j", "BANHAMMER"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: tc.handler}
			b, err := New(Spec{Name: "iptables"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = b.Start(context.Background())
			if tc.wantErr != (err != nil) {
				t.Fatalf("Start error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgvSeq(t, f.argvs(), tc.want)

			if tc.v6off {
				v6 := testBan(t, "2001:db8::1")
				if err := b.Ban(context.Background(), v6); !errors.Is(err, ErrFamilyUnavailable) {
					t.Fatalf("v6 Ban error = %v, want ErrFamilyUnavailable", err)
				}
				// An unban for a family we never installed is already true.
				if err := b.Unban(context.Background(), v6); err != nil {
					t.Fatalf("v6 Unban = %v, want nil", err)
				}
			}
		})
	}
}

func TestIPTablesBanArgv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want []string
	}{
		{
			name: "IPv4 uses iptables",
			ip:   "203.0.113.7",
			want: []string{"iptables", "--wait", "-t", "filter", "-I", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
		},
		{
			name: "IPv6 uses ip6tables",
			ip:   "2001:db8::dead:beef",
			want: []string{"ip6tables", "--wait", "-t", "filter", "-I", "BANHAMMER", "-s", "2001:db8::dead:beef", "-j", "DROP"},
		},
		{
			// A v4-mapped address is an IPv4 ban; sending it to ip6tables
			// would silently fail to block the attacker.
			name: "v4-in-v6 is unmapped onto iptables",
			ip:   "::ffff:198.51.100.9",
			want: []string{"iptables", "--wait", "-t", "filter", "-I", "BANHAMMER", "-s", "198.51.100.9", "-j", "DROP"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: cleanHost}
			b := newStartedIPTables(t, f)
			if err := b.Ban(context.Background(), testBan(t, tc.ip)); err != nil {
				t.Fatalf("Ban: %v", err)
			}
			requireArgv(t, f.last(t), tc.want)
		})
	}
}

func cleanHost(argv []string, _ bool) ([]byte, error) {
	if hasArg(argv, "-C") {
		return nil, exitErr(1, "iptables: Bad rule (does a matching rule exist in that chain?).")
	}
	return nil, nil
}

func TestIPTablesUnban(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ip      string
		err     error
		want    []string
		wantErr bool
	}{
		{
			name: "success",
			ip:   "203.0.113.7",
			want: []string{"iptables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
		},
		{
			name: "rule already gone is a no-op success",
			ip:   "203.0.113.7",
			err:  exitErr(1, "iptables: Bad rule (does a matching rule exist in that chain?).\n"),
			want: []string{"iptables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
		},
		{
			name: "chain flushed away is a no-op success",
			ip:   "2001:db8::1",
			err:  exitErr(1, "iptables: No chain/target/match by that name."),
			want: []string{"ip6tables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "2001:db8::1", "-j", "DROP"},
		},
		{
			name:    "xtables lock failure is a real error",
			ip:      "203.0.113.7",
			err:     exitErr(4, "Another app is currently holding the xtables lock; still 3s 0us time ahead to have a chance to grab the lock..."),
			want:    []string{"iptables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
			wantErr: true,
		},
		{
			name:    "permission denied is a real error",
			ip:      "203.0.113.7",
			err:     exitErr(3, "iptables: Permission denied (you must be root)."),
			want:    []string{"iptables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
			wantErr: true,
		},
		{
			name:    "binary missing is a real error",
			ip:      "203.0.113.7",
			err:     &CmdError{ExitCode: -1, Err: errors.New("exec format error")},
			want:    []string{"iptables", "--wait", "-t", "filter", "-D", "BANHAMMER", "-s", "203.0.113.7", "-j", "DROP"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: cleanHost}
			b := newStartedIPTables(t, f)
			f.handler = func(argv []string, _ bool) ([]byte, error) { return nil, tc.err }

			err := b.Unban(context.Background(), testBan(t, tc.ip))
			if tc.wantErr != (err != nil) {
				t.Fatalf("Unban error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgv(t, f.last(t), tc.want)
		})
	}
}

func TestIPTablesBanBeforeStart(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: cleanHost}
	b, err := New(Spec{}, f, discardLogger()) // empty Name defaults to iptables
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Name() != "iptables" {
		t.Fatalf("Name = %q, want iptables", b.Name())
	}
	if err := b.Ban(context.Background(), testBan(t, "203.0.113.7")); err == nil {
		t.Fatal("Ban before Start should fail loudly rather than silently do nothing")
	}
	if n := len(f.argvs()); n != 0 {
		t.Fatalf("ran %d commands before Start, want 0", n)
	}
}

func TestIPTablesStopLeavesRulesInPlace(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: cleanHost}
	b := newStartedIPTables(t, f)
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := len(f.argvs()); n != 0 {
		t.Fatalf("Stop ran %d commands, want 0 (bans must survive a restart)", n)
	}
}

func TestIPTablesPerCommandTimeout(t *testing.T) {
	t.Parallel()
	// A backend command must carry the Spec timeout as a deadline, so a wedged
	// iptables cannot pin the executor goroutine forever.
	var deadlineSeen bool
	f := &fakeRunner{}
	f.handler = func(argv []string, _ bool) ([]byte, error) { return nil, nil }
	b, err := New(Spec{Name: "iptables", Timeout: 50 * time.Millisecond}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ipt := b.(*iptables)
	ipt.run = runnerFunc(func(ctx context.Context, argv []string, shell bool) ([]byte, error) {
		if _, ok := ctx.Deadline(); ok {
			deadlineSeen = true
		}
		return nil, nil
	})
	if _, err := ipt.exec(context.Background(), false, "iptables", "-V"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !deadlineSeen {
		t.Fatal("command context had no deadline")
	}
}

type runnerFunc func(ctx context.Context, argv []string, shell bool) ([]byte, error)

func (fn runnerFunc) Run(ctx context.Context, argv []string, shell bool) ([]byte, error) {
	return fn(ctx, argv, shell)
}
