package action

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIPSetStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler func(argv []string, shell bool) ([]byte, error)
		want    [][]string
		wantErr bool
	}{
		{
			name:    "clean host",
			handler: cleanHost,
			want: [][]string{
				{"ipset", "-exist", "create", "banhammer4", "hash:ip", "family", "inet"},
				{"iptables", "--wait", "-V"},
				{"iptables", "--wait", "-t", "filter", "-C", "INPUT", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
				{"iptables", "--wait", "-t", "filter", "-I", "INPUT", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
				{"ipset", "-exist", "create", "banhammer6", "hash:ip", "family", "inet6"},
				{"ip6tables", "--wait", "-V"},
				{"ip6tables", "--wait", "-t", "filter", "-C", "INPUT", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
				{"ip6tables", "--wait", "-t", "filter", "-I", "INPUT", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
			},
		},
		{
			name:    "restart: set and rule already exist",
			handler: func(argv []string, _ bool) ([]byte, error) { return nil, nil },
			want: [][]string{
				{"ipset", "-exist", "create", "banhammer4", "hash:ip", "family", "inet"},
				{"iptables", "--wait", "-V"},
				{"iptables", "--wait", "-t", "filter", "-C", "INPUT", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
				{"ipset", "-exist", "create", "banhammer6", "hash:ip", "family", "inet6"},
				{"ip6tables", "--wait", "-V"},
				{"ip6tables", "--wait", "-t", "filter", "-C", "INPUT", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
			},
		},
		{
			name: "ipset binary missing is fatal",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if argv[0] == "ipset" {
					return nil, &CmdError{ExitCode: -1, Err: errors.New("executable file not found in $PATH")}
				}
				return nil, nil
			},
			want: [][]string{
				{"ipset", "-exist", "create", "banhammer4", "hash:ip", "family", "inet"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: tc.handler}
			b, err := New(Spec{Name: "ipset"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := b.Start(context.Background()); tc.wantErr != (err != nil) {
				t.Fatalf("Start error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgvSeq(t, f.argvs(), tc.want)
		})
	}
}

func TestIPSetBanUnban(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		unban   bool
		ip      string
		err     error
		want    []string
		wantErr bool
	}{
		{
			name: "ban v4 adds a bare element",
			ip:   "203.0.113.7",
			want: []string{"ipset", "-exist", "add", "banhammer4", "203.0.113.7"},
		},
		{
			name: "ban v6 uses the v6 set",
			ip:   "2001:db8::1",
			want: []string{"ipset", "-exist", "add", "banhammer6", "2001:db8::1"},
		},
		{
			name:  "unban",
			unban: true,
			ip:    "203.0.113.7",
			want:  []string{"ipset", "-exist", "del", "banhammer4", "203.0.113.7"},
		},
		{
			// Flushed set, reboot, or a manual `ipset del`: the end state we
			// wanted already holds, so this must not be reported as a failure.
			name:  "unban of an entry that is already gone",
			unban: true,
			ip:    "203.0.113.7",
			err:   exitErr(1, "ipset v7.15: Element cannot be deleted from the set: it's not added to the set"),
			want:  []string{"ipset", "-exist", "del", "banhammer4", "203.0.113.7"},
		},
		{
			name:    "unban with a real failure",
			unban:   true,
			ip:      "203.0.113.7",
			err:     exitErr(1, "ipset v7.15: Kernel error received: Operation not permitted"),
			want:    []string{"ipset", "-exist", "del", "banhammer4", "203.0.113.7"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: cleanHost}
			b, err := New(Spec{Name: "ipset"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := b.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			f.reset()
			f.handler = func([]string, bool) ([]byte, error) { return nil, tc.err }

			ban := testBan(t, tc.ip)
			if tc.unban {
				err = b.Unban(context.Background(), ban)
			} else {
				err = b.Ban(context.Background(), ban)
			}
			if tc.wantErr != (err != nil) {
				t.Fatalf("error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgv(t, f.last(t), tc.want)
		})
	}
}

// TestSetBackendsHaveNoKernelExpiry is a regression guard for an integration
// decision: internal/ban never re-issues Ban when a ban is extended, so a
// kernel-side timeout would be a second expiry authority that silently
// released an extended ban early. No command may mention one.
func TestSetBackendsHaveNoKernelExpiry(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"ipset", "nft"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: cleanHost}
			b, err := New(Spec{Name: name}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx := context.Background()
			if err := b.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			for _, ip := range []string{"203.0.113.7", "2001:db8::1"} {
				ban := testBan(t, ip)
				if err := b.Ban(ctx, ban); err != nil {
					t.Fatalf("Ban: %v", err)
				}
				// Re-banning must be a no-op success: Restore re-applies every
				// live ban on each daemon start.
				if err := b.Ban(ctx, ban); err != nil {
					t.Fatalf("re-Ban: %v", err)
				}
				if err := b.Unban(ctx, ban); err != nil {
					t.Fatalf("Unban: %v", err)
				}
			}
			for _, argv := range f.argvs() {
				for _, a := range argv {
					if strings.Contains(a, "timeout") {
						t.Fatalf("command mentions a kernel timeout: %s", Quote(argv))
					}
				}
			}
		})
	}
}

func TestIPSetWithoutIPv6(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func(argv []string, _ bool) ([]byte, error) {
		if hasArg(argv, "banhammer6") {
			return nil, exitErr(1, "ipset v7.15: Kernel error received: Protocol not supported")
		}
		return cleanHost(argv, false)
	}}
	b, err := New(Spec{Name: "ipset"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A host without IPv6 must still start and keep protecting IPv4.
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	v6 := testBan(t, "2001:db8::1")
	if err := b.Ban(context.Background(), v6); !errors.Is(err, ErrFamilyUnavailable) {
		t.Fatalf("v6 Ban error = %v, want ErrFamilyUnavailable", err)
	}
	if err := b.Unban(context.Background(), v6); err != nil {
		t.Fatalf("v6 Unban = %v, want nil", err)
	}
	if err := b.Ban(context.Background(), testBan(t, "203.0.113.7")); err != nil {
		t.Fatalf("v4 Ban = %v, want success", err)
	}
	requireArgv(t, f.last(t), []string{"ipset", "-exist", "add", "banhammer4", "203.0.113.7"})
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestIPSetStopLeavesSetsByDefault(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: cleanHost}
	b, err := New(Spec{Name: "ipset"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.reset()
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := len(f.argvs()); n != 0 {
		t.Fatalf("Stop ran %d commands, want 0 (bans must survive a restart)", n)
	}
}

func TestIPSetStopFlushesWhenConfigured(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: cleanHost}
	b, err := New(Spec{Name: "ipset", FlushOnExit: true}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	f.reset()
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	requireArgvSeq(t, f.argvs(), [][]string{
		{"iptables", "--wait", "-t", "filter", "-D", "INPUT", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
		{"ipset", "destroy", "banhammer4"},
		{"ip6tables", "--wait", "-t", "filter", "-D", "INPUT", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
		{"ipset", "destroy", "banhammer6"},
	})
}

func TestNFTStart(t *testing.T) {
	t.Parallel()

	setup := [][]string{
		{"nft", "add", "table", "inet", "banhammer"},
		{"nft", "add", "set", "inet", "banhammer", "banhammer4", "{ type ipv4_addr; }"},
		{"nft", "add", "set", "inet", "banhammer", "banhammer6", "{ type ipv6_addr; }"},
		{"nft", "add", "chain", "inet", "banhammer", "input", "{ type filter hook input priority -10; policy accept; }"},
		{"nft", "list", "chain", "inet", "banhammer", "input"},
	}

	tests := []struct {
		name    string
		handler func(argv []string, shell bool) ([]byte, error)
		want    [][]string
		wantErr bool
	}{
		{
			name:    "clean host adds both rules",
			handler: func([]string, bool) ([]byte, error) { return nil, nil },
			want: append(setup, [][]string{
				{"nft", "add", "rule", "inet", "banhammer", "input", "ip", "saddr", "@banhammer4", "drop"},
				{"nft", "add", "rule", "inet", "banhammer", "input", "ip6", "saddr", "@banhammer6", "drop"},
			}...),
		},
		{
			// "nft add rule" appends unconditionally, so a restart must not
			// duplicate the rules: we list the chain and skip what is there.
			name: "restart does not duplicate rules",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "list") {
					return []byte("table inet banhammer {\n chain input {\n  ip saddr @banhammer4 drop\n  ip6 saddr @banhammer6 drop\n }\n}\n"), nil
				}
				return nil, exitErr(1, "Error: Could not process rule: File exists")
			},
			want: setup,
		},
		{
			name: "half-installed chain gets only the missing rule",
			handler: func(argv []string, _ bool) ([]byte, error) {
				if hasArg(argv, "list") {
					return []byte("  ip saddr @banhammer4 drop\n"), nil
				}
				return nil, nil
			},
			want: append(setup, []string{"nft", "add", "rule", "inet", "banhammer", "input", "ip6", "saddr", "@banhammer6", "drop"}),
		},
		{
			name: "nft missing is fatal",
			handler: func([]string, bool) ([]byte, error) {
				return nil, &CmdError{ExitCode: -1, Err: errors.New("executable file not found in $PATH")}
			},
			want:    [][]string{{"nft", "add", "table", "inet", "banhammer"}},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: tc.handler}
			b, err := New(Spec{Name: "nft"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := b.Start(context.Background()); tc.wantErr != (err != nil) {
				t.Fatalf("Start error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgvSeq(t, f.argvs(), tc.want)
		})
	}
}

func TestNFTBanUnban(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		unban   bool
		ip      string
		err     error
		want    []string
		wantErr bool
	}{
		{
			name: "ban v4",
			ip:   "203.0.113.7",
			want: []string{"nft", "add", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
		},
		{
			name: "ban v6",
			ip:   "2001:db8::1",
			want: []string{"nft", "add", "element", "inet", "banhammer", "banhammer6", "{ 2001:db8::1 }"},
		},
		{
			name: "re-ban of a present element is success, not a retry loop",
			ip:   "203.0.113.7",
			err:  exitErr(1, "Error: Could not process rule: File exists"),
			want: []string{"nft", "add", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
		},
		{
			name:    "ban failure propagates",
			ip:      "203.0.113.7",
			err:     exitErr(1, "Error: Could not process rule: Operation not permitted"),
			want:    []string{"nft", "add", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
			wantErr: true,
		},
		{
			name:  "unban",
			unban: true,
			ip:    "203.0.113.7",
			want:  []string{"nft", "delete", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
		},
		{
			name:  "unban of a kernel-expired element is success",
			unban: true,
			ip:    "203.0.113.7",
			err:   exitErr(1, "Error: Could not process rule: No such file or directory"),
			want:  []string{"nft", "delete", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
		},
		{
			name:    "unban failure propagates",
			unban:   true,
			ip:      "203.0.113.7",
			err:     exitErr(1, "Error: Could not process rule: Operation not permitted"),
			want:    []string{"nft", "delete", "element", "inet", "banhammer", "banhammer4", "{ 203.0.113.7 }"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: func([]string, bool) ([]byte, error) { return nil, tc.err }}
			b, err := New(Spec{Name: "nft"}, f, discardLogger())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ban := testBan(t, tc.ip)
			if tc.unban {
				err = b.Unban(context.Background(), ban)
			} else {
				err = b.Ban(context.Background(), ban)
			}
			if tc.wantErr != (err != nil) {
				t.Fatalf("error = %v, wantErr = %v", err, tc.wantErr)
			}
			requireArgv(t, f.last(t), tc.want)
		})
	}
}

func TestIPSetCustomChain(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: cleanHost}
	b, err := New(Spec{Name: "ipset", Chain: "DOCKER-USER"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireArgvSeq(t, f.argvs(), [][]string{
		{"ipset", "-exist", "create", "banhammer4", "hash:ip", "family", "inet"},
		{"iptables", "--wait", "-V"},
		{"iptables", "--wait", "-t", "filter", "-C", "DOCKER-USER", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
		{"iptables", "--wait", "-t", "filter", "-I", "DOCKER-USER", "-m", "set", "--match-set", "banhammer4", "src", "-j", "DROP"},
		{"ipset", "-exist", "create", "banhammer6", "hash:ip", "family", "inet6"},
		{"ip6tables", "--wait", "-V"},
		{"ip6tables", "--wait", "-t", "filter", "-C", "DOCKER-USER", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
		{"ip6tables", "--wait", "-t", "filter", "-I", "DOCKER-USER", "-m", "set", "--match-set", "banhammer6", "src", "-j", "DROP"},
	})
}

func TestNFTCustomChain(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func([]string, bool) ([]byte, error) { return nil, nil }}
	b, err := New(Spec{Name: "nft", Chain: "FORWARD"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireArgvSeq(t, f.argvs(), [][]string{
		{"nft", "add", "table", "inet", "banhammer"},
		{"nft", "add", "set", "inet", "banhammer", "banhammer4", "{ type ipv4_addr; }"},
		{"nft", "add", "set", "inet", "banhammer", "banhammer6", "{ type ipv6_addr; }"},
		{"nft", "add", "chain", "inet", "banhammer", "forward", "{ type filter hook forward priority -10; policy accept; }"},
		{"nft", "list", "chain", "inet", "banhammer", "forward"},
		{"nft", "add", "rule", "inet", "banhammer", "forward", "ip", "saddr", "@banhammer4", "drop"},
		{"nft", "add", "rule", "inet", "banhammer", "forward", "ip6", "saddr", "@banhammer6", "drop"},
	})
}

func TestNFTStopLeavesTableByDefault(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func([]string, bool) ([]byte, error) { return nil, nil }}
	b, err := New(Spec{Name: "nft"}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if n := len(f.argvs()); n != 0 {
		t.Fatalf("Stop ran %d commands, want 0 (bans must survive a restart)", n)
	}
}

func TestNFTStopFlushesWhenConfigured(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func([]string, bool) ([]byte, error) { return nil, nil }}
	b, err := New(Spec{Name: "nft", FlushOnExit: true}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	requireArgv(t, f.last(t), []string{"nft", "delete", "table", "inet", "banhammer"})
}

func TestNFTStopFlushToleratesAlreadyGone(t *testing.T) {
	t.Parallel()
	f := &fakeRunner{handler: func([]string, bool) ([]byte, error) {
		return nil, exitErr(1, "Error: No such file or directory")
	}}
	b, err := New(Spec{Name: "nft", FlushOnExit: true}, f, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Stop with table already gone should succeed, got: %v", err)
	}
}
