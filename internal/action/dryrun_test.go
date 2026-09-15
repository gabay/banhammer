package action

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestDryRunExecutesNothing is the safety property: with DryRun set, the wrapped
// Runner must never be reached, whatever the backend does.
func TestDryRunExecutesNothing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec Spec
	}{
		{name: "explicit dryrun backend", spec: Spec{Name: "dryrun"}},
		{name: "iptables with --dry-run", spec: Spec{Name: "iptables", DryRun: true}},
		{name: "ipset with --dry-run", spec: Spec{Name: "ipset", DryRun: true}},
		{name: "nft with --dry-run", spec: Spec{Name: "nft", DryRun: true}},
		{name: "cmd with --dry-run", spec: Spec{Name: "cmd", Ban: "/b {ip}", Unban: "/u {ip}", DryRun: true}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRunner{handler: func(argv []string, _ bool) ([]byte, error) {
				t.Errorf("dry-run reached the real runner with %v", argv)
				return nil, nil
			}}
			var buf bytes.Buffer
			b, err := New(tc.spec, f, bufLogger(&buf))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx := context.Background()
			ban := testBan(t, "203.0.113.7")
			if err := b.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if err := b.Ban(ctx, ban); err != nil {
				t.Fatalf("Ban: %v", err)
			}
			if err := b.Unban(ctx, ban); err != nil {
				t.Fatalf("Unban: %v", err)
			}
			if err := b.Stop(ctx); err != nil {
				t.Fatalf("Stop: %v", err)
			}
			if n := len(f.argvs()); n != 0 {
				t.Fatalf("%d commands escaped the dry-run wrapper", n)
			}
			if !strings.Contains(buf.String(), "dry-run: would execute") {
				t.Fatalf("dry-run logged nothing useful:\n%s", buf.String())
			}
		})
	}
}

// TestDryRunLogsCopyPasteableCommands checks the exact commands an operator
// validating a config would see for the default backend on a clean host.
func TestDryRunLogsCopyPasteableCommands(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	b, err := New(Spec{Name: "dryrun"}, &fakeRunner{}, bufLogger(&buf))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ban := testBan(t, "203.0.113.7")
	if err := b.Ban(ctx, ban); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := b.Unban(ctx, ban); err != nil {
		t.Fatalf("Unban: %v", err)
	}

	log := buf.String()
	// The bootstrap insert must appear even though nothing exists to check:
	// dry-run assumes a clean host so the operator sees the whole plan.
	for _, want := range []string{
		"iptables --wait -t filter -N BANHAMMER",
		"iptables --wait -t filter -I INPUT -j BANHAMMER",
		"ip6tables --wait -t filter -I INPUT -j BANHAMMER",
		"iptables --wait -t filter -I BANHAMMER -s 203.0.113.7 -j DROP",
		"iptables --wait -t filter -D BANHAMMER -s 203.0.113.7 -j DROP",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("dry-run log missing %q:\n%s", want, log)
		}
	}
}

func TestDryRunShellTemplateIsLoggedAsShell(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	b, err := New(Spec{
		Name:   "cmd",
		Ban:    "/b {ip} | tee /tmp/x",
		Unban:  "/u {ip}",
		Shell:  true,
		DryRun: true,
	}, &fakeRunner{}, bufLogger(&buf))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := b.Ban(context.Background(), testBan(t, "203.0.113.7")); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !strings.Contains(buf.String(), `sh -c '/b 203.0.113.7 | tee /tmp/x'`) {
		t.Fatalf("shell command not logged in runnable form:\n%s", buf.String())
	}
}

func TestNilRunnerAndLoggerAreTolerated(t *testing.T) {
	t.Parallel()
	// A nil Runner must default to the real one — but we only construct it,
	// never Start it, so nothing is executed.
	b, err := New(Spec{Name: "iptables"}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.Name() != "iptables" {
		t.Fatalf("Name = %q", b.Name())
	}
}

func TestBackendNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec Spec
		want string
	}{
		{spec: Spec{}, want: "iptables"},
		{spec: Spec{Name: "IPTables"}, want: "iptables"},
		{spec: Spec{Name: " ipset "}, want: "ipset"},
		{spec: Spec{Name: "nft"}, want: "nft"},
		{spec: Spec{Name: "cmd", Ban: "/b", Unban: "/u"}, want: "cmd"},
		{spec: Spec{Name: "dryrun"}, want: "iptables"}, // dryrun is iptables that never runs
	}
	for _, tc := range tests {
		b, err := New(tc.spec, &fakeRunner{}, discardLogger())
		if err != nil {
			t.Fatalf("New(%+v): %v", tc.spec, err)
		}
		if b.Name() != tc.want {
			t.Fatalf("New(%+v).Name() = %q, want %q", tc.spec, b.Name(), tc.want)
		}
	}
}
