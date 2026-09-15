package rule

import (
	"strings"
	"sync"
	"testing"
)

func mustCompile(t *testing.T, s Spec) *Set {
	t.Helper()
	set, err := Compile(s)
	if err != nil {
		t.Fatalf("Compile(%+v) error: %v", s, err)
	}
	return set
}

func TestCompileErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		spec    Spec
		wantErr string
	}{
		{
			name:    "unknown format",
			spec:    Spec{Format: "xml", Line: []string{"x"}},
			wantErr: "unknown format",
		},
		{
			name:    "field patterns need json",
			spec:    Spec{Format: "text", Fields: map[string]string{"a": "b"}},
			wantErr: "require format: json",
		},
		{
			name:    "ip_field needs json",
			spec:    Spec{Format: "text", IPField: "a.b"},
			wantErr: "ip_field requires format: json",
		},
		{
			name:    "two ip macros in one pattern",
			spec:    Spec{Line: []string{"<IP> -> <IP>"}},
			wantErr: "capture groups",
		},
		{
			name:    "macro plus explicit group",
			spec:    Spec{Line: []string{`<IP> (?P<ip>\d+)`}},
			wantErr: "capture groups",
		},
		{
			name:    "two explicit groups",
			spec:    Spec{Line: []string{`(?P<ip>a)|(?P<ip>b)`}},
			wantErr: "capture groups",
		},
		{
			name:    "macro inside a character class",
			spec:    Spec{Line: []string{`[<IP>]`}},
			wantErr: "character class",
		},
		{
			name:    "invalid regex",
			spec:    Spec{Line: []string{`(unclosed`}},
			wantErr: "error parsing regexp",
		},
		{
			name:    "invalid ignore regex",
			spec:    Spec{Line: []string{"ok"}, IgnoreLine: []string{"*bad"}},
			wantErr: "ignore:",
		},
		{
			name:    "ip_field conflicts with an ip group",
			spec:    Spec{Format: "json", IPField: "remote_ip", Line: []string{"from <IP>"}},
			wantErr: "conflicts",
		},
		{
			name:    "ip_field conflicts with a field ip group",
			spec:    Spec{Format: "json", IPField: "remote_ip", Fields: map[string]string{"msg": "from <IP>"}},
			wantErr: "conflicts",
		},
		{
			name:    "empty field name",
			spec:    Spec{Format: "json", Fields: map[string]string{"": "x"}},
			wantErr: "empty field name",
		},
		{
			name:    "invalid field regex names the field",
			spec:    Spec{Format: "json", Fields: map[string]string{"msg": "(("}},
			wantErr: "field msg",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(tc.spec)
			if err == nil {
				t.Fatalf("Compile() = nil error, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestCompileAccepts(t *testing.T) {
	t.Parallel()
	specs := []struct {
		name string
		spec Spec
	}{
		{"explicit ip group", Spec{Line: []string{`from (?P<ip>[0-9.]+) port`}}},
		{"ignore may use the macro alongside ip_field", Spec{
			Format:     "json",
			IPField:    "remote_ip",
			Fields:     map[string]string{"msg": "failed"},
			IgnoreLine: []string{"from <IP> port .* ssh2: RSA"},
		}},
		{"json inferred from ip_field", Spec{IPField: "remote_ip", Line: []string{"failed"}}},
		{"empty spec never matches", Spec{}},
		{"two patterns each with one macro", Spec{Line: []string{"a <IP>", "b <IP>"}}},
	}
	for _, tc := range specs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := mustCompile(t, tc.spec)
			// Whatever the spec, matching must not panic on junk input.
			set.Match([]byte("junk line 1.2.3.4"))
			set.Match(nil)
		})
	}
}

func TestNeedsIPField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec Spec
		want bool
	}{
		{"macro supplies the ip", Spec{Line: []string{"from <IP>"}}, false},
		{"explicit group supplies the ip", Spec{Line: []string{`from (?P<ip>\S+)`}}, false},
		{"field pattern supplies the ip", Spec{Format: "json", Fields: map[string]string{"m": "from <IP>"}}, false},
		{"plain pattern needs a field", Spec{Line: []string{"Failed password"}}, true},
		{"ignore macro does not count", Spec{Line: []string{"failed"}, IgnoreLine: []string{"from <IP>"}}, true},
		{"ip_field set", Spec{Format: "json", IPField: "remote_ip", Line: []string{"failed"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mustCompile(t, tc.spec).NeedsIPField(); got != tc.want {
				t.Errorf("NeedsIPField() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMatchText(t *testing.T) {
	t.Parallel()
	spec := Spec{
		Line: []string{
			"Failed password for .* from <IP> port",
			"Invalid user .* from <IP>",
		},
		IgnoreLine: []string{"user backup ", "from 10\\."},
	}
	set := mustCompile(t, spec)

	tests := []struct {
		name string
		line string
		ip   string
		out  Outcome
	}{
		{
			name: "first pattern hits",
			line: "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
			ip:   "203.0.113.9",
			out:  OutcomeMatch,
		},
		{
			name: "second pattern hits",
			line: "sshd[1]: Invalid user oracle from 198.51.100.4 port 22",
			ip:   "198.51.100.4",
			out:  OutcomeMatch,
		},
		{
			name: "no pattern hits",
			line: "sshd[1]: Accepted publickey for root from 203.0.113.9 port 22 ssh2",
			out:  OutcomeNoMatch,
		},
		{
			name: "ignored by literal",
			line: "sshd[1]: Failed password for user backup  from 203.0.113.9 port 22 ssh2",
			out:  OutcomeIgnored,
		},
		{
			name: "ignored by regex",
			line: "sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2",
			out:  OutcomeIgnored,
		},
		{
			name: "empty line",
			line: "",
			out:  OutcomeNoMatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, out := set.Match([]byte(tc.line))
			if out != tc.out {
				t.Fatalf("outcome = %v, want %v", out, tc.out)
			}
			if tc.ip == "" {
				if res.IP.IsValid() {
					t.Errorf("unexpected ip %v", res.IP)
				}
				return
			}
			if res.IP.String() != tc.ip {
				t.Errorf("ip = %v, want %v", res.IP, tc.ip)
			}
			if res.Pattern == "" {
				t.Errorf("Result.Pattern is empty; {matched} would render nothing")
			}
		})
	}
}

// Result.Pattern has to identify which rule fired, because actions expose it
// as {matched}.
func TestResultPattern(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{Line: []string{"alpha <IP>", "beta <IP>"}})
	res, out := set.Match([]byte("beta 1.2.3.4"))
	if out != OutcomeMatch {
		t.Fatalf("outcome = %v", out)
	}
	if res.Pattern != "beta <IP>" {
		t.Errorf("Pattern = %q, want the source pattern %q", res.Pattern, "beta <IP>")
	}

	jsonSet := mustCompile(t, Spec{
		Format:  "json",
		Fields:  map[string]string{"msg": "failed", "level": "error"},
		IPField: "ip",
	})
	res, out = jsonSet.Match([]byte(`{"msg":"failed","level":"error","ip":"1.2.3.4"}`))
	if out != OutcomeMatch {
		t.Fatalf("outcome = %v", out)
	}
	if want := "level=error && msg=failed"; res.Pattern != want {
		t.Errorf("Pattern = %q, want %q", res.Pattern, want)
	}
}

// A pattern with no IP source at all still matches; the pipeline just has
// nobody to ban.
func TestMatchWithoutIPSource(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{Line: []string{"Failed password"}})
	res, out := set.Match([]byte("Failed password for root from 1.2.3.4"))
	if out != OutcomeNoIP {
		t.Fatalf("outcome = %v, want no_ip", out)
	}
	if res.Pattern != "Failed password" {
		t.Errorf("Pattern = %q", res.Pattern)
	}
}

// An operator who ignores a line should not also get a "could not find an IP"
// warning for it.
func TestIgnoreBeatsNoIP(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{Line: []string{"<IP>"}, IgnoreLine: []string{"ignore-me"}})
	if _, out := set.Match([]byte("999.1.1.1 ignore-me")); out != OutcomeIgnored {
		t.Errorf("outcome = %v, want ignored", out)
	}
}

func TestMatchJSON(t *testing.T) {
	t.Parallel()
	spec := Spec{
		Format:       "json",
		Fields:       map[string]string{"msg": "authentication failure", "level": "^error$"},
		IgnoreFields: map[string]string{"user": "^backup$"},
		IPField:      "request.remote_ip",
	}
	set := mustCompile(t, spec)

	tests := []struct {
		name string
		line string
		ip   string
		out  Outcome
	}{
		{
			name: "all fields match",
			line: `{"level":"error","msg":"authentication failure for root","request":{"remote_ip":"203.0.113.11"}}`,
			ip:   "203.0.113.11",
			out:  OutcomeMatch,
		},
		{
			name: "one field does not match",
			line: `{"level":"info","msg":"authentication failure","request":{"remote_ip":"203.0.113.11"}}`,
			out:  OutcomeNoMatch,
		},
		{
			name: "field missing entirely",
			line: `{"level":"error","request":{"remote_ip":"203.0.113.11"}}`,
			out:  OutcomeNoMatch,
		},
		{
			name: "ignored by field",
			line: `{"level":"error","msg":"authentication failure","user":"backup","request":{"remote_ip":"203.0.113.11"}}`,
			out:  OutcomeIgnored,
		},
		{
			name: "ip field missing",
			line: `{"level":"error","msg":"authentication failure"}`,
			out:  OutcomeNoIP,
		},
		{
			name: "ip field is not an address",
			line: `{"level":"error","msg":"authentication failure","request":{"remote_ip":"not-an-ip"}}`,
			out:  OutcomeNoIP,
		},
		{
			name: "ip field carries a port",
			line: `{"level":"error","msg":"authentication failure","request":{"remote_ip":"[2001:db8::5]:443"}}`,
			ip:   "2001:db8::5",
			out:  OutcomeMatch,
		},
		{
			name: "v4 mapped ip field is unmapped",
			line: `{"level":"error","msg":"authentication failure","request":{"remote_ip":"::ffff:203.0.113.11"}}`,
			ip:   "203.0.113.11",
			out:  OutcomeMatch,
		},
		{
			name: "zone scoped ip field is refused",
			line: `{"level":"error","msg":"authentication failure","request":{"remote_ip":"fe80::1%eth0"}}`,
			out:  OutcomeNoIP,
		},
		{
			name: "malformed json",
			line: `{"level":"error","msg":`,
			out:  OutcomeDecodeError,
		},
		{
			name: "not json at all",
			line: `Sep 15 12:00:00 host sshd[1]: Failed password`,
			out:  OutcomeDecodeError,
		},
		{
			name: "empty line",
			line: ``,
			out:  OutcomeDecodeError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, out := set.Match([]byte(tc.line))
			if out != tc.out {
				t.Fatalf("outcome = %v, want %v", out, tc.out)
			}
			if tc.ip == "" {
				if res.IP.IsValid() {
					t.Errorf("unexpected ip %v", res.IP)
				}
				return
			}
			if res.IP.String() != tc.ip {
				t.Errorf("ip = %v, want %v", res.IP, tc.ip)
			}
		})
	}
}

// In JSON mode the IP may come from a macro inside a field regex instead of
// ip_field.
func TestMatchJSONFieldMacro(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{
		Format: "json",
		Fields: map[string]string{"msg": "refused connection from <IP>"},
	})
	res, out := set.Match([]byte(`{"msg":"refused connection from 198.51.100.200 (blocked)"}`))
	if out != OutcomeMatch {
		t.Fatalf("outcome = %v", out)
	}
	if res.IP.String() != "198.51.100.200" {
		t.Errorf("ip = %v", res.IP)
	}
}

// Line patterns in JSON mode run against the raw line, which is how people
// write a quick rule without naming fields.
func TestMatchJSONLinePattern(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{
		Format: "json",
		Line:   []string{`"status":40[13].*"remote_ip":"<IP>"`},
	})
	res, out := set.Match([]byte(`{"status":403,"remote_ip":"203.0.113.30"}`))
	if out != OutcomeMatch {
		t.Fatalf("outcome = %v", out)
	}
	if res.IP.String() != "203.0.113.30" {
		t.Errorf("ip = %v", res.IP)
	}
	// With no decoded paths needed, a malformed line is simply a non-match
	// rather than a decode error; document that by asserting it.
	if _, out := set.Match([]byte(`{"status":403`)); out != OutcomeNoMatch {
		t.Errorf("outcome = %v, want no_match", out)
	}
}

// Escaped JSON values are matched after unescaping, which is the whole point
// of decoding rather than regexing the raw line.
func TestMatchJSONEscapedValue(t *testing.T) {
	t.Parallel()
	set := mustCompile(t, Spec{
		Format:  "json",
		Fields:  map[string]string{"msg": `user "root" failed`},
		IPField: "ip",
	})
	res, out := set.Match([]byte(`{"msg":"user \"root\" failed","ip":"1.2.3.4"}`))
	if out != OutcomeMatch {
		t.Fatalf("outcome = %v", out)
	}
	if res.IP.String() != "1.2.3.4" {
		t.Errorf("ip = %v", res.IP)
	}
}

func TestContainsPrefilter(t *testing.T) {
	t.Parallel()
	// Contains is a user override; it must gate the whole set.
	set := mustCompile(t, Spec{
		Line:     []string{"(?i)failed password from <IP>"},
		Contains: "sshd",
	})
	if _, out := set.Match([]byte("Failed password from 1.2.3.4")); out != OutcomeNoMatch {
		t.Errorf("line without the literal matched anyway: %v", out)
	}
	res, out := set.Match([]byte("sshd: Failed password from 1.2.3.4"))
	if out != OutcomeMatch || res.IP.String() != "1.2.3.4" {
		t.Errorf("got (%v, %v), want match 1.2.3.4", res.IP, out)
	}
}

func TestOutcomeString(t *testing.T) {
	t.Parallel()
	want := map[Outcome]string{
		OutcomeNoMatch:     "no_match",
		OutcomeMatch:       "match",
		OutcomeIgnored:     "ignored",
		OutcomeDecodeError: "decode_error",
		OutcomeNoIP:        "no_ip",
		Outcome(42):        "outcome(42)",
	}
	for o, s := range want {
		if got := o.String(); got != s {
			t.Errorf("Outcome(%d).String() = %q, want %q", int(o), got, s)
		}
	}
}

// The matcher pool shares one *Set across goroutines; the scratch state must
// not leak between them.
func TestMatchConcurrent(t *testing.T) {
	t.Parallel()
	textSet := mustCompile(t, Spec{Line: []string{"Failed password for .* from <IP> port"}})
	jsonSet := mustCompile(t, Spec{
		Format:  "json",
		Fields:  map[string]string{"msg": "failed"},
		IPField: "request.remote_ip",
	})

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				line := []byte("Failed password for root from 203.0.113." + string(rune('0'+g)) + " port 22")
				if _, out := textSet.Match(line); out != OutcomeMatch {
					t.Errorf("text outcome = %v", out)
					return
				}
				jline := []byte(`{"msg":"failed","request":{"remote_ip":"198.51.100.` + string(rune('0'+g)) + `"}}`)
				res, out := jsonSet.Match(jline)
				if out != OutcomeMatch {
					t.Errorf("json outcome = %v", out)
					return
				}
				if want := "198.51.100." + string(rune('0'+g)); res.IP.String() != want {
					t.Errorf("ip = %v, want %v", res.IP, want)
					return
				}
				// Interleave a non-matching and a malformed line.
				textSet.Match([]byte("nothing to see here"))
				jsonSet.Match([]byte(`{"msg":`))
			}
		}(g)
	}
	wg.Wait()
}

// The non-matching path is the one that runs on essentially every line.
func TestMatchNoMatchIsAllocationFree(t *testing.T) {
	// Not parallel: AllocsPerRun needs the process to itself.
	if raceEnabled {
		t.Skip("race instrumentation allocates; run without -race")
	}
	set := mustCompile(t, Spec{Line: []string{"Failed password for .* from <IP> port"}})
	line := []byte("Sep 15 12:00:00 host CRON[123]: pam_unix(cron:session): session opened for user root")
	if got := testing.AllocsPerRun(200, func() { set.Match(line) }); got != 0 {
		t.Errorf("non-matching text line allocated %v times, want 0", got)
	}

	jsonSet := mustCompile(t, Spec{
		Format:  "json",
		Fields:  map[string]string{"msg": "authentication failure"},
		IPField: "request.remote_ip",
	})
	jline := []byte(`{"level":"info","msg":"handled request","request":{"remote_ip":"203.0.113.5"},"status":200}`)
	if got := testing.AllocsPerRun(200, func() { jsonSet.Match(jline) }); got != 0 {
		t.Errorf("non-matching json line allocated %v times, want 0", got)
	}
}

var (
	benchTextSpec = Spec{
		Line: []string{
			"Failed password for .* from <IP> port",
			"Invalid user .* from <IP>",
			`Disconnected from authenticating user \S+ <IP> port`,
		},
	}
	benchMissLine = []byte("Sep 15 12:00:00 host CRON[12345]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
	benchHitLine  = []byte("Sep 15 12:00:00 host sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 55234 ssh2")
)

func BenchmarkMatchTextMiss(b *testing.B) {
	set, err := Compile(benchTextSpec)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchMissLine)))
	for b.Loop() {
		if _, out := set.Match(benchMissLine); out != OutcomeNoMatch {
			b.Fatalf("outcome = %v", out)
		}
	}
}

// The same corpus with the prefilter disabled, to show what it buys.
func BenchmarkMatchTextMissNoPrefilter(b *testing.B) {
	set, err := compile(benchTextSpec, false)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchMissLine)))
	for b.Loop() {
		if _, out := set.Match(benchMissLine); out != OutcomeNoMatch {
			b.Fatalf("outcome = %v", out)
		}
	}
}

func BenchmarkMatchTextHit(b *testing.B) {
	set, err := Compile(benchTextSpec)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchHitLine)))
	for b.Loop() {
		if _, out := set.Match(benchHitLine); out != OutcomeMatch {
			b.Fatalf("outcome = %v", out)
		}
	}
}

var (
	benchJSONSpec = Spec{
		Format:  "json",
		Fields:  map[string]string{"msg": "authentication failure"},
		IPField: "request.remote_ip",
	}
	benchJSONMiss = []byte(`{"level":"info","ts":1700000000.1,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.5","method":"GET","uri":"/"},"status":200}`)
	benchJSONHit  = []byte(`{"level":"error","ts":1700000000.1,"logger":"auth","msg":"authentication failure for root","request":{"remote_ip":"203.0.113.5","method":"POST","uri":"/login"},"status":403}`)
)

func BenchmarkMatchJSONMiss(b *testing.B) {
	set, err := Compile(benchJSONSpec)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchJSONMiss)))
	for b.Loop() {
		if _, out := set.Match(benchJSONMiss); out != OutcomeNoMatch {
			b.Fatalf("outcome = %v", out)
		}
	}
}

func BenchmarkMatchJSONHit(b *testing.B) {
	set, err := Compile(benchJSONSpec)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(benchJSONHit)))
	for b.Loop() {
		if _, out := set.Match(benchJSONHit); out != OutcomeMatch {
			b.Fatalf("outcome = %v", out)
		}
	}
}

func BenchmarkMatchParallel(b *testing.B) {
	set, err := Compile(benchTextSpec)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			set.Match(benchMissLine)
		}
	})
}
