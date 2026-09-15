package source

import "testing"

func TestStripSyslog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "rfc3164 with pid",
			in:   "<34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed for lonvick",
			want: "'su root' failed for lonvick",
		},
		{
			name: "rfc3164 without pid",
			in:   "<38>Jan  2 03:04:05 host sshd: Failed password for root from 10.0.0.1",
			want: "Failed password for root from 10.0.0.1",
		},
		{
			name: "rfc3164 space padded day",
			in:   "<13>Feb  5 09:08:07 host tag: message here",
			want: "message here",
		},
		{
			name: "rfc3164 without pri",
			in:   "Oct 11 22:14:15 mymachine su: message",
			want: "message",
		},
		{
			name: "rfc3164 with iso timestamp",
			in:   "<13>2023-01-02T03:04:05.123456+02:00 host app[7]: json={\"a\":1}",
			want: "json={\"a\":1}",
		},
		{
			name: "rfc3164 message containing colons is not re-split",
			in:   "<34>Oct 11 22:14:15 host sshd[1]: error: maximum authentication attempts: 3",
			want: "error: maximum authentication attempts: 3",
		},
		{
			name: "rfc3164 with no tag keeps the whole message",
			in:   "<34>Oct 11 22:14:15 host this message has no tag",
			want: "this message has no tag",
		},
		{
			name: "rfc5424 with nil structured data",
			in:   "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed",
			want: "BOM'su root' failed",
		},
		{
			name: "rfc5424 with structured data",
			in:   `<165>1 2003-10-11T22:14:15.003Z host evntslog - ID47 [exampleSDID@32473 iut="3"] An application event`,
			want: "An application event",
		},
		{
			name: "rfc5424 with several structured data elements",
			in:   `<165>1 2003-08-24T05:14:15Z host evntslog - ID47 [a@1 k="v"][b@2 k="v"] message`,
			want: "message",
		},
		{
			name: "rfc5424 with an escaped bracket in structured data",
			in:   `<165>1 2003-08-24T05:14:15Z host app - - [a@1 k="v\]"] message`,
			want: "message",
		},
		{
			name: "rfc5424 with a utf8 bom",
			in:   "<165>1 2003-08-24T05:14:15Z host app - - - \xEF\xBB\xBFmessage",
			want: "message",
		},
		{
			name: "rfc5424 with an empty message",
			in:   "<165>1 2003-08-24T05:14:15Z host app - - -",
			want: "",
		},
		{
			name: "plain line is untouched",
			in:   "Failed password for root from 10.0.0.1 port 22 ssh2",
			want: "Failed password for root from 10.0.0.1 port 22 ssh2",
		},
		{
			name: "unparseable prefix is passed through, only pri removed",
			in:   "<34>total garbage here",
			want: "total garbage here",
		},
		{
			name: "malformed pri is left alone",
			in:   "<not-a-pri>hello",
			want: "<not-a-pri>hello",
		},
		{
			name: "unterminated pri is left alone",
			in:   "<34 Oct 11 22:14:15 host tag: msg",
			want: "<34 Oct 11 22:14:15 host tag: msg",
		},
		{
			name: "json line beginning with a brace survives",
			in:   `{"msg":"hi","ip":"10.0.0.1"}`,
			want: `{"msg":"hi","ip":"10.0.0.1"}`,
		},
		{
			name: "empty line",
			in:   "",
			want: "",
		},
		{
			name: "just a pri",
			in:   "<34>",
			want: "",
		},
		{
			name: "truncated rfc5424 header is passed through",
			in:   "<34>1 2003-10-11T22:14:15.003Z host",
			want: "1 2003-10-11T22:14:15.003Z host",
		},
		{
			name: "unclosed structured data is passed through",
			in:   "<34>1 2003-10-11T22:14:15.003Z host app - - [a@1 k=\"v\" message",
			want: "1 2003-10-11T22:14:15.003Z host app - - [a@1 k=\"v\" message",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := string(stripSyslog([]byte(tc.in)))
			if got != tc.want {
				t.Errorf("stripSyslog(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

// stripSyslog must never grow a line or point outside it: the result must
// always be a suffix of the input.
func FuzzStripSyslogStaysWithinInput(f *testing.F) {
	seeds := []string{
		"<34>Oct 11 22:14:15 host tag: msg",
		"<165>1 2003-10-11T22:14:15.003Z host app - - [a@1 k=\"v\"] msg",
		"plain",
		"<",
		"<1>",
		"<999999>x",
		"Jan  1 00:00:00 h t: m",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		got := stripSyslog(in)
		if len(got) > len(in) {
			t.Fatalf("stripSyslog grew the line: %d > %d", len(got), len(in))
		}
		if len(got) > 0 && string(in[len(in)-len(got):]) != string(got) {
			t.Fatalf("result %q is not a suffix of input %q", got, in)
		}
	})
}
