package decode

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		raw   string
		paths []string
		want  map[string]string
	}{
		{
			name:  "flat string",
			raw:   `{"msg":"hello","level":"error"}`,
			paths: []string{"msg", "level"},
			want:  map[string]string{"msg": "hello", "level": "error"},
		},
		{
			name:  "nested object",
			raw:   `{"request":{"remote_ip":"1.2.3.4","method":"GET"},"status":403}`,
			paths: []string{"request.remote_ip", "status"},
			want:  map[string]string{"request.remote_ip": "1.2.3.4", "status": "403"},
		},
		{
			name:  "array index",
			raw:   `{"headers":["a","b","c"]}`,
			paths: []string{"headers.0", "headers.2"},
			want:  map[string]string{"headers.0": "a", "headers.2": "c"},
		},
		{
			name:  "array index out of range",
			raw:   `{"headers":["a"]}`,
			paths: []string{"headers.4"},
			want:  map[string]string{},
		},
		{
			name:  "array index leading zero never matches",
			raw:   `{"headers":["a","b"]}`,
			paths: []string{"headers.01"},
			want:  map[string]string{},
		},
		{
			name:  "object inside array",
			raw:   `{"a":[{"b":1},{"b":2}]}`,
			paths: []string{"a.0.b", "a.1.b"},
			want:  map[string]string{"a.0.b": "1", "a.1.b": "2"},
		},
		{
			name:  "top level array",
			raw:   `[{"ip":"9.9.9.9"}]`,
			paths: []string{"0.ip"},
			want:  map[string]string{"0.ip": "9.9.9.9"},
		},
		{
			name:  "literals are rendered verbatim",
			raw:   `{"a":true,"b":false,"c":null,"d":-1.5e+10,"e":0}`,
			paths: []string{"a", "b", "c", "d", "e"},
			want:  map[string]string{"a": "true", "b": "false", "c": "null", "d": "-1.5e+10", "e": "0"},
		},
		{
			name:  "container value yields raw json",
			raw:   `{"req":{"a":1,"b":[2,3]},"arr":[1,2]}`,
			paths: []string{"req", "arr"},
			want:  map[string]string{"req": `{"a":1,"b":[2,3]}`, "arr": `[1,2]`},
		},
		{
			name:  "missing paths are absent",
			raw:   `{"a":1}`,
			paths: []string{"a", "b", "a.b.c"},
			want:  map[string]string{"a": "1"},
		},
		{
			name:  "duplicate key last wins",
			raw:   `{"a":"first","a":"second"}`,
			paths: []string{"a"},
			want:  map[string]string{"a": "second"},
		},
		{
			name:  "escapes are decoded",
			raw:   `{"m":"a\"b\\c\/d\be\ff\ng\rh\ti"}`,
			paths: []string{"m"},
			want:  map[string]string{"m": "a\"b\\c/d\be\ff\ng\rh\ti"},
		},
		{
			name:  "unicode escape",
			raw:   `{"m":"caf\u00e9"}`,
			paths: []string{"m"},
			want:  map[string]string{"m": "café"},
		},
		{
			name:  "surrogate pair",
			raw:   `{"m":"\ud83d\udca9"}`,
			paths: []string{"m"},
			want:  map[string]string{"m": "\U0001F4A9"},
		},
		{
			name:  "lone high surrogate becomes replacement char",
			raw:   `{"m":"\ud83d"}`,
			paths: []string{"m"},
			want:  map[string]string{"m": "\uFFFD"},
		},
		{
			name:  "lone low surrogate becomes replacement char",
			raw:   `{"m":"x\udca9y"}`,
			paths: []string{"m"},
			want:  map[string]string{"m": "x\uFFFDy"},
		},
		{
			name:  "escaped key",
			raw:   `{"a\u002eb":"x","a":{"b":"y"}}`,
			paths: []string{"a.b"},
			want:  map[string]string{"a.b": "y"},
		},
		{
			name:  "escaped key matches when the path segment needs it",
			raw:   `{"we\"ird":"v"}`,
			paths: []string{`we"ird`},
			want:  map[string]string{`we"ird`: "v"},
		},
		{
			name:  "empty string value",
			raw:   `{"a":""}`,
			paths: []string{"a"},
			want:  map[string]string{"a": ""},
		},
		{
			name:  "empty containers",
			raw:   `{"a":{},"b":[]}`,
			paths: []string{"a", "b", "a.x", "b.0"},
			want:  map[string]string{"a": "{}", "b": "[]"},
		},
		{
			name:  "whitespace everywhere",
			raw:   " {\n\t\"a\" :\r [ 1 , { \"b\" : \"c\" } ] \n} ",
			paths: []string{"a.1.b"},
			want:  map[string]string{"a.1.b": "c"},
		},
		{
			name:  "no paths requested",
			raw:   `{"a":1}`,
			paths: nil,
			want:  map[string]string{},
		},
		{
			name:  "duplicate requested path",
			raw:   `{"a":"x"}`,
			paths: []string{"a", "a"},
			want:  map[string]string{"a": "x"},
		},
		{
			name:  "path prefix of another path",
			raw:   `{"a":{"b":"x"}}`,
			paths: []string{"a", "a.b"},
			want:  map[string]string{"a": `{"b":"x"}`, "a.b": "x"},
		},
		{
			name:  "sibling with same leading segment",
			raw:   `{"a":{"b":{"c":"1"}},"ab":{"c":"2"}}`,
			paths: []string{"a.b.c", "ab.c"},
			want:  map[string]string{"a.b.c": "1", "ab.c": "2"},
		},
		{
			name:  "key repeated at a different depth",
			raw:   `{"x":{"x":{"x":"deep"}},"y":"shallow"}`,
			paths: []string{"x.x.x", "y"},
			want:  map[string]string{"x.x.x": "deep", "y": "shallow"},
		},
		{
			name:  "invalid utf8 in a value passes through",
			raw:   "{\"a\":\"\xff\xfe\"}",
			paths: []string{"a"},
			want:  map[string]string{"a": "\xff\xfe"},
		},
		{
			name:  "caddy access log",
			raw:   `{"level":"error","ts":1700000000.123,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.5","remote_port":"54321","proto":"HTTP/2.0","method":"POST","host":"example.com","uri":"/wp-login.php","headers":{"User-Agent":["curl/8.0"]}},"status":403}`,
			paths: []string{"request.remote_ip", "status", "request.uri", "request.headers.User-Agent.0"},
			want: map[string]string{
				"request.remote_ip":            "203.0.113.5",
				"status":                       "403",
				"request.uri":                  "/wp-login.php",
				"request.headers.User-Agent.0": "curl/8.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := make(map[string]string)
			if err := Fields([]byte(tc.raw), tc.paths, dst); err != nil {
				t.Fatalf("Fields() error = %v", err)
			}
			if len(dst) != len(tc.want) {
				t.Errorf("got %d fields %v, want %d %v", len(dst), dst, len(tc.want), tc.want)
			}
			for k, want := range tc.want {
				if got, ok := dst[k]; !ok {
					t.Errorf("missing path %q (got %v)", k, dst)
				} else if got != want {
					t.Errorf("path %q = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// A monitor may reference more paths than the walker's initial bookkeeping
// capacity; the grow path must behave identically.
func TestFieldsManyPaths(t *testing.T) {
	t.Parallel()
	const n = 40
	var sb strings.Builder
	paths := make([]string, 0, n)
	sb.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"k%d":"v%d"`, i, i)
		paths = append(paths, fmt.Sprintf("k%d", i))
	}
	sb.WriteByte('}')

	dst := make(map[string]string)
	if err := Fields([]byte(sb.String()), paths, dst); err != nil {
		t.Fatalf("Fields() error = %v", err)
	}
	if len(dst) != len(paths) {
		t.Fatalf("got %d fields, want %d", len(dst), len(paths))
	}
	for i, p := range paths {
		if got, want := dst[p], fmt.Sprintf("v%d", i); got != want {
			t.Errorf("path %q = %q, want %q", p, got, want)
		}
	}
}

func TestFieldsClearsDst(t *testing.T) {
	t.Parallel()
	dst := map[string]string{"stale": "junk", "a": "old"}
	if err := Fields([]byte(`{"a":"new"}`), []string{"a", "b"}, dst); err != nil {
		t.Fatalf("Fields() error = %v", err)
	}
	if _, ok := dst["stale"]; ok {
		t.Errorf("stale key survived: %v", dst)
	}
	if dst["a"] != "new" {
		t.Errorf("a = %q, want %q", dst["a"], "new")
	}
	if len(dst) != 1 {
		t.Errorf("dst = %v, want only {a:new}", dst)
	}

	// A path that disappears from a later line must disappear from dst.
	if err := Fields([]byte(`{"b":"only"}`), []string{"a", "b"}, dst); err != nil {
		t.Fatalf("Fields() error = %v", err)
	}
	if _, ok := dst["a"]; ok {
		t.Errorf("a should be gone: %v", dst)
	}
	if dst["b"] != "only" {
		t.Errorf("b = %q, want %q", dst["b"], "only")
	}
}

func TestFieldsNilDst(t *testing.T) {
	t.Parallel()
	if err := Fields([]byte(`{"a":1}`), []string{"a"}, nil); !errors.Is(err, ErrNilDst) {
		t.Fatalf("Fields(nil dst) = %v, want ErrNilDst", err)
	}
}

func TestFieldsMalformed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ``},
		{"whitespace only", "  \n"},
		{"unterminated object", `{"a":1`},
		{"unterminated array", `[1,2`},
		{"unterminated string", `{"a":"xy`},
		{"unterminated escape", `{"a":"xy\`},
		{"missing colon", `{"a" 1}`},
		{"missing value", `{"a":}`},
		{"missing key", `{1:2}`},
		{"trailing comma in object", `{"a":1,}`},
		{"trailing comma in array", `[1,]`},
		{"trailing garbage", `{"a":1} {"b":2}`},
		{"trailing garbage scalar", `1 2`},
		{"bare word", `nope`},
		{"truncated literal", `tru`},
		{"bad escape", `{"a":"\q"}`},
		{"short unicode escape", `{"a":"\u12"}`},
		{"non hex unicode escape", `{"a":"\uZZZZ"}`},
		{"raw control char", "{\"a\":\"x\ny\"}"},
		{"leading zero number", `{"a":01}`},
		{"negative leading zero", `{"a":-01}`},
		{"bare minus", `{"a":-}`},
		{"trailing dot", `{"a":1.}`},
		{"leading dot", `{"a":.5}`},
		{"empty exponent", `{"a":1e}`},
		{"plus sign", `{"a":+1}`},
		{"NaN", `{"a":NaN}`},
		{"single quotes", `{'a':1}`},
		{"unquoted key", `{a:1}`},
		{"lone close brace", `}`},
		{"mismatched brackets", `{"a":[1}`},
		{"object as array element key", `[{"a" 1}]`},
		{"nul byte in string", "{\"a\":\"\x00\"}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := map[string]string{"pre": "existing"}
			err := Fields([]byte(tc.raw), []string{"a", "b"}, dst)
			if err == nil {
				t.Fatalf("Fields(%q) = nil error, want a syntax error (dst=%v)", tc.raw, dst)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("error %v is not a *SyntaxError", err)
			}
			if se.Offset < 0 || se.Offset > len(tc.raw) {
				t.Errorf("offset %d out of range for input of %d bytes", se.Offset, len(tc.raw))
			}
			if len(dst) != 0 {
				t.Errorf("dst not cleared on error: %v", dst)
			}
		})
	}
}

// Malformed input buried below the requested paths must still be reported:
// a line we cannot fully parse is a line whose fields we cannot trust.
func TestFieldsMalformedInSkippedSubtree(t *testing.T) {
	t.Parallel()
	tests := []string{
		`{"a":"ok","ignored":{"b":nul}}`,
		`{"a":"ok","ignored":[1,2,}`,
		`{"a":"ok","ignored":["x\q"]}`,
		`{"a":"ok","ignored":[01]}`,
		`{"a":"ok","ignored":{"b" 1}}`,
		`{"a":"ok","ignored":{1:2}}`,
		`{"a":"ok","ignored":tru}`,
		`{"a":"ok","ignored":[[[}]]]}`,
		`{"a":"ok","ignored":`,
		`{"a":"ok","ignored":[`,
		`{"a":"ok","ignored":{"b":"unterminated}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			dst := make(map[string]string)
			if err := Fields([]byte(raw), []string{"a"}, dst); err == nil {
				t.Fatalf("Fields(%q) = nil, want error", raw)
			}
			if len(dst) != 0 {
				t.Errorf("dst = %v, want empty", dst)
			}
		})
	}
}

func TestSyntaxErrorMessage(t *testing.T) {
	t.Parallel()
	err := Fields([]byte(`{"a":}`), []string{"a"}, make(map[string]string))
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "decode:") || !strings.Contains(msg, "offset 5") {
		t.Errorf("error message %q should name the package and the offset", msg)
	}
}

// A single pathological line must not leave a huge scratch buffer pinned in
// the walker pool.
func TestFieldsHugeEscapedValueIsNotRetained(t *testing.T) {
	t.Parallel()
	big := `{"a":"` + strings.Repeat(`\n`, maxRetainedScratch) + `"}`
	dst := make(map[string]string)
	if err := Fields([]byte(big), []string{"a"}, dst); err != nil {
		t.Fatalf("Fields() error = %v", err)
	}
	if got := len(dst["a"]); got != maxRetainedScratch {
		t.Fatalf("value length = %d, want %d", got, maxRetainedScratch)
	}
	// The next line must still decode correctly with the recycled walker.
	if err := Fields([]byte(`{"a":"small"}`), []string{"a"}, dst); err != nil {
		t.Fatalf("Fields() error = %v", err)
	}
	if dst["a"] != "small" {
		t.Errorf("a = %q, want %q", dst["a"], "small")
	}
}

func TestFieldsDepthLimit(t *testing.T) {
	t.Parallel()
	nest := func(n int) []byte {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString(`{"a":`)
		}
		sb.WriteString(`1`)
		for i := 0; i < n; i++ {
			sb.WriteString(`}`)
		}
		return []byte(sb.String())
	}
	dst := make(map[string]string)

	if err := Fields(nest(MaxDepth), []string{"a"}, dst); err != nil {
		t.Errorf("nesting of exactly MaxDepth should parse, got %v", err)
	}
	// Hostile input: far past the limit, both on the requested-path walk and
	// on the skip path. Neither may blow the stack.
	for _, paths := range [][]string{{"a"}, {"zzz"}} {
		if err := Fields(nest(100_000), paths, dst); err == nil {
			t.Errorf("paths=%v: deep nesting accepted, want error", paths)
		}
	}
	// Unbalanced but deep (no closing brackets) must not hang or crash.
	if err := Fields([]byte(strings.Repeat(`[`, 100_000)), []string{"a"}, dst); err == nil {
		t.Errorf("unbalanced deep input accepted, want error")
	}
}

// The steady state of the daemon is the same monitor decoding line after line
// into the same map; that must not allocate once the values repeat.
func TestFieldsAllocations(t *testing.T) {
	// Not parallel: AllocsPerRun requires exclusive use of the process.
	if raceEnabled {
		t.Skip("race instrumentation allocates; run without -race")
	}
	raw := []byte(`{"level":"error","request":{"remote_ip":"203.0.113.5","uri":"/x"},"status":403}`)
	paths := []string{"request.remote_ip", "status", "level"}
	dst := make(map[string]string)
	if err := Fields(raw, paths, dst); err != nil {
		t.Fatal(err)
	}
	got := testing.AllocsPerRun(200, func() {
		if err := Fields(raw, paths, dst); err != nil {
			t.Fatal(err)
		}
	})
	if got != 0 {
		t.Errorf("Fields allocated %v times per run on repeated values, want 0", got)
	}
}

func FuzzFields(f *testing.F) {
	seeds := []string{
		`{"a":1}`,
		`{"request":{"remote_ip":"1.2.3.4"},"status":403}`,
		`{"a":[1,{"b":"c"}]}`,
		`{"a":"\ud83d\ude00\u0000\\"}`,
		`[[[[[[[[[[1]]]]]]]]]]`,
		`{"a":-1.5e+10,"b":null,"c":true}`,
		`{"a.b":"dotted key","a":{"b":"nested"}}`,
		"{\"\xff\":\"\xfe\"}",
		`{"a":{"a":{"a":{"a":"deep"}}}}`,
		`  {"a" : "b"}  `,
		`{"a":1}{"a":2}`,
		`{"":""}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "a.b")
	}

	f.Fuzz(func(t *testing.T, raw []byte, pathSpec string) {
		// The path list is attacker-influenced too: it comes from config, but
		// nothing about the walk should depend on it being well formed.
		paths := strings.Split(pathSpec, ",")
		if len(paths) > 8 {
			paths = paths[:8]
		}
		dst := make(map[string]string)
		err := Fields(raw, paths, dst)
		if err != nil {
			if len(dst) != 0 {
				t.Fatalf("dst not cleared on error: %v", dst)
			}
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("non-syntax error %v", err)
			}
			return
		}
		// Every key present must be one of the requested paths, and every
		// value must be a plausible rendering (we cannot check much more
		// without a second parser, but these invariants catch scribbles).
		for k, v := range dst {
			found := false
			for _, p := range paths {
				if p == k {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("dst contains unrequested path %q=%q", k, v)
			}
		}
		if len(dst) > len(paths) {
			t.Fatalf("more results (%d) than paths (%d)", len(dst), len(paths))
		}
		// Running twice must be idempotent.
		second := make(map[string]string)
		if err := Fields(raw, paths, second); err != nil {
			t.Fatalf("second pass failed: %v", err)
		}
		if len(second) != len(dst) {
			t.Fatalf("not idempotent: %v vs %v", dst, second)
		}
		for k, v := range dst {
			if second[k] != v {
				t.Fatalf("not idempotent for %q: %q vs %q", k, v, second[k])
			}
		}
	})
}

var benchLine = []byte(`{"level":"error","ts":1700000000.123,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.5","remote_port":"54321","proto":"HTTP/2.0","method":"POST","host":"example.com","uri":"/wp-login.php","headers":{"User-Agent":["curl/8.0"]}},"duration":0.0012,"status":403}`)

func BenchmarkFields(b *testing.B) {
	paths := []string{"request.remote_ip", "status"}
	dst := make(map[string]string)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchLine)))
	for b.Loop() {
		if err := Fields(benchLine, paths, dst); err != nil {
			b.Fatal(err)
		}
	}
}

// The value changes on every line, which is the realistic worst case: one
// string allocation per extracted field and nothing else.
func BenchmarkFieldsChangingValue(b *testing.B) {
	paths := []string{"request.remote_ip"}
	dst := make(map[string]string)
	lines := make([][]byte, 256)
	for i := range lines {
		lines[i] = []byte(fmt.Sprintf(`{"request":{"remote_ip":"203.0.113.%d"},"status":403}`, i))
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if err := Fields(lines[i%len(lines)], paths, dst); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkFieldsMiss(b *testing.B) {
	paths := []string{"nope.not.here"}
	dst := make(map[string]string)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchLine)))
	for b.Loop() {
		if err := Fields(benchLine, paths, dst); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFieldsEscaped(b *testing.B) {
	raw := []byte(`{"msg":"a \"quoted\" \u00e9 string with \\ escapes","ip":"1.2.3.4"}`)
	paths := []string{"msg", "ip"}
	dst := make(map[string]string)
	b.ReportAllocs()
	for b.Loop() {
		if err := Fields(raw, paths, dst); err != nil {
			b.Fatal(err)
		}
	}
}
