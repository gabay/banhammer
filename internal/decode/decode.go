// Package decode extracts a fixed set of dotted paths out of a JSON log line
// in a single pass.
//
// Log matching only ever needs a handful of fields (the ones named by a
// monitor's rules plus its ip_field), so unmarshalling into a map[string]any
// would allocate an object graph per line and throw almost all of it away.
// Fields instead scans the document at the token level and copies out only the
// requested values, which keeps the per-line cost proportional to the size of
// the line rather than to its structure.
package decode

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the deepest container nesting Fields will walk. Log lines are
// shallow; a cap keeps hostile input from turning nesting into unbounded
// recursion.
const MaxDepth = 128

// ErrNilDst is returned when Fields is called with a nil destination map.
// Fields cannot allocate one for the caller because the map is expected to be
// reused across lines.
var ErrNilDst = errors.New("decode: dst map is nil")

// SyntaxError describes malformed JSON, including the byte offset at which the
// scanner gave up. Callers generally only count these (decode_errors_total),
// but the offset makes a rate-limited warning actionable.
type SyntaxError struct {
	Offset int    // byte offset within raw
	Msg    string // what the scanner expected
}

// Error reports what the scanner expected and where it gave up.
func (e *SyntaxError) Error() string {
	return fmt.Sprintf("decode: %s at byte offset %d", e.Msg, e.Offset)
}

// result is where a path's value was found: a range either in the input or in
// the walker's unescape scratch buffer.
type result struct {
	start, end int
	scratch    bool
	found      bool
}

// The walk is recursive, so its bookkeeping slices unavoidably escape; pooling
// them is what keeps the steady state allocation-free. The pool also makes
// Fields safe to call from several matcher goroutines at once.
var walkerPool = sync.Pool{New: func() any { return new(walker) }}

// maxRetainedScratch bounds the buffer a pooled walker keeps alive. One
// pathological line with a megabyte of escapes must not permanently pin that
// memory in a daemon that is otherwise measured in single-digit megabytes.
const maxRetainedScratch = 1 << 16

// Fields walks raw once and writes the requested dotted paths into dst.
//
// dst is left holding exactly the paths that were present in raw: any
// pre-existing key is removed, and paths missing from the document are simply
// absent. Values are rendered as their JSON text with strings unquoted and
// unescaped, and numbers, booleans and null verbatim; a path naming an object
// or array yields that container's raw JSON text.
//
// Paths address nested objects with dots (request.remote_ip) and arrays with
// decimal indices (headers.0). Duplicate keys resolve last-one-wins, matching
// encoding/json.
//
// On malformed input dst is emptied and a *SyntaxError is returned. Fields
// never panics, and never allocates in proportion to the input: the only
// allocations are the extracted value strings themselves, and only when a
// value differs from what dst already held.
func Fields(raw []byte, paths []string, dst map[string]string) error {
	if dst == nil {
		return ErrNilDst
	}

	w := walkerPool.Get().(*walker)
	w.reset(raw, paths)
	err := w.document()
	if err != nil {
		clear(dst)
	} else {
		w.commit(dst)
	}
	w.release()
	walkerPool.Put(w)
	return err
}

type walker struct {
	raw []byte
	pos int

	paths []string
	// matched[i] is the number of leading segments of paths[i] that match the
	// container path the scanner is currently inside. A path is "alive" at
	// depth d when matched[i] == d.
	matched []int
	// target[i] is set when matched[i] consumed the path's last segment, i.e.
	// the value being parsed is the one the caller asked for.
	target []bool
	res    []result
	// scratch holds unescaped string values; ranges in res may point into it.
	scratch []byte
}

func (w *walker) reset(raw []byte, paths []string) {
	w.raw = raw
	w.pos = 0
	w.paths = paths
	n := len(paths)
	if cap(w.matched) < n {
		w.matched = make([]int, n)
	}
	if cap(w.target) < n {
		w.target = make([]bool, n)
	}
	if cap(w.res) < n {
		w.res = make([]result, n)
	}
	w.matched = w.matched[:n]
	w.target = w.target[:n]
	w.res = w.res[:n]
	clear(w.matched)
	clear(w.target)
	clear(w.res)
	w.scratch = w.scratch[:0]
}

// release drops references to the caller's data so a pooled walker never pins
// a log line (which may itself be a window into a reader's buffer).
func (w *walker) release() {
	w.raw = nil
	w.paths = nil
	w.matched = w.matched[:0]
	w.target = w.target[:0]
	w.res = w.res[:0]
	if cap(w.scratch) > maxRetainedScratch {
		w.scratch = nil
	}
}

func (w *walker) errAt(msg string) error {
	return &SyntaxError{Offset: w.pos, Msg: msg}
}

// document parses exactly one top-level JSON value. Trailing content is an
// error: a log line carrying two concatenated objects is corrupt, and
// silently accepting the first would hide it.
func (w *walker) document() error {
	w.skipWS()
	if w.pos >= len(w.raw) {
		return w.errAt("unexpected end of input")
	}
	if _, _, _, err := w.parseValue(0); err != nil {
		return err
	}
	w.skipWS()
	if w.pos != len(w.raw) {
		return w.errAt("trailing data after top-level value")
	}
	return nil
}

func (w *walker) skipWS() {
	for w.pos < len(w.raw) {
		switch w.raw[w.pos] {
		case ' ', '\t', '\n', '\r':
			w.pos++
		default:
			return
		}
	}
}

// parseValue parses the value starting at w.pos and reports its extent: for
// strings the bounds of the (still escaped) content between the quotes, for
// everything else the bounds of the literal text. esc reports that the content
// contains backslash escapes and must be decoded before use.
//
// depth is both the container nesting level and the number of path segments
// consumed so far; the two are the same by construction.
func (w *walker) parseValue(depth int) (start, end int, esc bool, err error) {
	if depth > MaxDepth {
		return 0, 0, false, w.errAt("maximum nesting depth exceeded")
	}
	switch c := w.raw[w.pos]; c {
	case '{':
		return w.parseObject(depth)
	case '[':
		return w.parseArray(depth)
	case '"':
		return w.parseString()
	case 't':
		return w.parseLit("true")
	case 'f':
		return w.parseLit("false")
	case 'n':
		return w.parseLit("null")
	default:
		if c == '-' || (c >= '0' && c <= '9') {
			return w.parseNumber()
		}
		return 0, 0, false, w.errAt("invalid character looking for a value")
	}
}

func (w *walker) parseLit(lit string) (int, int, bool, error) {
	if w.pos+len(lit) > len(w.raw) || string(w.raw[w.pos:w.pos+len(lit)]) != lit {
		return 0, 0, false, w.errAt("invalid literal, expected " + lit)
	}
	s := w.pos
	w.pos += len(lit)
	return s, w.pos, false, nil
}

func (w *walker) parseObject(depth int) (int, int, bool, error) {
	start := w.pos
	w.pos++ // '{'
	w.skipWS()
	if w.pos < len(w.raw) && w.raw[w.pos] == '}' {
		w.pos++
		return start, w.pos, false, nil
	}
	for {
		w.skipWS()
		if w.pos >= len(w.raw) || w.raw[w.pos] != '"' {
			return 0, 0, false, w.errAt("expected object key")
		}
		ks, ke, kesc, err := w.parseString()
		if err != nil {
			return 0, 0, false, err
		}
		w.skipWS()
		if w.pos >= len(w.raw) || w.raw[w.pos] != ':' {
			return 0, 0, false, w.errAt("expected ':' after object key")
		}
		w.pos++
		w.skipWS()
		if w.pos >= len(w.raw) {
			return 0, 0, false, w.errAt("unexpected end of input")
		}
		if err := w.member(depth, ks, ke, kesc, -1); err != nil {
			return 0, 0, false, err
		}
		w.skipWS()
		if w.pos >= len(w.raw) {
			return 0, 0, false, w.errAt("unexpected end of input in object")
		}
		switch w.raw[w.pos] {
		case ',':
			w.pos++
		case '}':
			w.pos++
			return start, w.pos, false, nil
		default:
			return 0, 0, false, w.errAt("expected ',' or '}' after object value")
		}
	}
}

func (w *walker) parseArray(depth int) (int, int, bool, error) {
	start := w.pos
	w.pos++ // '['
	w.skipWS()
	if w.pos < len(w.raw) && w.raw[w.pos] == ']' {
		w.pos++
		return start, w.pos, false, nil
	}
	for idx := 0; ; idx++ {
		w.skipWS()
		if w.pos >= len(w.raw) {
			return 0, 0, false, w.errAt("unexpected end of input in array")
		}
		if err := w.member(depth, 0, 0, false, idx); err != nil {
			return 0, 0, false, err
		}
		w.skipWS()
		if w.pos >= len(w.raw) {
			return 0, 0, false, w.errAt("unexpected end of input in array")
		}
		switch w.raw[w.pos] {
		case ',':
			w.pos++
		case ']':
			w.pos++
			return start, w.pos, false, nil
		default:
			return 0, 0, false, w.errAt("expected ',' or ']' after array element")
		}
	}
}

// member parses one object member or array element, updating the per-path
// bookkeeping first. For an object member the key lives in raw[ks:ke] and idx
// is -1; for an array element idx is the element's position. The per-element
// cost is a few integer compares per requested path.
func (w *walker) member(depth, ks, ke int, kesc bool, idx int) error {
	alive := 0
	for i := range w.paths {
		if w.matched[i] != depth {
			continue
		}
		seg, last, ok := segmentAt(w.paths[i], depth)
		if !ok {
			continue
		}
		if idx >= 0 {
			if !indexMatches(seg, idx) {
				continue
			}
		} else if !w.keyMatches(ks, ke, kesc, seg) {
			continue
		}
		w.matched[i] = depth + 1
		w.target[i] = last
		alive++
	}
	if alive == 0 {
		// Nothing below here can be requested: validate and move on.
		return w.skipValue(depth + 1)
	}
	vs, ve, esc, err := w.parseValue(depth + 1)
	if err != nil {
		return err
	}
	w.capture(depth+1, vs, ve, esc)
	// Undo this member's bookkeeping before the next one.
	for i := range w.paths {
		if w.matched[i] > depth {
			w.matched[i] = depth
			w.target[i] = false
		}
	}
	return nil
}

// capture records the value for every path that ended at this depth. The
// unescape work is done at most once even when several paths coincide.
func (w *walker) capture(depth, vs, ve int, esc bool) {
	unescaped := false
	var us, ue int
	for i := range w.paths {
		if w.matched[i] != depth || !w.target[i] {
			continue
		}
		if esc {
			if !unescaped {
				us, ue = w.unescape(vs, ve)
				unescaped = true
			}
			w.res[i] = result{start: us, end: ue, scratch: true, found: true}
			continue
		}
		w.res[i] = result{start: vs, end: ve, found: true}
	}
}

// skipValue validates a subtree without any path bookkeeping. Malformed JSON
// is still an error here: a line we cannot fully parse is a line we cannot
// trust to have given us all of its fields.
func (w *walker) skipValue(depth int) error {
	if depth > MaxDepth {
		return w.errAt("maximum nesting depth exceeded")
	}
	switch c := w.raw[w.pos]; c {
	case '{', '[':
		closing := byte('}')
		if c == '[' {
			closing = ']'
		}
		w.pos++
		w.skipWS()
		if w.pos < len(w.raw) && w.raw[w.pos] == closing {
			w.pos++
			return nil
		}
		for {
			w.skipWS()
			if w.pos >= len(w.raw) {
				return w.errAt("unexpected end of input in container")
			}
			if closing == '}' {
				if w.raw[w.pos] != '"' {
					return w.errAt("expected object key")
				}
				if _, _, _, err := w.parseString(); err != nil {
					return err
				}
				w.skipWS()
				if w.pos >= len(w.raw) || w.raw[w.pos] != ':' {
					return w.errAt("expected ':' after object key")
				}
				w.pos++
				w.skipWS()
			}
			if w.pos >= len(w.raw) {
				return w.errAt("unexpected end of input in container")
			}
			if err := w.skipValue(depth + 1); err != nil {
				return err
			}
			w.skipWS()
			if w.pos >= len(w.raw) {
				return w.errAt("unexpected end of input in container")
			}
			switch w.raw[w.pos] {
			case ',':
				w.pos++
			case closing:
				w.pos++
				return nil
			default:
				return w.errAt("expected ',' or closing bracket")
			}
		}
	case '"':
		_, _, _, err := w.parseString()
		return err
	case 't':
		_, _, _, err := w.parseLit("true")
		return err
	case 'f':
		_, _, _, err := w.parseLit("false")
		return err
	case 'n':
		_, _, _, err := w.parseLit("null")
		return err
	default:
		if c == '-' || (c >= '0' && c <= '9') {
			_, _, _, err := w.parseNumber()
			return err
		}
		return w.errAt("invalid character looking for a value")
	}
}

// parseString consumes a quoted string and returns the bounds of its content,
// excluding the quotes. Control characters are rejected as RFC 8259 requires;
// invalid UTF-8 is passed through unchanged, as encoding/json does.
func (w *walker) parseString() (start, end int, esc bool, err error) {
	w.pos++ // opening quote
	start = w.pos
	for w.pos < len(w.raw) {
		c := w.raw[w.pos]
		switch {
		case c == '"':
			end = w.pos
			w.pos++
			return start, end, esc, nil
		case c == '\\':
			esc = true
			if w.pos+1 >= len(w.raw) {
				return 0, 0, false, w.errAt("unterminated escape sequence")
			}
			switch w.raw[w.pos+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				w.pos += 2
			case 'u':
				if w.pos+6 > len(w.raw) || !isHex4(w.raw[w.pos+2:w.pos+6]) {
					return 0, 0, false, w.errAt("invalid \\u escape")
				}
				w.pos += 6
			default:
				return 0, 0, false, w.errAt("invalid escape character")
			}
		case c < 0x20:
			return 0, 0, false, w.errAt("unescaped control character in string")
		default:
			w.pos++
		}
	}
	return 0, 0, false, w.errAt("unterminated string")
}

func isHex4(b []byte) bool {
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// parseNumber validates the JSON number grammar strictly, so that "01", "1.",
// "+1" and "NaN" are all rejected rather than silently truncated.
func (w *walker) parseNumber() (int, int, bool, error) {
	start := w.pos
	if w.pos < len(w.raw) && w.raw[w.pos] == '-' {
		w.pos++
	}
	n := w.digits()
	if n == 0 {
		return 0, 0, false, w.errAt("invalid number")
	}
	// A leading zero may not be followed by more digits.
	if w.raw[start] == '-' {
		if n > 1 && w.raw[start+1] == '0' {
			return 0, 0, false, w.errAt("invalid number with leading zero")
		}
	} else if n > 1 && w.raw[start] == '0' {
		return 0, 0, false, w.errAt("invalid number with leading zero")
	}
	if w.pos < len(w.raw) && w.raw[w.pos] == '.' {
		w.pos++
		if w.digits() == 0 {
			return 0, 0, false, w.errAt("invalid number, expected digits after '.'")
		}
	}
	if w.pos < len(w.raw) && (w.raw[w.pos] == 'e' || w.raw[w.pos] == 'E') {
		w.pos++
		if w.pos < len(w.raw) && (w.raw[w.pos] == '+' || w.raw[w.pos] == '-') {
			w.pos++
		}
		if w.digits() == 0 {
			return 0, 0, false, w.errAt("invalid number, expected digits in exponent")
		}
	}
	return start, w.pos, false, nil
}

func (w *walker) digits() int {
	n := 0
	for w.pos < len(w.raw) && w.raw[w.pos] >= '0' && w.raw[w.pos] <= '9' {
		w.pos++
		n++
	}
	return n
}

// unescape decodes the string content in raw[s:e] into the scratch buffer and
// returns its bounds there.
func (w *walker) unescape(s, e int) (int, int) {
	start := len(w.scratch)
	for i := s; i < e; {
		c := w.raw[i]
		if c != '\\' {
			w.scratch = append(w.scratch, c)
			i++
			continue
		}
		i++
		switch w.raw[i] {
		case '"', '\\', '/':
			w.scratch = append(w.scratch, w.raw[i])
			i++
		case 'b':
			w.scratch = append(w.scratch, '\b')
			i++
		case 'f':
			w.scratch = append(w.scratch, '\f')
			i++
		case 'n':
			w.scratch = append(w.scratch, '\n')
			i++
		case 'r':
			w.scratch = append(w.scratch, '\r')
			i++
		case 't':
			w.scratch = append(w.scratch, '\t')
			i++
		case 'u':
			r := rune(hex4(w.raw[i+1 : i+5]))
			i += 5
			// A high surrogate is only meaningful paired with the low one
			// that follows it; anything else becomes U+FFFD, as
			// encoding/json does. parseString already guaranteed that any
			// \u here is followed by four hex digits.
			if utf16.IsSurrogate(r) {
				r = utf8.RuneError
				if i+6 <= e && w.raw[i] == '\\' && w.raw[i+1] == 'u' {
					if dec := utf16.DecodeRune(rune(hex4(w.raw[i-4:i])), rune(hex4(w.raw[i+2:i+6]))); dec != utf8.RuneError {
						i += 6
						r = dec
					}
				}
			}
			var buf [4]byte
			n := utf8.EncodeRune(buf[:], r)
			w.scratch = append(w.scratch, buf[:n]...)
		}
	}
	return start, len(w.scratch)
}

func hex4(b []byte) uint32 {
	var v uint32
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint32(c-'a') + 10
		default:
			v |= uint32(c-'A') + 10
		}
	}
	return v
}

// keyMatches compares the object key in raw[ks:ke] with a path segment. The
// comparison is done byte by byte so that no temporary string is created on
// the hot path.
func (w *walker) keyMatches(ks, ke int, kesc bool, seg string) bool {
	if !kesc {
		if ke-ks != len(seg) {
			return false
		}
		for i := 0; i < len(seg); i++ {
			if w.raw[ks+i] != seg[i] {
				return false
			}
		}
		return true
	}
	// Escaped keys are rare; decode into scratch and compare, then roll the
	// scratch buffer back so it only ever holds captured values.
	mark := len(w.scratch)
	s, e := w.unescape(ks, ke)
	eq := string(w.scratch[s:e]) == seg
	w.scratch = w.scratch[:mark]
	return eq
}

// indexMatches reports whether the path segment is the decimal index idx.
// Leading zeros never match, so "headers.01" addresses nothing.
func indexMatches(seg string, idx int) bool {
	if len(seg) == 0 || len(seg) > 9 {
		return false
	}
	if seg[0] == '0' && len(seg) > 1 {
		return false
	}
	n := 0
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n == idx
}

// segmentAt returns the depth'th dot-separated segment of path, whether it is
// the last one, and whether path has that many segments.
func segmentAt(path string, depth int) (seg string, last bool, ok bool) {
	for i := 0; i < depth; i++ {
		j := strings.IndexByte(path, '.')
		if j < 0 {
			return "", false, false
		}
		path = path[j+1:]
	}
	if j := strings.IndexByte(path, '.'); j >= 0 {
		return path[:j], false, true
	}
	return path, true, true
}

// commit publishes the captured values, leaving dst holding exactly the paths
// that were found. Values identical to what dst already held are left alone,
// which keeps steady-state fields (level, msg, host) from allocating on every
// line.
func (w *walker) commit(dst map[string]string) {
	if len(dst) > 0 {
		for k := range dst {
			keep := false
			for i := range w.paths {
				if w.res[i].found && w.paths[i] == k {
					keep = true
					break
				}
			}
			if !keep {
				delete(dst, k)
			}
		}
	}
	for i := range w.paths {
		r := w.res[i]
		if !r.found {
			continue
		}
		var v []byte
		if r.scratch {
			v = w.scratch[r.start:r.end]
		} else {
			v = w.raw[r.start:r.end]
		}
		if old, ok := dst[w.paths[i]]; ok && old == string(v) {
			continue
		}
		dst[w.paths[i]] = string(v)
	}
}
