// Package rule compiles a monitor's match/ignore configuration into the
// matcher that runs on every log line.
//
// The hot path is "line does not match", by many orders of magnitude, so the
// design is built around rejecting lines cheaply: a required literal is
// derived from each pattern at compile time and checked with bytes.Contains
// before the regex engine is ever asked. Correctness beats speed at every
// turn — a literal is only used when it provably appears in every match.
//
// # The <IP> macro
//
// <IP> (and <HOST>, which also accepts DNS names) expands to a named capture
// group matching IPv4 dotted-quad and IPv6 in every RFC 3986 form: full,
// compressed, v4-embedded and v4-mapped. Brackets are not part of the group,
// so "[2001:db8::1]:443" yields 2001:db8::1 and leaves the port alone.
//
// It deliberately does not yield an address for:
//
//   - leading-zero octets ("010.1.1.1"), which different resolvers read as
//     different hosts;
//   - anything whose neighbouring bytes could have continued the address, so
//     "999.1.1.1", "1.2.3.4.5" and "1:2:3:4:5:6:7:8:9" are refused rather
//     than truncated to something that parses;
//   - zone-scoped addresses ("fe80::1%eth0"), which are not a stable identity;
//   - the unspecified addresses "::" and "0.0.0.0", which are never a real
//     offender and are usually the debris of a truncated match.
//
// Those refusals report OutcomeNoIP rather than a wrong ban. RE2 has no
// lookaround, so they are enforced by inspecting the bytes around the capture
// after the match; see boundaryOK.
//
// A macro inside a character class is a compile error rather than a silently
// wrong regex: Go reads [<IP>] as the class of '<', 'I', 'P' and '>', so
// splicing a group in there would change the meaning of the pattern without
// failing. Write \x3c to match a literal '<'.
package rule

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"

	"banhammer/internal/decode"
)

// Spec is the compiled form of a monitor's matching configuration. It mirrors
// the config package's Monitor without depending on it.
type Spec struct {
	Format string // text|json; empty means text unless a JSON-only field is set

	Line   []string          // whole-line patterns, OR
	Fields map[string]string // JSON field -> pattern, AND

	IgnoreLine   []string
	IgnoreFields map[string]string

	IPField  string // JSON dotted path holding the offender's address
	Contains string // literal prefilter override, checked against the raw line
}

// Outcome is the verdict for one line.
type Outcome int

const (
	// OutcomeNoMatch is the overwhelmingly common case: nothing fired.
	OutcomeNoMatch Outcome = iota
	// OutcomeMatch means a match rule fired and an IP was extracted.
	OutcomeMatch
	// OutcomeIgnored means a match fired but an ignore rule vetoed it.
	OutcomeIgnored
	// OutcomeDecodeError means the line is not the JSON the monitor expects.
	OutcomeDecodeError
	// OutcomeNoIP means a match fired but no usable address came out of it,
	// e.g. <HOST> matched a DNS name, or the field held a zone-scoped address.
	OutcomeNoIP
)

// String renders the outcome as the snake_case token used in logs and
// metrics labels.
func (o Outcome) String() string {
	switch o {
	case OutcomeNoMatch:
		return "no_match"
	case OutcomeMatch:
		return "match"
	case OutcomeIgnored:
		return "ignored"
	case OutcomeDecodeError:
		return "decode_error"
	case OutcomeNoIP:
		return "no_ip"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// Result carries what the pipeline needs from a hit: the offender and the rule
// that caught them (surfaced to actions as {matched}).
type Result struct {
	IP      netip.Addr
	Pattern string
}

// pattern is one compiled regex plus everything Match needs to avoid work.
type pattern struct {
	src   string         // as the user wrote it, for Result.Pattern
	field string         // JSON field this applies to; "" means the raw line
	re    *regexp.Regexp //
	lit   string         // literal required by every match; "" if none
	litB  []byte         // lit as bytes, to keep Match conversion-free
	ipIdx int            // submatch index of the ip group, -1 if absent
	macro bool           // ip group came from <IP>/<HOST>: boundary-check it
}

// Set is a monitor's compiled rules. It is safe for concurrent use: the only
// mutable state is a pool of scratch maps for JSON decoding.
type Set struct {
	json bool

	line   []pattern
	fields []pattern // AND semantics; every entry must match
	// fieldsDesc names the AND rule as a whole, precomputed so that reporting
	// a hit never allocates.
	fieldsDesc string

	ignoreLine   []pattern
	ignoreFields []pattern

	ipField  string
	contains []byte

	// paths is the union of every JSON path the set needs, handed to
	// decode.Fields so the line is walked exactly once.
	paths []string

	// patternHasIP records whether the match patterns can produce an address
	// on their own; see NeedsIPField.
	patternHasIP bool

	pool sync.Pool
}

// Compile turns a Spec into a Set.
//
// <IP> and <HOST> macros are expanded before compilation. A pattern may
// instead carry its own (?P<ip>...) group; having two IP groups in one pattern
// is an error, as is combining an IP group in a match pattern with IPField,
// since then it is ambiguous which one identifies the offender. Ignore
// patterns may use <IP> freely — theirs is never used for extraction.
func Compile(s Spec) (*Set, error) { return compile(s, true) }

// compile is Compile with the prefilter switchable, so tests can prove that
// prefiltering never changes a verdict.
func compile(s Spec, usePrefilter bool) (*Set, error) {
	set := &Set{ipField: s.IPField}

	switch s.Format {
	case "json":
		set.json = true
	case "text":
	case "":
		// Be forgiving about an unset format when the spec is unambiguously
		// about JSON; config validates the user-facing rule.
		set.json = len(s.Fields) > 0 || len(s.IgnoreFields) > 0 || s.IPField != ""
	default:
		return nil, fmt.Errorf("rule: unknown format %q", s.Format)
	}
	if !set.json {
		switch {
		case len(s.Fields) > 0 || len(s.IgnoreFields) > 0:
			return nil, fmt.Errorf("rule: field patterns require format: json")
		case s.IPField != "":
			return nil, fmt.Errorf("rule: ip_field requires format: json")
		}
	}

	var err error
	if set.line, err = compilePatterns("", s.Line, usePrefilter); err != nil {
		return nil, err
	}
	if set.fields, err = compileFieldPatterns(s.Fields, usePrefilter); err != nil {
		return nil, err
	}
	if set.ignoreLine, err = compilePatterns("", s.IgnoreLine, usePrefilter); err != nil {
		return nil, fmt.Errorf("ignore: %w", err)
	}
	if set.ignoreFields, err = compileFieldPatterns(s.IgnoreFields, usePrefilter); err != nil {
		return nil, fmt.Errorf("ignore: %w", err)
	}

	for _, group := range [][]pattern{set.line, set.fields} {
		for i := range group {
			if group[i].ipIdx >= 0 {
				set.patternHasIP = true
			}
		}
	}
	if set.patternHasIP && s.IPField != "" {
		return nil, fmt.Errorf("rule: ip_field %q conflicts with an <IP> group in a match pattern; use one or the other", s.IPField)
	}

	set.fieldsDesc = describeFields(s.Fields)
	if usePrefilter && s.Contains != "" {
		set.contains = []byte(s.Contains)
	}

	if set.json {
		set.paths = unionPaths(s.Fields, s.IgnoreFields, s.IPField)
	}
	set.pool.New = func() any {
		return &state{fields: make(map[string]string, len(set.paths))}
	}
	return set, nil
}

func compilePatterns(field string, srcs []string, usePrefilter bool) ([]pattern, error) {
	if len(srcs) == 0 {
		return nil, nil
	}
	out := make([]pattern, 0, len(srcs))
	for _, src := range srcs {
		p, err := compilePattern(field, src, usePrefilter)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// compileFieldPatterns keeps a stable order so that a failure always reports
// the same field first and benchmarks are reproducible.
func compileFieldPatterns(m map[string]string, usePrefilter bool) ([]pattern, error) {
	if len(m) == 0 {
		return nil, nil
	}
	fields := make([]string, 0, len(m))
	for f := range m {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	out := make([]pattern, 0, len(fields))
	for _, f := range fields {
		if f == "" {
			return nil, fmt.Errorf("rule: empty field name in a field pattern map")
		}
		p, err := compilePattern(f, m[f], usePrefilter)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func compilePattern(field, src string, usePrefilter bool) (pattern, error) {
	where := "pattern"
	if field != "" {
		where = "field " + field
	}
	expanded, macros, err := expandMacros(src)
	if err != nil {
		return pattern{}, fmt.Errorf("rule: %s %q: %w", where, src, err)
	}
	re, err := regexp.Compile(expanded)
	if err != nil {
		return pattern{}, fmt.Errorf("rule: %s %q: %w", where, src, err)
	}

	n := 0
	for _, name := range re.SubexpNames() {
		if name == ipGroup {
			n++
		}
	}
	if n > 1 {
		return pattern{}, fmt.Errorf("rule: %s %q: %d %q capture groups, expected at most one", where, src, n, ipGroup)
	}

	p := pattern{src: src, field: field, re: re, ipIdx: -1, macro: macros > 0}
	if n == 1 {
		p.ipIdx = re.SubexpIndex(ipGroup)
	}
	if usePrefilter {
		p.lit = requiredLiteral(expanded, re)
		if p.lit != "" {
			p.litB = []byte(p.lit)
		}
	}
	return p, nil
}

// describeFields renders an AND rule for Result.Pattern. Precomputed because
// it would otherwise allocate on every hit.
func describeFields(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	fields := make([]string, 0, len(m))
	for f := range m {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f+"="+m[f])
	}
	return strings.Join(parts, " && ")
}

// unionPaths collects every JSON path the set needs, so decode.Fields walks
// the line once for match, ignore and ip_field together.
func unionPaths(fields, ignoreFields map[string]string, ipField string) []string {
	seen := make(map[string]struct{}, len(fields)+len(ignoreFields)+1)
	add := func(p string) {
		if p != "" {
			seen[p] = struct{}{}
		}
	}
	for f := range fields {
		add(f)
	}
	for f := range ignoreFields {
		add(f)
	}
	add(ipField)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// state is the per-line scratch space for JSON mode.
type state struct {
	fields map[string]string
}

// NeedsIPField reports whether the match patterns cannot produce an address by
// themselves, so the monitor must name an IPField. Config uses this to reject
// a monitor that could never identify an offender.
func (s *Set) NeedsIPField() bool { return !s.patternHasIP }

// Match applies the rules to one raw line.
//
// It is safe to call from multiple goroutines. raw is only read, never
// retained. Ignore rules are evaluated after a match fires and take precedence
// over IP extraction, so a line the operator asked to ignore never shows up as
// a warning about a missing address.
func (s *Set) Match(raw []byte) (Result, Outcome) {
	if len(s.contains) > 0 && !bytes.Contains(raw, s.contains) {
		return Result{}, OutcomeNoMatch
	}
	if s.json {
		return s.matchJSON(raw)
	}
	return s.matchText(raw)
}

func (s *Set) matchText(raw []byte) (Result, Outcome) {
	for i := range s.line {
		p := &s.line[i]
		ip, hit, ok := p.matchBytes(raw)
		if !hit {
			continue
		}
		if s.ignoredText(raw) {
			return Result{Pattern: p.src}, OutcomeIgnored
		}
		if !ok {
			return Result{Pattern: p.src}, OutcomeNoIP
		}
		return Result{IP: ip, Pattern: p.src}, OutcomeMatch
	}
	return Result{}, OutcomeNoMatch
}

func (s *Set) matchJSON(raw []byte) (Result, Outcome) {
	var st *state
	if len(s.paths) > 0 {
		st = s.pool.Get().(*state)
		if err := decode.Fields(raw, s.paths, st.fields); err != nil {
			s.pool.Put(st)
			return Result{}, OutcomeDecodeError
		}
	}

	var (
		res   Result
		hit   bool
		ip    netip.Addr
		haveP bool // an IP came out of the matching pattern
	)

	// AND over the field patterns first: it is the JSON-native form, and its
	// per-field prefilters usually reject in a few bytes.
	if len(s.fields) > 0 {
		if pip, ok, pok := s.matchFieldSet(st.fields, s.fields); ok {
			hit, res.Pattern = true, s.fieldsDesc
			ip, haveP = pip, pok
		}
	}
	if !hit {
		for i := range s.line {
			p := &s.line[i]
			pip, phit, pok := p.matchBytes(raw)
			if !phit {
				continue
			}
			hit, res.Pattern = true, p.src
			ip, haveP = pip, pok
			break
		}
	}
	if !hit {
		if st != nil {
			s.pool.Put(st)
		}
		return Result{}, OutcomeNoMatch
	}

	ignored := s.ignoredText(raw)
	if !ignored && len(s.ignoreFields) > 0 && st != nil {
		_, ignored, _ = s.matchFieldSet(st.fields, s.ignoreFields)
	}

	// The IPField value is read before the scratch map goes back to the pool.
	if !ignored && s.ipField != "" && st != nil {
		if v, ok := st.fields[s.ipField]; ok {
			ip, haveP = parseIP(v)
		} else {
			haveP = false
		}
	}
	if st != nil {
		s.pool.Put(st)
	}

	switch {
	case ignored:
		return Result{Pattern: res.Pattern}, OutcomeIgnored
	case !haveP:
		return Result{Pattern: res.Pattern}, OutcomeNoIP
	default:
		res.IP = ip
		return res, OutcomeMatch
	}
}

// matchFieldSet applies an AND set of field patterns to the decoded fields.
// It reports the address extracted from whichever pattern carried an ip group.
func (s *Set) matchFieldSet(decoded map[string]string, set []pattern) (netip.Addr, bool, bool) {
	var (
		ip    netip.Addr
		haveP bool
	)
	for i := range set {
		p := &set[i]
		v, ok := decoded[p.field]
		if !ok {
			return netip.Addr{}, false, false
		}
		pip, hit, pok := p.matchString(v)
		if !hit {
			return netip.Addr{}, false, false
		}
		if pok && !haveP {
			ip, haveP = pip, true
		}
	}
	return ip, true, haveP
}

func (s *Set) ignoredText(raw []byte) bool {
	for i := range s.ignoreLine {
		if _, hit, _ := s.ignoreLine[i].matchBytes(raw); hit {
			return true
		}
	}
	return false
}

// matchBytes reports whether the pattern hits raw and, if it carries an ip
// group, the address it extracted. The two booleans are (matched, gotIP):
// a match with an unparseable address is still a match.
func (p *pattern) matchBytes(raw []byte) (netip.Addr, bool, bool) {
	if p.litB != nil && !bytes.Contains(raw, p.litB) {
		return netip.Addr{}, false, false
	}
	if p.ipIdx < 0 {
		// No capture needed: Match avoids allocating a submatch slice.
		return netip.Addr{}, p.re.Match(raw), false
	}
	loc := p.re.FindSubmatchIndex(raw)
	if loc == nil {
		return netip.Addr{}, false, false
	}
	s, e := loc[2*p.ipIdx], loc[2*p.ipIdx+1]
	if s < 0 {
		return netip.Addr{}, true, false
	}
	text := raw[s:e]
	if p.macro && !boundaryOK(raw, s, e, bytes.IndexByte(text, ':') >= 0) {
		return netip.Addr{}, true, false
	}
	ip, ok := parseIP(string(text))
	return ip, true, ok
}

// matchString is matchBytes for an already-decoded JSON field value.
func (p *pattern) matchString(v string) (netip.Addr, bool, bool) {
	if p.lit != "" && !strings.Contains(v, p.lit) {
		return netip.Addr{}, false, false
	}
	if p.ipIdx < 0 {
		return netip.Addr{}, p.re.MatchString(v), false
	}
	loc := p.re.FindStringSubmatchIndex(v)
	if loc == nil {
		return netip.Addr{}, false, false
	}
	s, e := loc[2*p.ipIdx], loc[2*p.ipIdx+1]
	if s < 0 {
		return netip.Addr{}, true, false
	}
	text := v[s:e]
	if p.macro && !boundaryOK(v, s, e, strings.IndexByte(text, ':') >= 0) {
		return netip.Addr{}, true, false
	}
	ip, ok := parseIP(text)
	return ip, true, ok
}
