package rule

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// minLiteralLen is the shortest literal worth scanning for. A single byte
// rejects so few lines that the scan costs more than it saves, and Go's own
// regexp already special-cases a required first byte.
const minLiteralLen = 2

// maxAltLiteralLen bounds the common-substring search over alternation
// branches. Compile time is not hot, but there is no reason to let a
// pathological pattern turn it quadratic in kilobytes.
const maxAltLiteralLen = 64

// requiredLiteral returns a byte string that must appear in every string the
// compiled pattern can match, or "" if no such string can be proven.
//
// This is the load-bearing invariant of the prefilter: "must appear in every
// match". A literal that is merely likely would silently drop attacks, which
// is far worse than a slower matcher, so every case below returns "" unless
// the literal is genuinely required.
func requiredLiteral(pattern string, compiled *regexp.Regexp) string {
	lit := ""
	if tree, err := syntax.Parse(pattern, syntax.Perl); err == nil {
		lit = literalOf(tree.Simplify())
	}
	// LiteralPrefix is a floor, not a ceiling: text that must begin a match
	// must also appear in it. It is usually weaker than the tree walk (it
	// gives up on anchors and alternations), but it costs nothing to take the
	// longer of the two.
	if p, _ := compiled.LiteralPrefix(); len(p) > len(lit) {
		lit = p
	}
	if len(lit) < minLiteralLen {
		return ""
	}
	return lit
}

// literalOf returns the longest literal run the node is guaranteed to emit.
func literalOf(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			// Case-folded text is not a byte substring of the subject.
			return ""
		}
		return string(re.Rune)

	case syntax.OpCapture:
		return literalOf(re.Sub[0])

	case syntax.OpPlus:
		// x+ matches x at least once.
		return literalOf(re.Sub[0])

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalOf(re.Sub[0])
		}
		return ""

	case syntax.OpConcat:
		// Adjacent literal children are contiguous in every match, so they
		// can be glued together; anything that may match empty breaks the run.
		best, cur := "", ""
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && sub.Flags&syntax.FoldCase == 0 {
				cur += string(sub.Rune)
				if len(cur) > len(best) {
					best = cur
				}
				continue
			}
			cur = ""
			if l := literalOf(sub); len(l) > len(best) {
				best = l
			}
		}
		return best

	case syntax.OpAlternate:
		// Every match takes exactly one branch, so only text common to all of
		// them is required.
		subs := make([]string, 0, len(re.Sub))
		for _, sub := range re.Sub {
			l := literalOf(sub)
			if l == "" {
				return ""
			}
			subs = append(subs, l)
		}
		return commonSubstring(subs)

	default:
		// Char classes, ., ?, *, anchors, empty: nothing is guaranteed.
		return ""
	}
}

// commonSubstring returns the longest substring present in every input.
func commonSubstring(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	shortest := ss[0]
	for _, s := range ss[1:] {
		if len(s) < len(shortest) {
			shortest = s
		}
	}
	if len(shortest) > maxAltLiteralLen {
		shortest = shortest[:maxAltLiteralLen]
	}
	best := ""
	for i := 0; i < len(shortest); i++ {
		for j := len(shortest); j > i+len(best); j-- {
			cand := shortest[i:j]
			ok := true
			for _, s := range ss {
				if !strings.Contains(s, cand) {
					ok = false
					break
				}
			}
			if ok {
				best = cand
				break
			}
		}
	}
	return best
}
