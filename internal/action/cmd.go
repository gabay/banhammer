package action

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"banhammer/internal/model"
)

// maxMatchedLen caps the {matched} substitution. The value is the operator's
// own rule pattern (rule.Result.Pattern), not log text, so it is trusted — but
// a pathologically long pattern would still push the child's argv towards
// ARG_MAX and turn every ban into a failure, and the cap costs nothing.
const maxMatchedLen = 256

// cmdBackend runs operator-supplied command templates.
type cmdBackend struct {
	base
	chain string
	shell bool
	// Pre-tokenised templates: a syntax error in a template is caught at
	// construction, not at 3 a.m. on the first ban.
	start, ban, unban, stop []string
}

func newCmd(b base, spec Spec) (*cmdBackend, error) {
	chain := spec.Chain
	if chain == "" {
		chain = DefaultChain
	}
	c := &cmdBackend{base: b, chain: chain, shell: spec.Shell}
	if strings.TrimSpace(spec.Ban) == "" || strings.TrimSpace(spec.Unban) == "" {
		return nil, errors.New("action: cmd backend requires both ban and unban templates")
	}
	for _, f := range []struct {
		name string
		src  string
		dst  *[]string
	}{
		{"start", spec.Start, &c.start},
		{"ban", spec.Ban, &c.ban},
		{"unban", spec.Unban, &c.unban},
		{"stop", spec.Stop, &c.stop},
	} {
		if strings.TrimSpace(f.src) == "" {
			continue
		}
		if c.shell {
			// In shell mode the template is one string for sh to parse; we do
			// not tokenise it, precisely because the user asked for sh's
			// grammar (pipes, ';', redirection) instead of ours.
			*f.dst = []string{f.src}
			continue
		}
		toks, err := tokenize(f.src)
		if err != nil {
			return nil, fmt.Errorf("action: %s template: %w", f.name, err)
		}
		if len(toks) == 0 {
			return nil, fmt.Errorf("action: %s template is empty after tokenising", f.name)
		}
		*f.dst = toks
	}
	if c.shell {
		b.log.Warn("cmd action uses shell: true; log-derived values are not escaped")
	}
	return c, nil
}

func (*cmdBackend) Name() string { return "cmd" }

func (c *cmdBackend) Start(ctx context.Context) error {
	return c.runTemplate(ctx, "start", c.start, model.Ban{})
}

func (c *cmdBackend) Ban(ctx context.Context, b model.Ban) error {
	return c.runTemplate(ctx, "ban", c.ban, b)
}

func (c *cmdBackend) Unban(ctx context.Context, b model.Ban) error {
	return c.runTemplate(ctx, "unban", c.unban, b)
}

func (c *cmdBackend) Stop(ctx context.Context) error {
	return c.runTemplate(ctx, "stop", c.stop, model.Ban{})
}

func (c *cmdBackend) runTemplate(ctx context.Context, name string, toks []string, b model.Ban) error {
	if len(toks) == 0 {
		return nil // optional template, nothing configured
	}
	argv := render(toks, varsFor(b, c.chain))
	if _, err := c.exec(ctx, c.shell, argv...); err != nil {
		return fmt.Errorf("cmd %s template: %w", name, err)
	}
	return nil
}

// vars holds the template substitutions for one operation.
type vars struct {
	ip, monitor, count, bantime, family, matched, chain string
}

func varsFor(b model.Ban, chain string) vars {
	v := vars{
		monitor: b.Monitor,
		count:   strconv.Itoa(b.Count),
		bantime: banDuration(b).String(),
		family:  b.Family().String(),
		// Ban.Matched is the rule pattern that fired, written by the operator
		// in the config. It is empty for manual bans, which renders as an empty
		// argument — the template's argv shape never changes.
		matched: truncate(b.Matched, maxMatchedLen),
		chain:   chain,
	}
	// {ip} is rendered from the parsed address, never from log text, so it can
	// only ever be a valid IP literal.
	if b.IP.IsValid() {
		v.ip = b.IP.Unmap().String()
	}
	return v
}

func (v vars) lookup(name string) (string, bool) {
	switch name {
	case "ip":
		return v.ip, true
	case "monitor":
		return v.monitor, true
	case "count":
		return v.count, true
	case "bantime":
		return v.bantime, true
	case "family":
		return v.family, true
	case "matched":
		return v.matched, true
	case "chain":
		return v.chain, true
	}
	return "", false
}

// render substitutes variables into already-tokenised argv elements.
//
// Substitution happens *after* tokenisation, which is the whole trick: a value
// containing spaces, quotes, semicolons or newlines lands inside one argv
// element and cannot become a second argument, let alone a second command.
// Unknown {placeholders} are left verbatim — nft and friends use braces.
func render(toks []string, v vars) []string {
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = substitute(t, v)
	}
	return out
}

func substitute(s string, v vars) string {
	if !strings.ContainsRune(s, '{') {
		return sanitize(s)
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '{' {
			sb.WriteByte(s[i])
			i++
			continue
		}
		// Only a well-formed, known {name} is a variable. Anything else is a
		// literal brace — nft templates are full of them — and we must keep
		// scanning inside it so "{ {ip} }" still renders the address.
		if end := strings.IndexByte(s[i:], '}'); end > 0 {
			if val, ok := v.lookup(s[i+1 : i+end]); ok {
				sb.WriteString(sanitize(val))
				i += end + 1
				continue
			}
		}
		sb.WriteByte('{')
		i++
	}
	return sb.String()
}

// sanitize strips NUL bytes. execve rejects an argument containing NUL, so
// leaving one in would turn a crafted log line into a permanent action
// failure; dropping the byte keeps the rest of the value visible.
func sanitize(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary so we never emit invalid UTF-8 into a log or argv.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// tokenize splits a command template the way a shell would split words, and
// nothing more: no expansion, no globbing, no substitution, no operators.
//
//   - whitespace separates tokens
//   - '...' is literal
//   - "..." is literal except for \" and \\
//   - a backslash outside quotes escapes the next byte
//
// An unterminated quote or a trailing backslash is a configuration error,
// reported at startup rather than silently swallowing half a command.
func tokenize(s string) ([]string, error) {
	var (
		toks    []string
		cur     strings.Builder
		started bool
	)
	flush := func() {
		if started {
			toks = append(toks, cur.String())
			cur.Reset()
			started = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
		case '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing backslash")
			}
			i++
			cur.WriteByte(s[i])
			started = true
		case '\'':
			started = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case '"':
			started = true
			closed := false
			for i++; i < len(s); i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					i++
					cur.WriteByte(s[i])
					continue
				}
				if s[i] == '"' {
					closed = true
					break
				}
				cur.WriteByte(s[i])
			}
			if !closed {
				return nil, errors.New("unterminated double quote")
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	flush()
	return toks, nil
}
