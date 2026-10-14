package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// The raw* types mirror the YAML document one-for-one. Every scalar is a
// pointer so that "unset" can be told apart from "explicitly zero": without
// that distinction `threshold: 0` would silently inherit the default of 5
// instead of being rejected.
type rawConfig struct {
	StateDir   *string                `yaml:"state_dir"`
	LogFormat  *string                `yaml:"log_format"`
	AllowLocal *bool                  `yaml:"allow_local"`
	Allowlist  []rawPrefix            `yaml:"allowlist"`
	Metrics    *rawMetrics            `yaml:"metrics"`
	Web        *rawWeb                `yaml:"web"`
	QueueSize  *intVal                `yaml:"queue_size"`
	Defaults   *rawSettings           `yaml:"defaults"`
	Monitors   map[string]*rawMonitor `yaml:"monitors"`
}

type rawMetrics struct {
	Listen *string `yaml:"listen"`
}

// rawWeb is the `web:` block: the optional read-only status page.
type rawWeb struct {
	Enabled   *bool     `yaml:"enabled"`
	Listen    *string   `yaml:"listen"`
	GeoIP     *string   `yaml:"geoip"`
	Retention *duration `yaml:"retention"`
	LogLines  *bool     `yaml:"log_lines"`
}

// rawSettings is the set of knobs valid both under `defaults:` and directly on
// a monitor.
type rawSettings struct {
	Threshold     *intVal    `yaml:"threshold"`
	Window        *duration  `yaml:"window"`
	Bantime       *duration  `yaml:"bantime"`
	BantimeFactor *floatVal  `yaml:"bantime_factor"`
	BantimeMax    *duration  `yaml:"bantime_max"`
	FindHistory   *duration  `yaml:"find_history"`
	MaxTracked    *intVal    `yaml:"max_tracked"`
	StartAt       *string    `yaml:"start_at"`
	OnRepeat      *string    `yaml:"on_repeat"`
	Action        *rawAction `yaml:"action"`
}

// rawMonitor inlines rawSettings rather than nesting it so that a monitor can
// override any default in place, and so that KnownFields still reports a typo
// on a settings key as a typo "in a monitor".
type rawMonitor struct {
	File        *string  `yaml:"file"`
	Listen      *string  `yaml:"listen"`
	Stdin       *bool    `yaml:"stdin"`
	Format      *string  `yaml:"format"`
	StripSyslog *bool    `yaml:"strip_syslog"`
	Match       Patterns `yaml:"match"`
	Ignore      Patterns `yaml:"ignore"`
	IPField     *string  `yaml:"ip_field"`
	Contains    *string  `yaml:"contains"`

	rawSettings `yaml:",inline"`
}

// rawAction is the `action:` value: either a backend name or a block of
// command templates / backend parameters.
type rawAction struct {
	Name        *string   `yaml:"name"`
	Chain       *string   `yaml:"chain"`
	Start       *string   `yaml:"start"`
	Ban         *string   `yaml:"ban"`
	Unban       *string   `yaml:"unban"`
	Stop        *string   `yaml:"stop"`
	Shell       *bool     `yaml:"shell"`
	Timeout     *duration `yaml:"timeout"`
	FlushOnExit *bool     `yaml:"flush_on_exit"`
}

// UnmarshalYAML implements yaml.Unmarshaler for both action shapes.
//
// The mapping case is walked by hand because yaml.v3's KnownFields setting does
// not reach a custom unmarshaler — Node.Decode builds a fresh, lenient decoder —
// and silently swallowing `unbam:` is exactly the footgun this loader promises
// not to have.
func (a *rawAction) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == nullTag {
			return nil
		}
		name := n.Value
		a.Name = &name
		return nil

	case yaml.MappingNode:
		pairs, msgs := mappingPairs(n)
		seen := make(map[string]bool, len(pairs))
		for _, p := range pairs {
			kn, vn := p.key, p.val
			key, ok := scalarText(kn)
			if !ok {
				msgs = append(msgs, msgAt(kn, "action keys must be names, got %s", describeNode(kn)))
				continue
			}
			if seen[key] {
				msgs = append(msgs, msgAt(kn, "key %q appears twice in the same action", key))
				continue
			}
			seen[key] = true

			switch key {
			case "name":
				msgs = appendString(msgs, &a.Name, key, vn)
			case "chain":
				msgs = appendString(msgs, &a.Chain, key, vn)
			case "start":
				msgs = appendString(msgs, &a.Start, key, vn)
			case "ban":
				msgs = appendString(msgs, &a.Ban, key, vn)
			case "unban":
				msgs = appendString(msgs, &a.Unban, key, vn)
			case "stop":
				msgs = appendString(msgs, &a.Stop, key, vn)
			case "shell":
				b, err := scalarBool(vn)
				if err != nil {
					msgs = append(msgs, msgAt(vn, "action shell: %s", err))
					continue
				}
				a.Shell = &b
			case "timeout":
				var d duration
				if err := d.UnmarshalYAML(vn); err != nil {
					msgs = append(msgs, typeErrorMessages(err)...)
					continue
				}
				a.Timeout = &d
			case "flush_on_exit":
				b, err := scalarBool(vn)
				if err != nil {
					msgs = append(msgs, msgAt(vn, "action flush_on_exit: %s", err))
					continue
				}
				a.FlushOnExit = &b
			default:
				// Every other key in the block was still stored, so the
				// monitor around it is worth validating.
				msgs = append(msgs, keptValues(unknownKeyMsg(kn.Line, key, "an action", actionKeys())))
			}
		}
		return nodeErrs(msgs...)

	default:
		return nodeErrs(msgAt(n, "action must be a backend name (iptables, ipset, nft, dryrun) or a map of command templates, got %s", describeNode(n)))
	}
}

// appendString stores a scalar string field, recording a problem instead when
// the value has the wrong shape.
func appendString(msgs []string, dst **string, key string, vn *yaml.Node) []string {
	s, ok := scalarText(vn)
	if !ok {
		return append(msgs, msgAt(vn, "action %s must be a string, got %s", key, describeNode(vn)))
	}
	*dst = &s
	return msgs
}

func scalarBool(n *yaml.Node) (bool, error) {
	s, ok := scalarText(n)
	if !ok {
		return false, fmt.Errorf("expected true or false, got %s", describeNode(n))
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("expected true or false, got %q", s)
	}
	return b, nil
}

// typeErrorMessages unwraps the message list from an error produced by one of
// this package's unmarshalers.
func typeErrorMessages(err error) []string {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return te.Errors
	}
	return []string{err.Error()}
}

// parseProblem is one decode-time problem, tagged where it is created with
// whether the surrounding block still has its values.
//
// The tag cannot be recovered afterwards: by the time parse sees a problem it
// is a sentence, and deciding "was this only a typo?" by reading that sentence
// turns a reworded message into a silently weaker check.
type parseProblem struct {
	err error
	// valuesLost says the block this problem came from is missing a value, so
	// validating it would invent problems on top of the real one. An unknown
	// key is the counter-example: yaml notes it and every other value in the
	// block decodes fine, so that block must still be validated.
	valuesLost bool
}

// decode parses src strictly and returns the raw document plus every problem
// found, already rewritten into human phrasing.
//
// A syntax error (as opposed to a schema error) yields a nil document: nothing
// downstream can be trusted after the parser has lost its place.
func decode(src []byte) (*rawConfig, []parseProblem) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)

	err := dec.Decode(&raw)
	switch {
	case errors.Is(err, io.EOF):
		// An empty file is syntactically fine; validation will object that it
		// declares no monitors.
		return &raw, nil
	case err == nil:
		return &raw, extraDocument(dec)
	}

	var te *yaml.TypeError
	if errors.As(err, &te) {
		out := make([]parseProblem, 0, len(te.Errors)+1)
		for _, m := range te.Errors {
			text, valuesLost := humanize(m)
			out = append(out, parseProblem{err: errors.New(text), valuesLost: valuesLost})
		}
		// A schema error in the first document is no reason to stop looking
		// for a second one: a stray "---" silently deletes everything below
		// it, which is the worse of the two problems, and the user would
		// otherwise only hear about it on the next round-trip.
		return &raw, append(out, extraDocument(dec)...)
	}
	return nil, []parseProblem{{err: syntaxError(src, err), valuesLost: true}}
}

// extraDocument reports anything after the first YAML document.
//
// The decoder simply ignores it, which is worse than an error: the user's
// edits would appear to do nothing. A second document that does not even parse
// must be reported too — otherwise a typo below a stray "---" deletes half the
// config in silence. Neither costs the first document a value, so neither
// suppresses its validation.
func extraDocument(dec *yaml.Decoder) []parseProblem {
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return []parseProblem{{err: fmt.Errorf("line %d: the file contains more than one YAML document (a stray %q?); only the first would be used", extra.Line, "---")}}
	case !errors.Is(err, io.EOF):
		return []parseProblem{{err: fmt.Errorf("there is a second YAML document (a stray %q?) and it does not parse: %w", "---", err)}}
	}
	return nil
}

// tabbedLine reports the first line indented with a tab, which YAML forbids.
// yaml.v3 calls it "found character that cannot start any token", which sends
// people hunting for an invisible gremlin.
func tabbedLine(src []byte) (int, bool) {
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "\t") {
			return i + 1, true
		}
	}
	return 0, false
}

// syntaxError turns a parser-level failure into the clearest message available.
func syntaxError(src []byte, err error) error {
	if strings.Contains(err.Error(), "cannot start any token") {
		if line, ok := tabbedLine(src); ok {
			return fmt.Errorf("line %d: YAML does not allow tabs for indentation; use spaces", line)
		}
	}
	return fmt.Errorf("invalid YAML: %w", err)
}

// yaml.v3's unknown-key message, e.g.
// `line 41: field treshold not found in type config.rawMonitor`.
var fieldNotFoundRe = regexp.MustCompile(`^line (\d+): field (.+) not found in type (\S+)$`)

// yaml.v3's type-mismatch message, e.g.
// "line 3: cannot unmarshal !!str `hello` into config.rawMonitor". The quoted
// value is absent for collections and truncated for long scalars.
var cannotUnmarshalRe = regexp.MustCompile("^line (\\d+): cannot unmarshal (!![a-z]+)(?: `(.*)`)? into (.+)$")

// yaml.v3's duplicate-key message, e.g.
// `line 5: mapping key "sshd" already defined at line 3`. uniqueKeys is always
// on in yaml.v3, so this is not an option this package could turn off.
var duplicateKeyRe = regexp.MustCompile(`^line (\d+): mapping key "(.*)" already defined at line (\d+)$`)

// humanize rewrites one yaml.v3 message into something actionable and reports
// whether the problem cost the block a value. Messages it does not recognise
// are passed through unchanged rather than mangled, and assumed destructive:
// inventing extra problems is a smaller sin than hiding a real one behind a
// message nobody has read yet.
func humanize(msg string) (text string, valuesLost bool) {
	if text, ok := strings.CutPrefix(msg, keptValuesMark); ok {
		// One of this package's own unmarshalers phrased this one and marked
		// it as costing nothing.
		return text, false
	}
	if m := fieldNotFoundRe.FindStringSubmatch(msg); m != nil {
		line, err := strconv.Atoi(m[1])
		if err != nil {
			return msg, true
		}
		key, typeName := m[2], m[3]
		label, ok := typeLabels[typeName]
		if !ok {
			return msg, true
		}
		// yaml records the unknown key and decodes the rest of the block, so
		// every other value in it is good.
		return unknownKeyMsg(line, key, label, keysFor(typeName)), false
	}
	if m := cannotUnmarshalRe.FindStringSubmatch(msg); m != nil {
		return wrongShapeMsg(m[1], m[2], m[3], m[4], msg), true
	}
	if m := duplicateKeyRe.FindStringSubmatch(msg); m != nil {
		return duplicateKeyMsg(m[1], m[2], m[3], msg), true
	}
	return msg, true
}

// duplicateKeyMsg explains a repeated key without the "mapping key" jargon,
// and warns about the collateral damage: yaml.v3 abandons the whole block
// rather than pick a winner, so everything in it goes missing.
func duplicateKeyMsg(lineText, key, firstText, fallback string) string {
	line, err := strconv.Atoi(lineText)
	if err != nil {
		return fallback
	}
	first, err := strconv.Atoi(firstText)
	if err != nil {
		return fallback
	}
	return fmt.Sprintf("line %d: key %q is already set at line %d; remove one of them (while it is ambiguous the whole block is dropped)", line, key, first)
}

// goTypeShapes translates the Go types yaml names in its messages back into
// config vocabulary; leaking "config.rawMonitor" at a user is a bug.
var goTypeShapes = map[string]string{
	"string":          "a string",
	"int":             "a whole number",
	"config.intVal":   "a whole number",
	"float64":         "a number",
	"config.floatVal": "a number",
	"bool":            "a true/false",
}

// wrongShapeMsg explains a type mismatch in terms of blocks and indentation,
// which is what actually went wrong nine times out of ten.
func wrongShapeMsg(lineText, tag, value, goType, fallback string) string {
	line, err := strconv.Atoi(lineText)
	if err != nil {
		return fallback
	}
	got, ok := tagShapes[tag]
	if !ok {
		return fallback
	}
	if value != "" {
		got += fmt.Sprintf(" (%s)", value)
	}
	if goType == monitorsMapType {
		return fmt.Sprintf("line %d: monitors must be a block of named monitors, got %s", line, got)
	}
	if label, ok := typeLabels[goType]; ok {
		return fmt.Sprintf("line %d: %s must be a block of indented keys, got %s", line, label, got)
	}
	if want, ok := goTypeShapes[goType]; ok {
		return fmt.Sprintf("line %d: expected %s, got %s", line, want, got)
	}
	return fallback
}

// monitorsMapType is how yaml names the monitors map in its messages.
const monitorsMapType = "map[string]*config.rawMonitor"

// unknownKeyMsg is the single phrasing for "you typed a key I do not know",
// wherever it is detected.
func unknownKeyMsg(line int, key, label string, valid []string) string {
	if s := suggest(key, valid); s != "" {
		return fmt.Sprintf("line %d: unknown key %q in %s (did you mean %q?)", line, key, label, s)
	}
	return fmt.Sprintf("line %d: unknown key %q in %s; valid keys are %s", line, key, label, strings.Join(quoteAll(valid), ", "))
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}

// typeLabels names each raw type the way the config file spells it.
var typeLabels = map[string]string{
	"config.rawConfig":   "the top level",
	"config.rawSettings": "defaults",
	"config.rawMonitor":  "a monitor",
	"config.rawMetrics":  "metrics",
	"config.rawWeb":      "web",
	"config.rawAction":   "an action",
}

// keyIndex is built once from the struct tags themselves, so the suggestions
// cannot drift away from what the parser actually accepts.
var keyIndex = sync.OnceValue(func() map[string][]string {
	types := []reflect.Type{
		reflect.TypeFor[rawConfig](),
		reflect.TypeFor[rawSettings](),
		reflect.TypeFor[rawMonitor](),
		reflect.TypeFor[rawMetrics](),
		reflect.TypeFor[rawWeb](),
		reflect.TypeFor[rawAction](),
	}
	m := make(map[string][]string, len(types))
	for _, t := range types {
		m[t.String()] = structKeys(t)
	}
	return m
})

func keysFor(typeName string) []string { return keyIndex()[typeName] }

func actionKeys() []string { return keysFor("config.rawAction") }

// structKeys lists the YAML keys a struct accepts, following ",inline".
func structKeys(t reflect.Type) []string {
	var keys []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if slices.Contains(strings.Split(opts, ","), "inline") {
			keys = append(keys, structKeys(f.Type)...)
			continue
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		keys = append(keys, name)
	}
	slices.Sort(keys)
	return keys
}

// suggest returns the closest valid key, or "" when nothing is close enough to
// be worth guessing. The budget grows with the key's length so that short keys
// ("ban") do not get wild suggestions while long ones ("bantime_factor") still
// tolerate a couple of slips.
func suggest(key string, valid []string) string {
	budget := min(1+len(key)/4, 3)
	best, bestDist := "", budget+1
	for _, v := range valid {
		d := levenshtein(key, v)
		if d < bestDist {
			best, bestDist = v, d
		}
	}
	if bestDist > budget {
		return ""
	}
	return best
}

// levenshtein is the plain two-row edit distance; key lists are tiny, so the
// naive version is the right one.
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}
