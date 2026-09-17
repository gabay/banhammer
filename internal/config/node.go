package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// The resolved YAML tags this package reasons about. nullTag is the one that
// carries meaning of its own: an empty scalar ("key:" with no value) is
// "unset", not "".
const (
	nullTag  = "!!null"
	strTag   = "!!str"
	intTag   = "!!int"
	floatTag = "!!float"
	boolTag  = "!!bool"
	seqTag   = "!!seq"
	mapTag   = "!!map"
)

// tagShapes translates a YAML tag into the words this package's diagnostics
// use. describeNode (for nodes it walks itself) and wrongShapeMsg (for the
// tags yaml quotes back in its own messages) both read it, so the two can only
// ever say the same thing about the same value.
var tagShapes = map[string]string{
	strTag:   "a string",
	intTag:   "a number",
	floatTag: "a number",
	boolTag:  "a true/false",
	nullTag:  "an empty value",
	seqTag:   "a list",
	mapTag:   "a map",
}

// mergeKey is YAML's "inherit these keys from another mapping" operator.
const mergeKey = "<<"

// keptValuesMark tags a message as one that cost the block no value, for the
// trip through yaml.v3's error channel.
//
// A custom unmarshaler can only hand problems back as a *yaml.TypeError, whose
// payload is []string, so the tag has to ride inside the text. decode strips
// it before anybody sees the message; see parseProblem for why the tag has to
// be applied at the point the message is written.
const keptValuesMark = "\x00kept-values\x00"

// keptValues marks a message whose block decoded fine apart from the problem
// being reported.
func keptValues(msg string) string { return keptValuesMark + msg }

// resolveAlias follows an alias to the node it points at. Aliases never nest —
// an anchor is always attached to a real node — so one hop is enough.
//
// yaml.v3 resolves aliases itself before invoking a custom unmarshaler, but not
// for nodes this package walks by hand, and a config that works everywhere
// except inside one block is worse than one that supports nothing.
func resolveAlias(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

// scalarText returns the literal text of a scalar node. Non-scalars and empty
// values report false so callers can produce a shape-specific error.
//
// The node's resolved tag is deliberately ignored: `contains: 404` should be
// usable as the string "404" rather than rejected for being an int.
func scalarText(n *yaml.Node) (string, bool) {
	n = resolveAlias(n)
	if n.Kind != yaml.ScalarNode || n.Tag == nullTag {
		return "", false
	}
	return n.Value, true
}

// describeNode names a node's shape for error messages, in the same words a
// user would use for their own YAML.
func describeNode(n *yaml.Node) string {
	n = resolveAlias(n)
	switch n.Kind {
	case yaml.ScalarNode:
		if shape, ok := tagShapes[n.Tag]; ok {
			return shape
		}
		// An exotic or custom tag (!!timestamp, !!binary) is still text as far
		// as a reader of the file is concerned.
		return tagShapes[strTag]
	case yaml.SequenceNode:
		return tagShapes[seqTag]
	case yaml.MappingNode:
		return tagShapes[mapTag]
	default:
		return "an unsupported value"
	}
}

// msgAt formats one problem tagged with its source line, matching the shape of
// yaml.v3's own messages so that everything reads alike in the final report.
func msgAt(n *yaml.Node, format string, args ...any) string {
	return fmt.Sprintf("line %d: %s", n.Line, fmt.Sprintf(format, args...))
}

// nodeErrs wraps messages as a *yaml.TypeError.
//
// This type matters: yaml.v3 appends a *yaml.TypeError returned by a custom
// UnmarshalYAML to the errors it has already collected and keeps decoding,
// whereas any other error type aborts the whole document. Returning a plain
// error here would hide every later problem behind the first bad duration.
func nodeErrs(msgs ...string) error {
	if len(msgs) == 0 {
		return nil
	}
	return &yaml.TypeError{Errors: msgs}
}

// kvPair is one key/value entry of a mapping node.
type kvPair struct{ key, val *yaml.Node }

// mappingPairs flattens a mapping node into its entries, resolving YAML merge
// keys (`<<: *anchor`, or a list of them).
//
// Merge semantics follow the spec: an explicitly written key always wins over a
// merged one, and among several merged mappings the first wins. Hand-walked
// blocks have to do this themselves — yaml.v3 only applies merges on its own
// struct and map decoding paths.
func mappingPairs(n *yaml.Node) ([]kvPair, []string) {
	var (
		out    []kvPair
		msgs   []string
		merges []*yaml.Node
	)
	seen := make(map[string]bool, len(n.Content)/2)

	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		key, ok := scalarText(kn)
		if ok && key == mergeKey {
			merges = append(merges, vn)
			continue
		}
		if ok {
			seen[key] = true
		}
		out = append(out, kvPair{kn, vn})
	}

	for _, m := range merges {
		for _, src := range mergeSources(m) {
			if src.Kind != yaml.MappingNode {
				msgs = append(msgs, msgAt(src, "a %q merge must refer to a map, got %s", mergeKey, describeNode(src)))
				continue
			}
			for i := 0; i+1 < len(src.Content); i += 2 {
				kn, vn := src.Content[i], src.Content[i+1]
				key, ok := scalarText(kn)
				if !ok || seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, kvPair{kn, vn})
			}
		}
	}
	return out, msgs
}

// mergeSources expands the value of a `<<` key into the mappings it names.
func mergeSources(n *yaml.Node) []*yaml.Node {
	n = resolveAlias(n)
	if n.Kind != yaml.SequenceNode {
		return []*yaml.Node{n}
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		out = append(out, resolveAlias(c))
	}
	return out
}
