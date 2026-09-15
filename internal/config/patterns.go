package config

import (
	"gopkg.in/yaml.v3"
)

// Patterns is the polymorphic `match:`/`ignore:` value. YAML may be a string, a
// list of strings (OR over the raw line), or a map of field->regex (AND).
type Patterns struct {
	Line   []string
	Fields map[string]string
}

// Empty reports whether no pattern at all was configured.
func (p Patterns) Empty() bool { return len(p.Line) == 0 && len(p.Fields) == 0 }

// UnmarshalYAML implements yaml.Unmarshaler for the three accepted shapes.
//
// Anything else — most plausibly a list of maps, which is how people expect
// fail2ban-style multi-field rules to look — is rejected with the line number
// and a reminder of the shapes that do work.
func (p *Patterns) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == nullTag {
			// `match:` with nothing after it. Left empty here; whether that is
			// fatal is validation's call (it is, for match:).
			*p = Patterns{}
			return nil
		}
		*p = Patterns{Line: []string{n.Value}}
		return nil

	case yaml.SequenceNode:
		var msgs []string
		lines := make([]string, 0, len(n.Content))
		for _, item := range n.Content {
			s, ok := scalarText(item)
			if !ok {
				msgs = append(msgs, msgAt(item, "each entry of a pattern list must be a regex string, got %s"+
					" (a map of field: regex must not be nested inside a list)", describeNode(item)))
				continue
			}
			lines = append(lines, s)
		}
		if len(msgs) > 0 {
			return nodeErrs(msgs...)
		}
		*p = Patterns{Line: lines}
		return nil

	case yaml.MappingNode:
		// Walking the mapping by hand (rather than decoding into a map) keeps
		// the line numbers and lets duplicate keys be reported instead of
		// silently overwritten.
		pairs, msgs := mappingPairs(n)
		fields := make(map[string]string, len(pairs))
		for _, p := range pairs {
			key, ok := scalarText(p.key)
			if !ok || key == "" {
				msgs = append(msgs, msgAt(p.key, "pattern map keys must be field names, got %s", describeNode(p.key)))
				continue
			}
			val, ok := scalarText(p.val)
			if !ok {
				msgs = append(msgs, msgAt(p.val, "pattern for field %q must be a regex string, got %s", key, describeNode(p.val)))
				continue
			}
			if _, dup := fields[key]; dup {
				msgs = append(msgs, msgAt(p.key, "field %q appears twice in the same pattern map", key))
				continue
			}
			fields[key] = val
		}
		if len(msgs) > 0 {
			return nodeErrs(msgs...)
		}
		*p = Patterns{Fields: fields}
		return nil

	default:
		return nodeErrs(msgAt(n, "patterns must be a regex string, a list of regex strings, or a map of field: regex, got %s", describeNode(n)))
	}
}
