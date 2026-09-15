package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// scope says which block of the document a problem belongs to. Problems are
// attributed so that a block which failed to decode can have its (necessarily
// bogus) validation errors dropped without silencing the rest of the file.
type scope int

const (
	scopeGlobal scope = iota
	scopeDefaults
	scopeMonitor
)

// origin is a scope plus, for a monitor, its name. A monitor may legally be
// named "defaults", hence the separate scope rather than a magic string.
type origin struct {
	scope scope
	name  string
}

func globalOrigin() origin          { return origin{scope: scopeGlobal} }
func defaultsOrigin() origin        { return origin{scope: scopeDefaults} }
func monitorOrigin(n string) origin { return origin{scope: scopeMonitor, name: n} }

// prefix renders the "monitor \"sshd\": " part of a message.
func (o origin) prefix() string {
	switch o.scope {
	case scopeDefaults:
		return "defaults: "
	case scopeMonitor:
		return fmt.Sprintf("monitor %q: ", o.name)
	default:
		return ""
	}
}

// ownedRange is the span of source lines belonging to one block.
type ownedRange struct {
	start, end int
	origin     origin
}

// lineOwners maps a source line back to the block that owns it.
//
// It exists for error attribution only, and is built from a second, lenient
// parse of the document: the strict decode cannot report line spans, and
// hand-decoding monitors would cost the unknown-key checking that is the whole
// point of this package.
type lineOwners struct {
	ranges []ownedRange
}

func newLineOwners(src []byte) lineOwners {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil || len(doc.Content) == 0 {
		// Unreachable in practice: attribution only runs after a decode that
		// got far enough to report schema errors. An empty map degrades to
		// "everything is global", which suppresses more than it should but
		// never invents an error.
		return lineOwners{}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return lineOwners{}
	}

	var owners lineOwners
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, vn := root.Content[i], root.Content[i+1]
		switch key.Value {
		case "defaults":
			owners.ranges = append(owners.ranges, ownedRange{key.Line, maxLine(vn), defaultsOrigin()})
		case "monitors":
			if vn.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(vn.Content); j += 2 {
				mk, mv := vn.Content[j], vn.Content[j+1]
				owners.ranges = append(owners.ranges, ownedRange{mk.Line, maxLine(mv), monitorOrigin(mk.Value)})
			}
		}
	}
	return owners
}

// owner reports which block a line belongs to, defaulting to the top level.
func (o lineOwners) owner(line int) origin {
	for _, r := range o.ranges {
		if line >= r.start && line <= r.end {
			return r.origin
		}
	}
	return globalOrigin()
}

// maxLine returns the last source line covered by a node's subtree.
func maxLine(n *yaml.Node) int {
	last := n.Line
	for _, c := range n.Content {
		if l := maxLine(c); l > last {
			last = l
		}
	}
	return last
}
