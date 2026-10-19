package ctl

import (
	"errors"
	"fmt"
	"strings"
)

// A deliberately small YAML reader and writer for netplan files. It understands block maps, block lists (also at the same indent as their key, which
// netplan files do), lists of maps, flow lists of plain scalars ("[a, b]"), quoted and plain scalars, and comments. Everything else (tabs, anchors,
// tags, block scalars, flow maps, multiple documents) is refused with an error, which the bridge planner reports as an unparsable file: refusing is
// always safe, guessing is not. Comments are not preserved; the planner shows the person the exact difference before anything is written.

type yKind byte

const (
	yMap yKind = 'm'
	yLst yKind = 'l'
	ySca yKind = 's'
)

// ynode is one YAML value. Map keys keep their order.
type ynode struct {
	kind   yKind
	keys   []string
	m      map[string]*ynode
	l      []*ynode
	s      string
	quoted bool
	null   bool // "key:" with nothing after it
}

func newMap() *ynode               { return &ynode{kind: yMap, m: map[string]*ynode{}} }
func newList() *ynode              { return &ynode{kind: yLst} }
func scalar(s string) *ynode       { return &ynode{kind: ySca, s: s} }
func quotedScalar(s string) *ynode { return &ynode{kind: ySca, s: s, quoted: true} }
func (n *ynode) isMap() bool       { return n != nil && n.kind == yMap }
func (n *ynode) isList() bool      { return n != nil && n.kind == yLst }
func (n *ynode) isScalar() bool    { return n != nil && n.kind == ySca && !n.null }
func (n *ynode) get(k string) *ynode {
	if n == nil || n.kind != yMap {
		return nil
	}
	return n.m[k]
}

func (n *ynode) set(k string, v *ynode) {
	if _, ok := n.m[k]; !ok {
		n.keys = append(n.keys, k)
	}
	n.m[k] = v
}

func (n *ynode) del(k string) {
	if _, ok := n.m[k]; !ok {
		return
	}
	delete(n.m, k)
	for i, kk := range n.keys {
		if kk == k {
			n.keys = append(n.keys[:i:i], n.keys[i+1:]...)
			break
		}
	}
}

// strs returns the scalars of a list (or the single scalar), and false if the node is anything else.
func (n *ynode) strs() ([]string, bool) {
	switch {
	case n == nil:
		return nil, true
	case n.isScalar():
		return []string{n.s}, true
	case n.isList():
		out := make([]string, 0, len(n.l))
		for _, e := range n.l {
			if !e.isScalar() {
				return nil, false
			}
			out = append(out, e.s)
		}
		return out, true
	}
	return nil, false
}

func strList(ss []string) *ynode {
	l := newList()
	for _, s := range ss {
		l.l = append(l.l, scalar(s))
	}
	return l
}

type yline struct {
	indent int
	text   string
	no     int
}

var errYAML = errors.New("unsupported or malformed YAML")

func yerr(no int, why string) error { return fmt.Errorf("%w: line %d: %s", errYAML, no, why) }

// stripComment removes a trailing comment (a '#' at the start or after a space, outside quotes).
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '[' || s[i-1] == ',' || s[i-1] == ':' {
				q = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return s[:i]
		}
	}
	return s
}

func lexYAML(src string) ([]yline, error) {
	var out []yline
	for no, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		line := stripComment(raw)
		t := strings.TrimRight(line, " ")
		if strings.TrimSpace(t) == "" {
			continue
		}
		ind := len(t) - len(strings.TrimLeft(t, " "))
		if strings.ContainsRune(t[:ind], '\t') || strings.HasPrefix(strings.TrimLeft(t, " "), "\t") {
			return nil, yerr(no+1, "tab indentation")
		}
		text := t[ind:]
		if ind == 0 && (strings.HasPrefix(text, "---") || strings.HasPrefix(text, "...") || strings.HasPrefix(text, "%")) {
			return nil, yerr(no+1, "document markers and directives are not supported")
		}
		out = append(out, yline{indent: ind, text: text, no: no + 1})
	}
	return out, nil
}

func isItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

type yparser struct {
	ls []yline
	i  int
}

// parseYAML reads one document whose root is a map.
func parseYAML(src string) (*ynode, error) {
	ls, err := lexYAML(src)
	if err != nil {
		return nil, err
	}
	if len(ls) == 0 {
		return newMap(), nil
	}
	p := &yparser{ls: ls}
	n, err := p.block(ls[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i != len(ls) {
		return nil, yerr(ls[p.i].no, "unexpected indentation")
	}
	if !n.isMap() {
		return nil, yerr(ls[0].no, "the document must be a map")
	}
	return n, nil
}

func (p *yparser) block(indent int) (*ynode, error) {
	if p.i >= len(p.ls) {
		return nil, errYAML
	}
	if isItem(p.ls[p.i].text) {
		return p.list(indent)
	}
	return p.mapping(indent)
}

func (p *yparser) list(indent int) (*ynode, error) {
	out := newList()
	for p.i < len(p.ls) && p.ls[p.i].indent == indent && isItem(p.ls[p.i].text) {
		l := p.ls[p.i]
		rest := strings.TrimLeft(strings.TrimPrefix(l.text, "-"), " ")
		if rest == "" {
			p.i++
			if p.i >= len(p.ls) || p.ls[p.i].indent <= indent {
				out.l = append(out.l, &ynode{kind: ySca, null: true})
				continue
			}
			child, err := p.block(p.ls[p.i].indent)
			if err != nil {
				return nil, err
			}
			out.l = append(out.l, child)
			continue
		}
		if _, _, isKV := splitKV(rest); isKV && !strings.HasPrefix(rest, "[") && !strings.HasPrefix(rest, "\"") && !strings.HasPrefix(rest, "'") {
			// "- key: value": the map's own indent is where the key starts
			p.ls[p.i] = yline{indent: indent + (len(l.text) - len(rest)), text: rest, no: l.no}
			child, err := p.mapping(p.ls[p.i].indent)
			if err != nil {
				return nil, err
			}
			out.l = append(out.l, child)
			continue
		}
		v, err := scalarOrFlow(rest, l.no)
		if err != nil {
			return nil, err
		}
		out.l = append(out.l, v)
		p.i++
	}
	if p.i < len(p.ls) && p.ls[p.i].indent > indent {
		return nil, yerr(p.ls[p.i].no, "unexpected indentation")
	}
	return out, nil
}

func (p *yparser) mapping(indent int) (*ynode, error) {
	out := newMap()
	for p.i < len(p.ls) && p.ls[p.i].indent == indent && !isItem(p.ls[p.i].text) {
		l := p.ls[p.i]
		k, v, ok := splitKV(l.text)
		if !ok {
			return nil, yerr(l.no, "expected \"key: value\"")
		}
		if _, dup := out.m[k]; dup {
			return nil, yerr(l.no, "duplicate key "+k)
		}
		p.i++
		if v == "" {
			if p.i < len(p.ls) && (p.ls[p.i].indent > indent || (p.ls[p.i].indent == indent && isItem(p.ls[p.i].text))) {
				child, err := p.block(p.ls[p.i].indent)
				if err != nil {
					return nil, err
				}
				out.set(k, child)
			} else {
				out.set(k, &ynode{kind: ySca, null: true})
			}
			continue
		}
		val, err := scalarOrFlow(v, l.no)
		if err != nil {
			return nil, err
		}
		out.set(k, val)
	}
	if p.i < len(p.ls) && p.ls[p.i].indent > indent {
		return nil, yerr(p.ls[p.i].no, "unexpected indentation")
	}
	return out, nil
}

// splitKV splits "key: value" (or "key:") at the first colon that ends the key. Keys are plain or quoted scalars.
func splitKV(s string) (k, v string, ok bool) {
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' || s[0] == '\'' {
		q := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] == q {
				rest := s[i+1:]
				if rest == ":" || strings.HasPrefix(rest, ": ") {
					return s[1:i], strings.TrimSpace(strings.TrimPrefix(rest, ":")), true
				}
				return "", "", false
			}
		}
		return "", "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func scalarOrFlow(v string, no int) (*ynode, error) {
	switch v[0] {
	case '{':
		return nil, yerr(no, "flow maps are not supported")
	case '&', '*', '!', '|', '>', '@', '`':
		return nil, yerr(no, "anchors, tags and block scalars are not supported")
	case '[':
		if !strings.HasSuffix(v, "]") {
			return nil, yerr(no, "unterminated flow list")
		}
		inner := strings.TrimSpace(v[1 : len(v)-1])
		l := newList()
		if inner == "" {
			return l, nil
		}
		for _, part := range splitFlow(inner) {
			part = strings.TrimSpace(part)
			if part == "" || strings.ContainsAny(part[:1], "[{") {
				return nil, yerr(no, "nested flow collections are not supported")
			}
			s, err := scalarText(part, no)
			if err != nil {
				return nil, err
			}
			l.l = append(l.l, s)
		}
		return l, nil
	}
	return scalarText(v, no)
}

func splitFlow(s string) []string {
	var parts []string
	var q byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == ',':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func scalarText(v string, no int) (*ynode, error) {
	switch v[0] {
	case '"':
		if len(v) < 2 || v[len(v)-1] != '"' {
			return nil, yerr(no, "unterminated quoted string")
		}
		body := v[1 : len(v)-1]
		if strings.ContainsAny(strings.ReplaceAll(strings.ReplaceAll(body, `\\`, ""), `\"`, ""), `\"`) {
			return nil, yerr(no, "escape sequences are not supported")
		}
		return quotedScalar(strings.ReplaceAll(strings.ReplaceAll(body, `\"`, `"`), `\\`, `\`)), nil
	case '\'':
		if len(v) < 2 || v[len(v)-1] != '\'' {
			return nil, yerr(no, "unterminated quoted string")
		}
		return quotedScalar(strings.ReplaceAll(v[1:len(v)-1], "''", "'")), nil
	}
	if strings.ContainsAny(v[:1], "&*!|>%@`") || strings.Contains(v, ": ") {
		return nil, yerr(no, "unsupported scalar")
	}
	return scalar(v), nil
}

func plainSafe(s string) bool {
	if s == "" || strings.HasSuffix(s, ":") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_./:+-", c) >= 0
		if !ok {
			return false
		}
	}
	return s[0] != '-' && s[0] != ':'
}

func scalarOut(n *ynode) string {
	if n.null {
		return ""
	}
	if n.quoted || !plainSafe(n.s) {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(n.s, `\`, `\\`), `"`, `\"`) + `"`
	}
	return n.s
}

// marshalYAML writes a node with two-space indentation. Lists of plain scalars are written as block lists, which every netplan version reads.
func marshalYAML(n *ynode) string { return marshalYAMLUnit(n, 2) }

// marshalYAMLUnit writes with the given number of spaces per level, so a rewritten file keeps the indentation its author chose.
func marshalYAMLUnit(n *ynode, unit int) string {
	if unit < 1 || unit > 8 {
		unit = 2
	}
	var b strings.Builder
	emitMap(&b, n, 0, unit)
	return b.String()
}

// indentUnit is the smallest indentation used in src (2 when there is none).
func indentUnit(src string) int {
	best := 0
	for _, l := range strings.Split(src, "\n") {
		t := strings.TrimLeft(l, " ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if ind := len(l) - len(t); ind > 0 && (best == 0 || ind < best) {
			best = ind
		}
	}
	if best == 0 || best > 8 {
		return 2
	}
	return best
}

func emitMap(b *strings.Builder, n *ynode, ind, unit int) {
	pad := strings.Repeat(" ", ind)
	for _, k := range n.keys {
		v := n.m[k]
		switch {
		case v.isMap():
			if len(v.keys) == 0 {
				b.WriteString(pad + k + ": {}\n")
				continue
			}
			b.WriteString(pad + k + ":\n")
			emitMap(b, v, ind+unit, unit)
		case v.isList():
			if len(v.l) == 0 {
				b.WriteString(pad + k + ": []\n")
				continue
			}
			b.WriteString(pad + k + ":\n")
			emitList(b, v, ind+unit, unit)
		default:
			if v.null {
				b.WriteString(pad + k + ":\n")
			} else {
				b.WriteString(pad + k + ": " + scalarOut(v) + "\n")
			}
		}
	}
}

func emitList(b *strings.Builder, n *ynode, ind, unit int) {
	pad := strings.Repeat(" ", ind)
	for _, e := range n.l {
		switch {
		case e.isMap():
			if len(e.keys) == 0 {
				b.WriteString(pad + "- {}\n")
				continue
			}
			var sb strings.Builder
			emitMap(&sb, e, ind+2, unit)
			s := sb.String()
			b.WriteString(pad + "- " + strings.TrimLeft(s[:strings.IndexByte(s, '\n')+1], " "))
			b.WriteString(s[strings.IndexByte(s, '\n')+1:])
		case e.isList():
			b.WriteString(pad + "-\n")
			emitList(b, e, ind+unit, unit)
		default:
			b.WriteString(pad + "- " + scalarOut(e) + "\n")
		}
	}
}

func (n *ynode) clone() *ynode {
	if n == nil {
		return nil
	}
	c := &ynode{kind: n.kind, s: n.s, quoted: n.quoted, null: n.null}
	if n.kind == yMap {
		c.m = map[string]*ynode{}
		for _, k := range n.keys {
			c.keys = append(c.keys, k)
			c.m[k] = n.m[k].clone()
		}
	}
	for _, e := range n.l {
		c.l = append(c.l, e.clone())
	}
	return c
}
