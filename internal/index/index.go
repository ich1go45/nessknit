// Package index scans a .nessus file once and records where its parts
// sit, as byte offsets, without keeping any of the content in memory.
package index

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

const (
	rootElement  = "NessusClientData_v2"
	xmlNamespace = "http://www.w3.org/XML/1998/namespace"
)

// NS is one namespace declaration. Prefix is empty for the default
// namespace.
type NS struct{ Prefix, URI string }

// Range is a half-open byte range [Start, End) within a file.
type Range struct{ Start, End int64 }

func (r Range) Len() int64 { return r.End - r.Start }

// Host locates one named ReportHost element.
type Host struct {
	Name     string
	Range    Range // the whole element, opening tag to closing tag
	Open     Range // the opening tag only
	Props    Range // the first HostProperties child; valid if HasProps
	HasProps bool
	Items    int  // number of ReportItem children
	NS       []NS // declarations on the ReportHost tag itself
}

// File is the index of one usable .nessus file.
type File struct {
	Path    string
	Size    int64
	ModTime time.Time

	// The header is [HeaderStart, HeaderEnd): everything before the
	// first ReportHost, minus a leading byte order mark. With no hosts
	// it ends at the closing Report tag, or at the end of a
	// self-closing Report tag.
	HeaderStart      int64
	HeaderEnd        int64
	ReportOpen       Range // the opening Report tag
	ReportSelfClosed bool  // the Report tag is written as <Report .../>

	// ReportName is the value of the Report name attribute, without
	// its quotes. If HasReportName is false the range is empty and
	// marks where a name attribute can be inserted.
	ReportName    Range
	HasReportName bool

	// NS holds the namespace declarations in scope for the children of
	// Report: the root's and Report's own, sorted by prefix. Elements
	// copied out of this file depend on them.
	NS []NS

	Hosts    []Host
	Nameless int // ReportHost elements skipped for having no name
}

// RejectError says why a file cannot be merged.
type RejectError struct {
	Path   string
	Reason string
}

func (e *RejectError) Error() string { return e.Reason }

// Scan reads the file at path once and returns its index. It returns a
// *RejectError if the file is readable but not a usable .nessus file.
func Scan(path string) (*File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	f := &File{Path: path, Size: st.Size(), ModTime: st.ModTime(), HeaderEnd: -1}
	reject := func(format string, a ...any) (*File, error) {
		return nil, &RejectError{Path: path, Reason: fmt.Sprintf(format, a...)}
	}

	var badCharset string
	dec := xml.NewDecoder(bufio.NewReaderSize(fh, 1<<20))
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		badCharset = label
		return nil, fmt.Errorf("unsupported encoding %q", label)
	}

	var (
		depth               int
		sawRoot, haveReport bool
		inReport, inProps   bool
		cur                 *Host
		scope               []NS  // declarations in force, innermost last
		marks               []int // len(scope) before each open element
	)
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if badCharset != "" {
				return reject("unsupported encoding %q (only UTF-8 is supported)", badCharset)
			}
			return reject("not well-formed XML: %v", err)
		}
		end := dec.InputOffset()

		switch t := tok.(type) {
		case xml.CharData:
			// The decoder allows text outside the root; XML does not.
			if depth == 0 && len(bytes.TrimSpace(bytes.TrimPrefix(t, []byte("\xef\xbb\xbf")))) > 0 {
				return reject("not well-formed XML: text outside the root element")
			}
		case xml.StartElement:
			depth++
			marks = append(marks, len(scope))
			decls := declarations(t)
			scope = append(scope, decls...)
			if reason := checkElement(t, scope); reason != "" {
				return reject("not well-formed XML: %s", reason)
			}
			switch {
			case depth == 1 && sawRoot:
				return reject("not well-formed XML: more than one root element")
			case depth == 1:
				sawRoot = true
				if t.Name.Local != rootElement {
					return reject("root element is <%s>, expected <%s>", t.Name.Local, rootElement)
				}
			case depth == 2 && !haveReport && t.Name.Local == "Report":
				haveReport, inReport = true, true
				f.ReportOpen = Range{start, end}
				f.NS = effective(scope)
			case depth == 3 && inReport && t.Name.Local == "ReportHost":
				if f.HeaderEnd < 0 {
					f.HeaderEnd = start
				}
				if name := attr(t, "name"); name == "" {
					f.Nameless++
				} else {
					cur = &Host{Name: name, Open: Range{start, end}, Range: Range{Start: start}, NS: decls}
				}
			case depth == 4 && cur != nil && t.Name.Local == "HostProperties":
				if !cur.HasProps && !inProps {
					inProps = true
					cur.Props.Start = start
				}
			case depth == 4 && cur != nil && t.Name.Local == "ReportItem":
				cur.Items++
			}
		case xml.EndElement:
			switch {
			case depth == 4 && inProps:
				inProps = false
				cur.HasProps = true
				cur.Props.End = end
			case depth == 3 && cur != nil:
				cur.Range.End = end
				f.Hosts = append(f.Hosts, *cur)
				cur = nil
			case depth == 2 && inReport:
				inReport = false
				if f.HeaderEnd < 0 {
					f.HeaderEnd = start
				}
				f.ReportSelfClosed = end == start
			}
			scope = scope[:marks[len(marks)-1]]
			marks = marks[:len(marks)-1]
			depth--
		}
	}
	if !sawRoot {
		return reject("empty file or no root element")
	}
	if !haveReport {
		return reject("no <Report> element")
	}

	tag := make([]byte, f.ReportOpen.Len())
	if _, err := fh.ReadAt(tag, f.ReportOpen.Start); err != nil {
		return nil, err
	}
	vs, ve, ok := attrValue(tag, "name")
	f.HasReportName = ok
	f.ReportName = Range{f.ReportOpen.Start + int64(vs), f.ReportOpen.Start + int64(ve)}

	bom := make([]byte, 3)
	if n, _ := fh.ReadAt(bom, 0); n == 3 && bytes.Equal(bom, []byte("\xef\xbb\xbf")) {
		f.HeaderStart = 3
	}
	return f, nil
}

// declarations returns the namespace declarations written on a tag.
func declarations(t xml.StartElement) []NS {
	var decls []NS
	for _, a := range t.Attr {
		switch {
		case a.Name.Space == "xmlns":
			decls = append(decls, NS{a.Name.Local, a.Value})
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			decls = append(decls, NS{"", a.Value})
		}
	}
	return decls
}

// effective reduces a scope to one declaration per prefix, the
// innermost winning, sorted by prefix.
func effective(scope []NS) []NS {
	byPrefix := map[string]string{}
	for _, d := range scope {
		byPrefix[d.Prefix] = d.URI
	}
	out := make([]NS, 0, len(byPrefix))
	for prefix, uri := range byPrefix {
		out = append(out, NS{prefix, uri})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// checkElement applies two rules the decoder does not enforce: a tag's
// attribute names are unique, and every namespace prefix is declared.
// It returns a reason, or "" if the tag is fine.
//
// The decoder replaces a declared prefix with its URI and leaves an
// undeclared one as it was, so a name's Space is acceptable only if it
// is a URI in scope.
func checkElement(t xml.StartElement, scope []NS) string {
	bound := func(space string) bool {
		if space == "" || space == "xmlns" || space == xmlNamespace {
			return true
		}
		for _, d := range scope {
			if d.URI == space {
				return true
			}
		}
		return false
	}
	if !bound(t.Name.Space) {
		return fmt.Sprintf("undeclared namespace prefix %q on <%s>", t.Name.Space, t.Name.Local)
	}
	for i, a := range t.Attr {
		if !bound(a.Name.Space) {
			return fmt.Sprintf("undeclared namespace prefix %q on attribute %s of <%s>", a.Name.Space, a.Name.Local, t.Name.Local)
		}
		for _, b := range t.Attr[:i] {
			if a.Name == b.Name {
				return fmt.Sprintf("duplicate attribute %q on <%s>", a.Name.Local, t.Name.Local)
			}
		}
	}
	return ""
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// attrValue finds attribute name in the raw bytes of a start tag and
// returns the range of its value, excluding the quotes. If the
// attribute is absent, ok is false and start and end both give the
// offset just after the element name.
func attrValue(tag []byte, name string) (start, end int, ok bool) {
	i := 1 // skip '<'
	for i < len(tag) && !isSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	nameEnd := i
	for {
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			return nameEnd, nameEnd, false
		}
		attrStart := i
		for i < len(tag) && tag[i] != '=' && !isSpace(tag[i]) {
			i++
		}
		attrName := string(tag[attrStart:i])
		for i < len(tag) && (isSpace(tag[i]) || tag[i] == '=') {
			i++
		}
		if i >= len(tag) || (tag[i] != '"' && tag[i] != '\'') {
			return nameEnd, nameEnd, false
		}
		quote := tag[i]
		i++
		valueStart := i
		for i < len(tag) && tag[i] != quote {
			i++
		}
		if i >= len(tag) {
			return nameEnd, nameEnd, false
		}
		if attrName == name {
			return valueStart, i, true
		}
		i++
	}
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
