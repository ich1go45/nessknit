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
	"time"
)

const rootElement = "NessusClientData_v2"

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
	Items    int // number of ReportItem children
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
		case xml.StartElement:
			depth++
			switch {
			case depth == 1 && !sawRoot:
				sawRoot = true
				if t.Name.Local != rootElement {
					return reject("root element is <%s>, expected <%s>", t.Name.Local, rootElement)
				}
			case depth == 2 && !haveReport && t.Name.Local == "Report":
				haveReport, inReport = true, true
				f.ReportOpen = Range{start, end}
			case depth == 3 && inReport && t.Name.Local == "ReportHost":
				if f.HeaderEnd < 0 {
					f.HeaderEnd = start
				}
				if name := attr(t, "name"); name == "" {
					f.Nameless++
				} else {
					cur = &Host{Name: name, Open: Range{start, end}, Range: Range{Start: start}}
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
