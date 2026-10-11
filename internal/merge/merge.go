// Package merge writes one merged .nessus document from indexed input
// files, copying elements as raw bytes and holding one host's finding
// keys in memory at a time.
package merge

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ich1go45/nessknit/internal/index"
	"github.com/ich1go45/nessknit/internal/logx"
	"github.com/ich1go45/nessknit/internal/summary"
)

// scanInfoPlugin is "Nessus Scan Information". It describes a scan, not
// a host, so only a host's first occurrence keeps it.
const scanInfoPlugin = "19506"

// ErrChanged reports that an input file is no longer the file that was
// indexed, so its recorded offsets cannot be trusted.
var ErrChanged = errors.New("file changed after it was indexed")

// Options configures Write.
type Options struct {
	ReportName string       // value for the Report name attribute
	Log        *logx.Logger // may be nil
}

// Write merges files into w. files[0] is the primary: its header is
// used for the output. The returned summary has Primary, Hosts,
// Findings and Files filled in.
func Write(w io.Writer, files []*index.File, opts Options) (*summary.Summary, error) {
	if len(files) == 0 {
		return nil, errors.New("no input files")
	}
	m := &merger{
		w:     w,
		files: files,
		log:   opts.Log,
		sum:   &summary.Summary{Primary: files[0].Path, Files: make([]summary.FileStats, len(files))},
		buf:   make([]byte, 256<<10),
	}
	for i, f := range files {
		m.sum.Files[i].Path = f.Path
		m.sum.Files[i].NamelessHosts = f.Nameless
		fh, err := os.Open(f.Path)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		st, err := fh.Stat()
		if err != nil {
			return nil, err
		}
		if st.Size() != f.Size || !st.ModTime().Equal(f.ModTime) {
			return nil, fmt.Errorf("%s: %w", f.Path, ErrChanged)
		}
		m.src = append(m.src, fh)
	}

	// Group every host's occurrences, keeping first-seen order.
	var order []string
	occs := map[string][]occurrence{}
	for fi, f := range files {
		for hi := range f.Hosts {
			h := &f.Hosts[hi]
			if _, ok := occs[h.Name]; !ok {
				order = append(order, h.Name)
			}
			occs[h.Name] = append(occs[h.Name], occurrence{file: fi, host: h})
		}
	}

	if err := m.writeHeader(opts.ReportName); err != nil {
		return nil, err
	}
	for _, name := range order {
		if err := m.writeHost(occs[name]); err != nil {
			return nil, err
		}
	}
	if err := m.write("</Report>\n</" + "NessusClientData_v2>\n"); err != nil {
		return nil, err
	}
	return m.sum, nil
}

type occurrence struct {
	file int // index into merger.files
	host *index.Host
}

type merger struct {
	w     io.Writer
	files []*index.File
	src   []*os.File
	log   *logx.Logger
	sum   *summary.Summary
	buf   []byte
}

// itemKey identifies a finding within one host.
type itemKey struct {
	plugin, port, proto string
	output              [sha256.Size]byte // of the trimmed plugin_output text
}

// child is one direct child element of a ReportHost.
type child struct {
	name     string
	rng      index.Range // absolute position in the source file
	key      itemKey     // set for ReportItem
	severity string      // set for ReportItem
}

func (m *merger) write(s string) error {
	_, err := io.WriteString(m.w, s)
	return err
}

// copyRange copies raw bytes from an input file to the output.
func (m *merger) copyRange(file int, r index.Range) error {
	_, err := io.CopyBuffer(m.w, io.NewSectionReader(m.src[file], r.Start, r.Len()), m.buf)
	return err
}

func (m *merger) read(file int, r index.Range) ([]byte, error) {
	b := make([]byte, r.Len())
	if _, err := m.src[file].ReadAt(b, r.Start); err != nil {
		return nil, fmt.Errorf("%s: %w", m.files[file].Path, err)
	}
	return b, nil
}

// writeHeader copies the primary's header with the report name replaced.
func (m *merger) writeHeader(name string) error {
	p := m.files[0]
	var esc bytes.Buffer
	if err := xml.EscapeText(&esc, []byte(name)); err != nil {
		return err
	}
	if err := m.copyRange(0, index.Range{Start: p.HeaderStart, End: p.ReportName.Start}); err != nil {
		return err
	}
	attr := esc.String()
	if !p.HasReportName {
		attr = ` name="` + attr + `"`
	}
	if err := m.write(attr); err != nil {
		return err
	}
	end := p.HeaderEnd
	if p.ReportSelfClosed {
		end = p.ReportOpen.End - 2 // drop "/>"
	}
	if err := m.copyRange(0, index.Range{Start: p.ReportName.End, End: end}); err != nil {
		return err
	}
	if p.ReportSelfClosed {
		return m.write(">\n")
	}
	return nil
}

// writeHost writes one merged ReportHost from all of its occurrences.
func (m *merger) writeHost(occs []occurrence) error {
	first := occs[0]
	name := first.host.Name
	m.sum.Hosts++
	m.sum.Files[first.file].NewHosts++
	for _, o := range occs[1:] {
		m.sum.Files[o.file].SeenHosts++
	}
	if len(occs) > 1 {
		paths := make([]string, len(occs))
		for i, o := range occs {
			paths[i] = m.files[o.file].Path
		}
		m.log.Debugf("host %q appears in %d blocks: %s", name, len(occs), strings.Join(paths, ", "))
	}

	open, err := m.read(first.file, first.host.Open)
	if err != nil {
		return err
	}
	if bytes.HasSuffix(open, []byte("/>")) {
		open = append(open[:len(open)-2], '>')
	}
	if err := m.write(string(open) + "\n"); err != nil {
		return err
	}

	props, err := m.mergedProps(occs)
	if err != nil {
		return err
	}
	propsWritten := props == nil
	writeProps := func() error {
		propsWritten = true
		return m.write(string(props) + "\n")
	}
	if !propsWritten && !first.host.HasProps {
		// Only a later occurrence has properties: they go first.
		if err := writeProps(); err != nil {
			return err
		}
	}

	seen := map[itemKey]struct{}{}
	copyChild := func(o occurrence, c child) error {
		if err := m.copyRange(o.file, c.rng); err != nil {
			return err
		}
		return m.write("\n")
	}

	err = m.eachChild(first, func(c child) error {
		switch {
		case c.name == "HostProperties" && !propsWritten:
			return writeProps()
		case c.name == "ReportItem":
			seen[c.key] = struct{}{}
			m.count(first.file, c)
		}
		return copyChild(first, c)
	})
	if err != nil {
		return err
	}

	for _, o := range occs[1:] {
		stats := &m.sum.Files[o.file]
		err := m.eachChild(o, func(c child) error {
			if c.name != "ReportItem" {
				return nil
			}
			if c.key.plugin == scanInfoPlugin {
				stats.ScanInfoSkipped++
				m.log.Debugf("skip scan-info host=%q from %s", name, stats.Path)
				return nil
			}
			if _, dup := seen[c.key]; dup {
				stats.Duplicates++
				m.log.Debugf("drop duplicate host=%q plugin=%s port=%s/%s output=%x from %s",
					name, c.key.plugin, c.key.port, c.key.proto, c.key.output[:6], stats.Path)
				return nil
			}
			seen[c.key] = struct{}{}
			m.count(o.file, c)
			return copyChild(o, c)
		})
		if err != nil {
			return err
		}
	}
	return m.write("</ReportHost>\n")
}

func (m *merger) count(file int, c child) {
	m.sum.Findings++
	m.sum.Files[file].CountFinding(c.severity)
}

// eachChild streams one ReportHost occurrence and calls fn for each of
// its direct children, in document order.
func (m *merger) eachChild(o occurrence, fn func(child) error) error {
	h := o.host
	section := io.NewSectionReader(m.src[o.file], h.Range.Start, h.Range.Len())
	dec := xml.NewDecoder(bufio.NewReaderSize(section, 64<<10))

	// plugin_output text is collected only from the first plugin_output
	// child, and only up to its first sub-element.
	const (
		outputPending = iota
		outputReading
		outputDone
	)
	var (
		depth  int
		cur    child
		output bytes.Buffer
		state  int
	)
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: host %q: %w", m.files[o.file].Path, h.Name, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 2:
				cur = child{name: t.Name.Local, rng: index.Range{Start: h.Range.Start + start}}
				output.Reset()
				state = outputPending
				if cur.name == "ReportItem" {
					for _, a := range t.Attr {
						if a.Name.Space != "" {
							continue
						}
						switch a.Name.Local {
						case "pluginID":
							cur.key.plugin = a.Value
						case "port":
							cur.key.port = a.Value
						case "protocol":
							cur.key.proto = a.Value
						case "severity":
							cur.severity = a.Value
						}
					}
				}
			case depth == 3 && cur.name == "ReportItem" && t.Name.Local == "plugin_output" && state == outputPending:
				state = outputReading
			case depth > 3 && state == outputReading:
				state = outputDone
			}
		case xml.CharData:
			if depth == 3 && state == outputReading {
				output.Write(t)
			}
		case xml.EndElement:
			if depth == 3 && state == outputReading {
				state = outputDone
			}
			if depth == 2 {
				cur.rng.End = h.Range.Start + dec.InputOffset()
				if cur.name == "ReportItem" {
					cur.key.output = sha256.Sum256(bytes.TrimSpace(output.Bytes()))
				}
				if err := fn(cur); err != nil {
					return err
				}
			}
			depth--
		}
	}
}

// mergedProps builds the HostProperties element for a host. The first
// block found is kept as it is; later blocks add only named tags whose
// name has not been seen. It returns nil if no occurrence has one.
func (m *merger) mergedProps(occs []occurrence) ([]byte, error) {
	var (
		base      []byte
		baseClose int
		extra     [][]byte
	)
	names := map[string]struct{}{}
	for _, o := range occs {
		if !o.host.HasProps {
			continue
		}
		raw, err := m.read(o.file, o.host.Props)
		if err != nil {
			return nil, err
		}
		tags, closeAt, err := propTags(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: host %q: %w", m.files[o.file].Path, o.host.Name, err)
		}
		isBase := base == nil
		if isBase {
			base, baseClose = raw, closeAt
		}
		for _, t := range tags {
			if t.name == "" {
				continue
			}
			if _, ok := names[t.name]; ok {
				continue
			}
			names[t.name] = struct{}{}
			if !isBase {
				extra = append(extra, raw[t.start:t.end])
			}
		}
	}
	if base == nil || len(extra) == 0 {
		return base, nil
	}
	var b bytes.Buffer
	if baseClose < 0 { // <HostProperties/>
		b.Write(base[:len(base)-2])
		b.WriteString(">\n")
	} else {
		b.Write(base[:baseClose])
	}
	for _, e := range extra {
		b.Write(e)
		b.WriteByte('\n')
	}
	b.WriteString("</HostProperties>")
	return b.Bytes(), nil
}

type propTag struct {
	name       string
	start, end int
}

// propTags lists the tag children of a raw HostProperties element.
// closeAt is the offset of its closing tag, or -1 if it is self-closing.
func propTags(raw []byte) (tags []propTag, closeAt int, err error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	var cur *propTag
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			return tags, closeAt, nil
		}
		if err != nil {
			return nil, 0, err
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == "tag" {
				cur = &propTag{start: start}
				for _, a := range t.Attr {
					if a.Name.Space == "" && a.Name.Local == "name" {
						cur.name = a.Value
					}
				}
			}
		case xml.EndElement:
			if depth == 2 && cur != nil {
				cur.end = end
				tags = append(tags, *cur)
				cur = nil
			}
			if depth == 1 {
				closeAt = start
				if end == start {
					closeAt = -1
				}
			}
			depth--
		}
	}
}
