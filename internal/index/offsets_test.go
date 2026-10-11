package index

import (
	"strings"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

// The whole design rests on this: slicing the source at the offsets
// Scan records must yield exactly the elements they claim to locate.
// The policy name is non-ASCII so that a rune/byte mix-up would show.
func TestScanOffsetsSliceToExactElements(t *testing.T) {
	src := nt.File("pölicy ✓", "r1",
		nt.Host("10.0.0.1",
			nt.Props(nt.Tag("HOST_END", "x")),
			nt.Item("19506", "0", "tcp", "0", "a &lt; b"),
			nt.Item("10267", "22", "tcp", "2", "ssh"),
		),
		`<ReportHost name="empty"/>`+"\n",
	)
	f, err := Scan(nt.Write(t, t.TempDir(), "a.nessus", src))
	if err != nil {
		t.Fatal(err)
	}
	slice := func(r Range) string { return src[r.Start:r.End] }

	if got, want := slice(f.ReportOpen), `<Report name="r1" xmlns:cm="http://www.nessus.org/cm">`; got != want {
		t.Errorf("ReportOpen = %q, want %q", got, want)
	}
	if got := slice(f.ReportName); got != "r1" || !f.HasReportName {
		t.Errorf("ReportName = %q (has=%v), want r1", got, f.HasReportName)
	}
	header := src[f.HeaderStart:f.HeaderEnd]
	if !strings.HasPrefix(header, "<?xml") || !strings.HasSuffix(header, "nessus.org/cm\">\n") {
		t.Errorf("header = %q", header)
	}
	if f.ReportSelfClosed {
		t.Error("ReportSelfClosed = true")
	}

	if len(f.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(f.Hosts))
	}
	h := f.Hosts[0]
	if got, want := slice(h.Open), `<ReportHost name="10.0.0.1">`; got != want {
		t.Errorf("Open = %q, want %q", got, want)
	}
	if got := slice(h.Range); !strings.HasPrefix(got, `<ReportHost name="10.0.0.1">`) || !strings.HasSuffix(got, "</ReportHost>") || strings.Count(got, "<ReportHost") != 1 {
		t.Errorf("Range = %q", got)
	}
	if got, want := slice(h.Props), nt.Props(nt.Tag("HOST_END", "x")); !h.HasProps || got+"\n" != want {
		t.Errorf("Props = %q, want %q", got, want)
	}
	if h.Name != "10.0.0.1" || h.Items != 2 {
		t.Errorf("Name = %q, Items = %d", h.Name, h.Items)
	}

	e := f.Hosts[1]
	if got, want := slice(e.Range), `<ReportHost name="empty"/>`; got != want || e.Open != e.Range {
		t.Errorf("self-closing host: Range = %q, Open = %v, Range = %v", got, e.Open, e.Range)
	}
	if e.HasProps || e.Items != 0 {
		t.Errorf("self-closing host: HasProps = %v, Items = %d", e.HasProps, e.Items)
	}
}
