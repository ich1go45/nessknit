package index

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

func scan(t *testing.T, src string) (*File, error) {
	t.Helper()
	return Scan(nt.Write(t, t.TempDir(), "in.nessus", src))
}

func mustScan(t *testing.T, src string) *File {
	t.Helper()
	f, err := scan(t, src)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestScanRejects(t *testing.T) {
	good := nt.File("p", "r", nt.Host("h"))
	cases := []struct {
		name, src, reason string
	}{
		{"truncated", good[:len(good)-30], "not well-formed XML"},
		{"bare ampersand", strings.Replace(good, "<policyName>p", "<policyName>p & q", 1), "not well-formed XML"},
		{"control character", strings.Replace(good, "<policyName>p", "<policyName>p\x01", 1), "not well-formed XML"},
		{"latin-1", strings.Replace(good, `<?xml version="1.0" ?>`, `<?xml version="1.0" encoding="ISO-8859-1"?>`, 1), `unsupported encoding "ISO-8859-1"`},
		{"wrong root", "<NessusClientData><Report name=\"r\"/></NessusClientData>", "root element is <NessusClientData>"},
		{"no report", "<NessusClientData_v2><Policy/></NessusClientData_v2>", "no <Report> element"},
		{"nested report only", "<NessusClientData_v2><Policy><Report name=\"r\"/></Policy></NessusClientData_v2>", "no <Report> element"},
		{"empty", "", "empty file or no root element"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := scan(t, c.src)
			var rej *RejectError
			if !errors.As(err, &rej) {
				t.Fatalf("err = %v, want *RejectError", err)
			}
			if !strings.Contains(rej.Reason, c.reason) {
				t.Errorf("reason = %q, want it to contain %q", rej.Reason, c.reason)
			}
		})
	}
}

func TestScanMissingFileIsNotARejection(t *testing.T) {
	_, err := Scan(filepath.Join(t.TempDir(), "absent.nessus"))
	var rej *RejectError
	if err == nil || errors.As(err, &rej) {
		t.Fatalf("err = %v, want a plain I/O error", err)
	}
}

func TestScanAcceptsExplicitUTF8Declaration(t *testing.T) {
	src := strings.Replace(nt.File("p", "r", nt.Host("h")), `<?xml version="1.0" ?>`, `<?xml version="1.0" encoding="utf-8"?>`, 1)
	if len(mustScan(t, src).Hosts) != 1 {
		t.Error("want 1 host")
	}
}

func TestScanRecordsSizeAndModTime(t *testing.T) {
	path := nt.Write(t, t.TempDir(), "a.nessus", nt.File("p", "r", nt.Host("h")))
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != path || f.Size != st.Size() || !f.ModTime.Equal(st.ModTime()) {
		t.Errorf("got %q %d %v, want %q %d %v", f.Path, f.Size, f.ModTime, path, st.Size(), st.ModTime())
	}
}

func TestScanSkipsNamelessHosts(t *testing.T) {
	src := nt.File("p", "r",
		"<ReportHost>\n"+nt.Item("1", "0", "tcp", "0", "x")+"</ReportHost>\n",
		nt.Host("", nt.Item("2", "0", "tcp", "0", "x")),
		nt.Host("kept", nt.Item("3", "0", "tcp", "0", "x")),
	)
	f := mustScan(t, src)
	if f.Nameless != 2 || len(f.Hosts) != 1 || f.Hosts[0].Name != "kept" || f.Hosts[0].Items != 1 {
		t.Errorf("Nameless = %d, Hosts = %+v", f.Nameless, f.Hosts)
	}
	if got := src[f.HeaderEnd:]; !strings.HasPrefix(got, "<ReportHost>") {
		t.Errorf("header must end at the first ReportHost even if nameless, got %q", got[:20])
	}
}

func TestScanHostProperties(t *testing.T) {
	src := nt.File("p", "r",
		nt.Host("none", nt.Item("1", "0", "tcp", "0", "x")),
		nt.Host("last", nt.Item("1", "0", "tcp", "0", "x"), nt.Props(nt.Tag("a", "1"))),
		nt.Host("two", nt.Props(nt.Tag("a", "1")), nt.Props(nt.Tag("b", "2"))),
		nt.Host("selfclosed", "<HostProperties/>\n"),
	)
	f := mustScan(t, src)
	slice := func(r Range) string { return src[r.Start:r.End] }
	if f.Hosts[0].HasProps {
		t.Error("none: HasProps = true")
	}
	if got := slice(f.Hosts[1].Props); !f.Hosts[1].HasProps || !strings.Contains(got, `name="a"`) {
		t.Errorf("last: Props = %q", got)
	}
	if got := slice(f.Hosts[2].Props); !strings.Contains(got, `name="a"`) || strings.Contains(got, `name="b"`) {
		t.Errorf("two: Props must be the first block only, got %q", got)
	}
	if got := slice(f.Hosts[3].Props); got != "<HostProperties/>" {
		t.Errorf("selfclosed: Props = %q", got)
	}
}

func TestScanReportWithoutHosts(t *testing.T) {
	src := nt.File("p", "r")
	f := mustScan(t, src)
	if len(f.Hosts) != 0 || f.ReportSelfClosed {
		t.Errorf("Hosts = %d, ReportSelfClosed = %v", len(f.Hosts), f.ReportSelfClosed)
	}
	if got := src[f.HeaderEnd:]; !strings.HasPrefix(got, "</Report>") {
		t.Errorf("header must end at </Report>, rest = %q", got)
	}
}

func TestScanSelfClosingReport(t *testing.T) {
	src := `<NessusClientData_v2><Report name="r"/></NessusClientData_v2>`
	f := mustScan(t, src)
	if !f.ReportSelfClosed || f.HeaderEnd != f.ReportOpen.End {
		t.Errorf("ReportSelfClosed = %v, HeaderEnd = %d, ReportOpen = %v", f.ReportSelfClosed, f.HeaderEnd, f.ReportOpen)
	}
}

func TestScanReportNameVariants(t *testing.T) {
	cases := []struct {
		name, tag, value string
		has              bool
		rest             string // what follows the recorded range
	}{
		{"single quotes", `<Report xmlns:cm='u' name='it"s'>`, `it"s`, true, `'>`},
		{"spaces around equals", `<Report name = "r 1" >`, "r 1", true, `" >`},
		{"not first", `<Report other="name" name="x">`, "x", true, `">`},
		{"absent", `<Report xmlns:cm="u">`, "", false, ` xmlns:cm="u">`},
		{"absent, bare", `<Report>`, "", false, `>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "<NessusClientData_v2>" + c.tag + "</Report></NessusClientData_v2>"
			f := mustScan(t, src)
			if got := src[f.ReportName.Start:f.ReportName.End]; got != c.value || f.HasReportName != c.has {
				t.Errorf("ReportName = %q (has=%v), want %q (has=%v)", got, f.HasReportName, c.value, c.has)
			}
			if got := src[f.ReportName.End:]; !strings.HasPrefix(got, c.rest) {
				t.Errorf("after ReportName: %q, want prefix %q", got, c.rest)
			}
		})
	}
}

func TestScanSkipsByteOrderMark(t *testing.T) {
	f := mustScan(t, "\xef\xbb\xbf"+nt.File("p", "r", nt.Host("h")))
	if f.HeaderStart != 3 || len(f.Hosts) != 1 {
		t.Errorf("HeaderStart = %d, Hosts = %d; want 3 and 1", f.HeaderStart, len(f.Hosts))
	}
	if g := mustScan(t, nt.File("p", "r")); g.HeaderStart != 0 {
		t.Errorf("no BOM: HeaderStart = %d, want 0", g.HeaderStart)
	}
}

func TestScanIgnoresSecondReport(t *testing.T) {
	src := "<NessusClientData_v2><Report name=\"a\">" + nt.Host("h1") + "</Report><Report name=\"b\">" + nt.Host("h2") + "</Report></NessusClientData_v2>"
	f := mustScan(t, src)
	if len(f.Hosts) != 1 || f.Hosts[0].Name != "h1" {
		t.Errorf("Hosts = %+v, want only h1", f.Hosts)
	}
}
