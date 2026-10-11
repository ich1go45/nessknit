package merge

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ich1go45/nessknit/internal/index"
	"github.com/ich1go45/nessknit/internal/logx"
	nt "github.com/ich1go45/nessknit/internal/nessustest"
	"github.com/ich1go45/nessknit/internal/summary"
)

type result struct {
	doc nt.Doc
	sum *summary.Summary
	raw string
}

func scanAll(t *testing.T, srcs ...string) []*index.File {
	t.Helper()
	dir := t.TempDir()
	var files []*index.File
	for i, src := range srcs {
		f, err := index.Scan(nt.Write(t, dir, fmt.Sprintf("f%d.nessus", i), src))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}

func mergeWith(t *testing.T, opts Options, srcs ...string) result {
	t.Helper()
	var out bytes.Buffer
	sum, err := Write(&out, scanAll(t, srcs...), opts)
	if err != nil {
		t.Fatal(err)
	}
	return result{nt.ParseBytes(t, out.Bytes()), sum, out.String()}
}

func merge(t *testing.T, srcs ...string) result {
	t.Helper()
	return mergeWith(t, Options{ReportName: "Combined Report"}, srcs...)
}

func item(plugin, port, output string) string { return nt.Item(plugin, port, "tcp", "1", output) }

func want(plugin, port, output string) nt.ItemData {
	return nt.ItemData{Plugin: plugin, Port: port, Proto: "tcp", Severity: "1", Output: output}
}

func hostNames(d nt.Doc) []string {
	var names []string
	for _, h := range d.Hosts {
		names = append(names, h.Name)
	}
	return names
}

func TestDisjointHostsAreConcatenatedInFirstSeenOrder(t *testing.T) {
	r := merge(t,
		nt.File("primary policy", "scan A", nt.Host("h2", item("1", "22", "a")), nt.Host("h1", item("2", "80", "b"))),
		nt.File("other policy", "scan B", nt.Host("h3", item("3", "443", "c"))),
	)
	if got := hostNames(r.doc); !reflect.DeepEqual(got, []string{"h2", "h1", "h3"}) {
		t.Errorf("hosts = %v", got)
	}
	if r.doc.Policy != "primary policy" || strings.Contains(r.raw, "other policy") {
		t.Errorf("policy = %q; the header must come from the primary only", r.doc.Policy)
	}
	if r.doc.ReportName != "Combined Report" {
		t.Errorf("report name = %q", r.doc.ReportName)
	}
	if !reflect.DeepEqual(r.doc.Hosts[2].Items, []nt.ItemData{want("3", "443", "c")}) {
		t.Errorf("h3 items = %v", r.doc.Hosts[2].Items)
	}
	if !strings.HasSuffix(r.raw, "</Report>\n</NessusClientData_v2>\n") || strings.Count(r.raw, "</Report>") != 1 {
		t.Errorf("bad footer: %q", r.raw[len(r.raw)-60:])
	}
}

func TestOverlappingHostUnionsFindings(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h",
			item("19506", "0", "scan info A"),
			item("10", "22", "banner one"),
			item("10", "22", "banner one"), // duplicate inside the first occurrence: kept
		)),
		nt.File("p", "r", nt.Host("h",
			item("19506", "0", "scan info B"),             // scan info from a later occurrence: skipped
			item("10", "22", "  banner one\n"),            // same after trimming: dropped
			item("10", "22", "banner two"),                // same plugin and port, different output: kept
			item("10", "23", "banner one"),                // different port: kept
			nt.Item("10", "22", "udp", "1", "banner one"), // different protocol: kept
			item("11", "22", "banner one"),                // different plugin: kept
			item("11", "22", "banner one"),                // duplicate inside a later occurrence: dropped
		)),
	)
	wantItems := []nt.ItemData{
		want("19506", "0", "scan info A"),
		want("10", "22", "banner one"),
		want("10", "22", "banner one"),
		want("10", "22", "banner two"),
		want("10", "23", "banner one"),
		{Plugin: "10", Port: "22", Proto: "udp", Severity: "1", Output: "banner one"},
		want("11", "22", "banner one"),
	}
	if len(r.doc.Hosts) != 1 || !reflect.DeepEqual(r.doc.Hosts[0].Items, wantItems) {
		t.Errorf("items = %v\nwant    %v", r.doc.Hosts[0].Items, wantItems)
	}
	f0, f1 := r.sum.Files[0], r.sum.Files[1]
	if f0.NewHosts != 1 || f0.SeenHosts != 0 || f0.Findings != 3 || f0.Duplicates != 0 {
		t.Errorf("file 0 stats = %+v", f0)
	}
	if f1.NewHosts != 0 || f1.SeenHosts != 1 || f1.Findings != 4 || f1.Duplicates != 2 || f1.ScanInfoSkipped != 1 {
		t.Errorf("file 1 stats = %+v", f1)
	}
	if r.sum.Hosts != 1 || r.sum.Findings != 7 {
		t.Errorf("totals: hosts %d, findings %d", r.sum.Hosts, r.sum.Findings)
	}
}

func TestFindingKeyUsesDecodedOutputText(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h", item("1", "0", "a &lt; b &amp; c"))),
		nt.File("p", "r", nt.Host("h",
			item("1", "0", "<![CDATA[a < b & c]]>"), // same text, written differently: dropped
			item("1", "0", "a &lt; b"),              // different text: kept
		)),
	)
	if got := r.doc.Hosts[0].Items; len(got) != 2 || got[1].Output != "a < b" {
		t.Errorf("items = %v", got)
	}
}

func TestMissingPluginOutputCountsAsEmpty(t *testing.T) {
	bare := `<ReportItem port="0" protocol="tcp" severity="0" pluginID="5"/>` + "\n"
	r := merge(t,
		nt.File("p", "r", nt.Host("h", bare)),
		nt.File("p", "r", nt.Host("h", bare, item("5", "0", "   "), item("5", "0", "x"))),
	)
	if got := len(r.doc.Hosts[0].Items); got != 2 {
		t.Errorf("got %d items, want 2 (the bare one and the one with output x)", got)
	}
}

func TestOnlyFirstPluginOutputFeedsTheKey(t *testing.T) {
	two := func(first, second string) string {
		return `<ReportItem port="0" protocol="tcp" severity="0" pluginID="5"><plugin_output>` + first + `</plugin_output><plugin_output>` + second + `</plugin_output></ReportItem>` + "\n"
	}
	r := merge(t,
		nt.File("p", "r", nt.Host("h", two("same", "x"))),
		nt.File("p", "r", nt.Host("h", two("same", "y"), two("other", "x"))),
	)
	if got := strings.Count(r.raw, "<ReportItem"); got != 2 {
		t.Errorf("got %d items, want 2", got)
	}
}

func TestHostPropertiesUnion(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h",
			nt.Props(nt.Tag("HOST_END", "first"), nt.Tag("os", "linux"), "<tag>nameless one</tag>\n"),
			item("1", "0", "x"),
		)),
		nt.File("p", "r", nt.Host("h",
			nt.Props(nt.Tag("HOST_END", "second"), nt.Tag("netbios", "BOX"), "<tag>nameless two</tag>\n", "<note name=\"zzz\">not a tag</note>\n"),
		)),
		nt.File("p", "r", nt.Host("h",
			nt.Props(nt.Tag("netbios", "OTHER"), nt.Tag("mac", "aa:bb")),
		)),
	)
	wantTags := []nt.TagData{{Name: "HOST_END", Value: "first"}, {Name: "os", Value: "linux"}, {Name: "", Value: "nameless one"}, {Name: "netbios", Value: "BOX"}, {Name: "mac", Value: "aa:bb"}}
	if got := r.doc.Hosts[0].Tags; !reflect.DeepEqual(got, wantTags) {
		t.Errorf("tags = %v\nwant   %v", got, wantTags)
	}
	if strings.Count(r.raw, "<HostProperties>") != 1 || strings.Contains(r.raw, "zzz") {
		t.Errorf("want one HostProperties block and no foreign children:\n%s", r.raw)
	}
	if props, items := strings.Index(r.raw, "<HostProperties>"), strings.Index(r.raw, "<ReportItem"); props > items {
		t.Error("HostProperties must stay where the first occurrence had it (before the items)")
	}
}

func TestHostPropertiesComeFromLaterOccurrenceWhenFirstHasNone(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h", item("1", "0", "x"))),
		nt.File("p", "r", nt.Host("h", nt.Props(nt.Tag("os", "linux"), "<tag>nameless</tag>\n"))),
		nt.File("p", "r", nt.Host("h", nt.Props(nt.Tag("os", "windows"), nt.Tag("mac", "aa")))),
	)
	wantTags := []nt.TagData{{Name: "os", Value: "linux"}, {Name: "", Value: "nameless"}, {Name: "mac", Value: "aa"}}
	if got := r.doc.Hosts[0].Tags; !reflect.DeepEqual(got, wantTags) {
		t.Errorf("tags = %v, want %v", got, wantTags)
	}
	if props, items := strings.Index(r.raw, "<HostProperties>"), strings.Index(r.raw, "<ReportItem"); props < 0 || props > items {
		t.Error("inserted HostProperties must come before the items")
	}
}

func TestHostPropertiesEdgeCases(t *testing.T) {
	t.Run("none anywhere", func(t *testing.T) {
		r := merge(t, nt.File("p", "r", nt.Host("h", item("1", "0", "x"))), nt.File("p", "r", nt.Host("h", item("2", "0", "x"))))
		if strings.Contains(r.raw, "HostProperties") {
			t.Error("no HostProperties expected")
		}
	})
	t.Run("self-closing base gains tags", func(t *testing.T) {
		r := merge(t, nt.File("p", "r", nt.Host("h", "<HostProperties/>\n")), nt.File("p", "r", nt.Host("h", nt.Props(nt.Tag("os", "linux")))))
		if got := r.doc.Hosts[0].Tags; !reflect.DeepEqual(got, []nt.TagData{{Name: "os", Value: "linux"}}) {
			t.Errorf("tags = %v", got)
		}
	})
	t.Run("properties after items stay there", func(t *testing.T) {
		r := merge(t, nt.File("p", "r", nt.Host("h", item("1", "0", "x"), nt.Props(nt.Tag("a", "1")))), nt.File("p", "r", nt.Host("h", nt.Props(nt.Tag("b", "2")))))
		if got := r.doc.Hosts[0].Tags; !reflect.DeepEqual(got, []nt.TagData{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}) {
			t.Errorf("tags = %v", got)
		}
		if strings.Index(r.raw, "<HostProperties>") < strings.Index(r.raw, "<ReportItem") {
			t.Error("HostProperties moved")
		}
	})
}

func TestOtherChildrenComeFromFirstOccurrenceOnly(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h", "<Extra>first</Extra>\n", item("1", "0", "x"))),
		nt.File("p", "r", nt.Host("h", "<Extra>second</Extra>\n", item("2", "0", "x"))),
	)
	if !strings.Contains(r.raw, "<Extra>first</Extra>") || strings.Contains(r.raw, "second") {
		t.Errorf("got:\n%s", r.raw)
	}
}

func TestElementsAreCopiedByteForByte(t *testing.T) {
	odd := `<ReportItem  pluginID='77' port="0"	protocol="tcp" severity="3" pluginName="a &amp; b &#233; é">
  <cm:compliance-check-name>CIS &lt;1.1&gt;</cm:compliance-check-name>
  <plugin_output><![CDATA[raw <b> & stuff]]></plugin_output>
  <!-- a comment -->
</ReportItem>`
	for _, name := range []string{"first occurrence", "later occurrence"} {
		t.Run(name, func(t *testing.T) {
			a, b := nt.Host("h", odd+"\n"), nt.Host("h", item("1", "0", "x"))
			if name == "later occurrence" {
				a, b = b, a
			}
			r := merge(t, nt.File("p", "r", a), nt.File("p", "r", b))
			if !strings.Contains(r.raw, odd) {
				t.Errorf("item was not copied verbatim:\n%s", r.raw)
			}
		})
	}
}

func TestReportName(t *testing.T) {
	hosts := nt.Host("h", item("1", "0", "x"))
	cases := []struct {
		name, reportTag string
	}{
		{"double quoted", `<Report name="old" xmlns:cm="u">`},
		{"single quoted", `<Report xmlns:cm='u' name='old'>`},
		{"no name attribute", `<Report xmlns:cm="u">`},
		{"bare", `<Report>`},
	}
	const newName = `A & B <"it's">`
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "<NessusClientData_v2><Policy/>" + c.reportTag + "\n" + hosts + "</Report></NessusClientData_v2>"
			r := mergeWith(t, Options{ReportName: newName}, src)
			if r.doc.ReportName != newName {
				t.Errorf("report name = %q, want %q", r.doc.ReportName, newName)
			}
			if strings.Contains(r.raw, "old") || len(r.doc.Hosts) != 1 {
				t.Errorf("got:\n%s", r.raw)
			}
			if strings.Contains(c.reportTag, "xmlns:cm") && !strings.Contains(r.raw, "xmlns:cm=") {
				t.Error("other Report attributes must be kept")
			}
		})
	}
}

func TestPrimaryWithoutHosts(t *testing.T) {
	other := nt.File("p2", "r", nt.Host("h", item("1", "0", "x")))
	for name, primary := range map[string]string{
		"empty report":        nt.File("p1", "r"),
		"self-closing report": `<NessusClientData_v2><Policy><policyName>p1</policyName></Policy><Report name="r"/></NessusClientData_v2>`,
	} {
		t.Run(name, func(t *testing.T) {
			r := merge(t, primary, other)
			if r.doc.Policy != "p1" || !reflect.DeepEqual(hostNames(r.doc), []string{"h"}) || r.doc.ReportName != "Combined Report" {
				t.Errorf("policy %q, hosts %v, name %q\n%s", r.doc.Policy, hostNames(r.doc), r.doc.ReportName, r.raw)
			}
		})
	}
}

func TestSelfClosingHostGainsFindings(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", `<ReportHost name="h"/>`+"\n"),
		nt.File("p", "r", nt.Host("h", item("1", "0", "x"))),
	)
	if len(r.doc.Hosts) != 1 || len(r.doc.Hosts[0].Items) != 1 {
		t.Errorf("got %+v\n%s", r.doc.Hosts, r.raw)
	}
}

func TestSameHostTwiceInOneFileIsMerged(t *testing.T) {
	r := merge(t, nt.File("p", "r",
		nt.Host("h", item("1", "0", "x")),
		nt.Host("other", item("9", "0", "x")),
		nt.Host("h", item("1", "0", "x"), item("2", "0", "y")),
	))
	if !reflect.DeepEqual(hostNames(r.doc), []string{"h", "other"}) {
		t.Fatalf("hosts = %v", hostNames(r.doc))
	}
	if got := r.doc.Hosts[0].Items; !reflect.DeepEqual(got, []nt.ItemData{want("1", "0", "x"), want("2", "0", "y")}) {
		t.Errorf("items = %v", got)
	}
	if f := r.sum.Files[0]; f.NewHosts != 2 || f.SeenHosts != 1 || f.Duplicates != 1 {
		t.Errorf("stats = %+v", f)
	}
}

func TestByteOrderMarkIsNotCopied(t *testing.T) {
	r := merge(t, "\xef\xbb\xbf"+nt.File("p", "r", nt.Host("h", item("1", "0", "x"))))
	if !strings.HasPrefix(r.raw, "<?xml") {
		t.Errorf("output starts with %q", r.raw[:8])
	}
}

func TestSummaryCountsSeverityAndNamelessHosts(t *testing.T) {
	r := merge(t, nt.File("p", "r",
		nt.Host("", item("1", "0", "x")),
		nt.Host("h",
			nt.Item("1", "0", "tcp", "0", "a"), nt.Item("2", "0", "tcp", "4", "b"),
			nt.Item("3", "0", "tcp", "4", "c"), nt.Item("4", "0", "tcp", "", "d"),
		),
	))
	f := r.sum.Files[0]
	if f.BySeverity != [5]int{1, 0, 0, 0, 2} || f.UnknownSeverity != 1 || f.Findings != 4 || f.NamelessHosts != 1 {
		t.Errorf("stats = %+v", f)
	}
	if r.sum.Primary != f.Path || len(r.doc.Hosts) != 1 {
		t.Errorf("primary = %q, hosts = %d", r.sum.Primary, len(r.doc.Hosts))
	}
}

func TestDebugLogNamesOverlapsAndDroppedDuplicates(t *testing.T) {
	var log bytes.Buffer
	mergeWith(t, Options{ReportName: "r", Log: logx.New(&log, logx.Debug)},
		nt.File("p", "r", nt.Host("h", item("7", "22", "x"))),
		nt.File("p", "r", nt.Host("h", item("7", "22", "x"), item("19506", "0", "i"))),
	)
	for _, wantLine := range []string{`host "h" appears in 2 blocks`, "f0.nessus", `drop duplicate host="h" plugin=7 port=22/tcp`, `skip scan-info host="h"`} {
		if !strings.Contains(log.String(), wantLine) {
			t.Errorf("debug log lacks %q:\n%s", wantLine, log.String())
		}
	}
}

func TestChangedInputAborts(t *testing.T) {
	src := nt.File("p", "r", nt.Host("h", item("1", "0", "x")))
	t.Run("size", func(t *testing.T) {
		files := scanAll(t, src)
		if err := os.WriteFile(files[0].Path, []byte(src+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(&bytes.Buffer{}, files, Options{}); !errors.Is(err, ErrChanged) {
			t.Errorf("err = %v, want ErrChanged", err)
		}
	})
	t.Run("modification time", func(t *testing.T) {
		files := scanAll(t, src)
		later := files[0].ModTime.Add(time.Hour)
		if err := os.Chtimes(files[0].Path, later, later); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(&bytes.Buffer{}, files, Options{}); !errors.Is(err, ErrChanged) {
			t.Errorf("err = %v, want ErrChanged", err)
		}
	})
	t.Run("removed", func(t *testing.T) {
		files := scanAll(t, src)
		if err := os.Remove(files[0].Path); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(&bytes.Buffer{}, files, Options{}); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("err = %v, want not-exist", err)
		}
	})
}

func TestNoFilesIsAnError(t *testing.T) {
	if _, err := Write(&bytes.Buffer{}, nil, Options{}); err == nil {
		t.Error("want an error")
	}
}

type failingWriter struct{ left int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.left -= len(p); w.left < 0 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestWriteErrorIsReturned(t *testing.T) {
	files := scanAll(t, nt.File("p", "r", nt.Host("h", item("1", "0", "x"))))
	for _, limit := range []int{0, 60, 200, 400} {
		if _, err := Write(&failingWriter{left: limit}, files, Options{}); err == nil || !strings.Contains(err.Error(), "disk full") {
			t.Errorf("limit %d: err = %v, want disk full", limit, err)
		}
	}
}
