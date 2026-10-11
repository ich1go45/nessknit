package merge

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ich1go45/nessknit/internal/index"
	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

const cmURI = "http://www.nessus.org/cm"

// nsFile builds a file whose root and Report tags carry the given
// attribute text, so each test controls where prefixes are declared.
func nsFile(rootAttrs, reportAttrs string, hosts ...string) string {
	return "<NessusClientData_v2" + rootAttrs + "><Policy/>\n<Report name=\"r\"" + reportAttrs + ">\n" +
		strings.Join(hosts, "") + "</Report>\n</NessusClientData_v2>\n"
}

func check(prefix, plugin string) string {
	return `<ReportItem pluginID="` + plugin + `" port="0" protocol="tcp" severity="3"><` + prefix + `:compliance-check-name>Check ` + plugin + `</` + prefix + `:compliance-check-name></ReportItem>` + "\n"
}

// strictMerge merges and then runs the result through index.Scan, which
// rejects undeclared prefixes. It returns the raw output.
func strictMerge(t *testing.T, srcs ...string) string {
	t.Helper()
	var out bytes.Buffer
	if _, err := Write(&out, scanAll(t, srcs...), Options{ReportName: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, err := index.Scan(nt.Write(t, t.TempDir(), "out.nessus", out.String())); err != nil {
		t.Fatalf("merged output is not well-formed: %v\n%s", err, out.String())
	}
	return out.String()
}

// A file written by the old Python script declares the compliance
// namespace as ns0 on the root; Nessus declares it as cm on Report.
func TestNamespaceDeclarationsFollowTheirElements(t *testing.T) {
	python := nsFile(` xmlns:ns0="`+cmURI+`"`, "", nt.Host("h1", check("ns0", "1")))
	nessus := nsFile("", ` xmlns:cm="`+cmURI+`"`, nt.Host("h2", check("cm", "2")), nt.Host("h1", check("cm", "3")))

	t.Run("python output first", func(t *testing.T) {
		raw := strictMerge(t, python, nessus)
		for _, want := range []string{
			`<ReportHost name="h1" xmlns:cm="` + cmURI + `">`, // a later occurrence brought cm: items
			`<ReportHost name="h2" xmlns:cm="` + cmURI + `">`,
		} {
			if !strings.Contains(raw, want) {
				t.Errorf("output lacks %s\n%s", want, raw)
			}
		}
	})
	t.Run("nessus file first", func(t *testing.T) {
		raw := strictMerge(t, nessus, python)
		if !strings.Contains(raw, `<ReportHost name="h1" xmlns:ns0="`+cmURI+`">`) {
			t.Errorf("h1 must declare ns0 for the items from the second file\n%s", raw)
		}
		if !strings.Contains(raw, `<ReportHost name="h2">`) {
			t.Errorf("h2 needs no extra declaration: the header already has cm\n%s", raw)
		}
	})
	t.Run("primary declares nothing", func(t *testing.T) {
		raw := strictMerge(t, nsFile("", "", nt.Host("h0")), nessus)
		if strings.Contains(raw, `<ReportHost name="h0" `) || !strings.Contains(raw, `<ReportHost name="h2" xmlns:cm=`) {
			t.Errorf("only hosts from the declaring file get the declaration\n%s", raw)
		}
	})
}

func TestSelfClosingHostStillGetsDeclarations(t *testing.T) {
	raw := strictMerge(t,
		nsFile("", "", `<ReportHost name="h"/>`+"\n"),
		nsFile("", ` xmlns:cm="`+cmURI+`"`, nt.Host("h", check("cm", "1"))),
	)
	if !strings.Contains(raw, `<ReportHost name="h" xmlns:cm="`+cmURI+`">`) {
		t.Errorf("got:\n%s", raw)
	}
}

func TestHostKeepsItsOwnFilesBindingWhenThePrimaryDiffers(t *testing.T) {
	raw := strictMerge(t,
		nsFile("", ` xmlns:cm="urn:one"`, nt.Host("h1", check("cm", "1"))),
		nsFile("", ` xmlns:cm="urn:two&amp;more"`, nt.Host("h2", check("cm", "2"))),
	)
	if !strings.Contains(raw, `<ReportHost name="h1">`) || !strings.Contains(raw, `<ReportHost name="h2" xmlns:cm="urn:two&amp;more">`) {
		t.Errorf("h2 must rebind cm to its own file's URI, escaped\n%s", raw)
	}
}

func TestDefaultNamespaceIsCarriedOrCancelled(t *testing.T) {
	withDefault := nsFile(` xmlns="urn:default"`, "", nt.Host("h1", item("1", "0", "x")))
	without := nsFile("", "", nt.Host("h2", item("2", "0", "x")))

	if raw := strictMerge(t, withDefault, without); !strings.Contains(raw, `<ReportHost name="h2" xmlns="">`) {
		t.Errorf("h2 had no default namespace and must not inherit the primary's\n%s", raw)
	}
	if raw := strictMerge(t, without, withDefault); !strings.Contains(raw, `<ReportHost name="h1" xmlns="urn:default">`) {
		t.Errorf("h1 must keep its default namespace\n%s", raw)
	}
}

// One host tag cannot bind a prefix to two URIs, so this merge has no
// correct output and must fail rather than write a wrong one.
func TestConflictingBindingsWithinOneHostAbort(t *testing.T) {
	files := scanAll(t,
		nsFile("", ` xmlns:cm="urn:one"`, nt.Host("h", check("cm", "1"))),
		nsFile("", ` xmlns:cm="urn:two"`, nt.Host("h", check("cm", "2"))),
	)
	_, err := Write(&bytes.Buffer{}, files, Options{})
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{`host "h"`, `prefix "cm"`, "urn:one", "urn:two", "f1.nessus"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}
