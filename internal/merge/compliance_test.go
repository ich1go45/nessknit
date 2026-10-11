package merge

import (
	"strings"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

// compliance builds a compliance finding as Nessus writes them: one
// shared plugin ID and port, no plugin_output, and the check identified
// by namespaced child elements.
func compliance(prefix, name, result string) string {
	return `<ReportItem pluginID="21156" port="0" protocol="tcp" severity="3">` +
		`<description>d</description>` +
		`<` + prefix + `:compliance-check-name> ` + name + ` </` + prefix + `:compliance-check-name>` +
		`<` + prefix + `:compliance-actual-value>whatever</` + prefix + `:compliance-actual-value>` +
		`<` + prefix + `:compliance-result>` + result + `</` + prefix + `:compliance-result>` +
		`</ReportItem>` + "\n"
}

// Compliance checks would all share one key if only the plugin, port,
// protocol and (absent) plugin output counted, and every check from a
// host's later files would be dropped.
func TestComplianceChecksAreToldApartByNameAndResult(t *testing.T) {
	const uri = ` xmlns:cm="http://www.nessus.org/cm" xmlns:ns0="http://www.nessus.org/cm"`
	raw := strictMerge(t,
		nsFile(uri, "", nt.Host("h",
			compliance("cm", "Password length", "PASSED"),
			compliance("cm", "Lockout threshold", "PASSED"),
		)),
		nsFile(uri, "", nt.Host("h",
			compliance("cm", "Password length", "PASSED"),    // same check, same result: dropped
			compliance("ns0", "Lockout threshold", "PASSED"), // same again under another prefix: dropped
			compliance("cm", "SMBv1 disabled", "FAILED"),     // new check: kept
			compliance("cm", "Password length", "FAILED"),    // same check, new result: kept
		)),
	)
	if got := strings.Count(raw, "<ReportItem"); got != 4 {
		t.Errorf("got %d findings, want 4\n%s", got, raw)
	}
	for _, want := range []string{"SMBv1 disabled", "FAILED</cm:compliance-result>"} {
		if !strings.Contains(raw, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(raw, "ns0:compliance-check-name") {
		t.Error("the duplicate under another prefix was kept")
	}
}

func TestComplianceKeyDoesNotChangeOrdinaryFindings(t *testing.T) {
	r := merge(t,
		nt.File("p", "r", nt.Host("h", item("21156", "0", "same output"))),
		nt.File("p", "r", nt.Host("h", item("21156", "0", "same output"), compliance("cm", "A check", "PASSED"))),
	)
	if got := len(r.doc.Hosts[0].Items); got != 2 {
		t.Errorf("got %d findings, want 2: the plain duplicate dropped, the compliance check kept", got)
	}
	if r.sum.Files[1].Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", r.sum.Files[1].Duplicates)
	}
}
