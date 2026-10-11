package summary

import (
	"bytes"
	"encoding/json"
	"testing"
)

func sample() *Summary {
	s := &Summary{
		Primary: "a.nessus", Output: "Combined.nessus", Hosts: 3, Findings: 7,
		Files: []FileStats{
			{Path: "a.nessus", NewHosts: 2},
			{Path: "b.nessus", NewHosts: 1, SeenHosts: 1, Duplicates: 2, ScanInfoSkipped: 1, NamelessHosts: 1},
		},
		Skipped: []Skipped{{Path: "bad.nessus", Reason: "no <Report> element"}},
	}
	for _, sev := range []string{"0", "0", "0", "2", "4"} {
		s.Files[0].CountFinding(sev)
	}
	for _, sev := range []string{"3", ""} {
		s.Files[1].CountFinding(sev)
	}
	return s
}

func TestCountFinding(t *testing.T) {
	var f FileStats
	for _, sev := range []string{"0", "1", "2", "3", "4", "4", "5", "", "x", "10"} {
		f.CountFinding(sev)
	}
	if f.Findings != 10 || f.BySeverity != [5]int{1, 1, 1, 1, 2} || f.UnknownSeverity != 4 {
		t.Errorf("got %+v", f)
	}
}

func TestTotals(t *testing.T) {
	got := sample().Totals()
	want := FileStats{
		NewHosts: 3, SeenHosts: 1, Findings: 7, BySeverity: [5]int{3, 0, 1, 1, 1},
		UnknownSeverity: 1, Duplicates: 2, ScanInfoSkipped: 1, NamelessHosts: 1,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	want := `Primary : a.nessus
Output  : Combined.nessus

a.nessus
  hosts    : 2 new, 0 already seen
  findings : 5 (critical 1, high 0, medium 1, low 0, info 3)
  dropped  : 0 duplicate, 0 scan-info

b.nessus
  hosts    : 1 new, 1 already seen
  findings : 2 (critical 0, high 1, medium 0, low 0, info 0, unknown 1)
  dropped  : 2 duplicate, 1 scan-info
  nameless : 1 host(s) skipped

Skipped (1)
  bad.nessus: no <Report> element

Total
  hosts    : 3
  findings : 7 (critical 1, high 1, medium 1, low 0, info 3, unknown 1)
  dropped  : 2 duplicate, 1 scan-info
  nameless : 1 host(s) skipped
`
	if buf.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteTextDryRun(t *testing.T) {
	s := sample()
	s.DryRun = true
	var buf bytes.Buffer
	if err := s.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Output  : (dry run, nothing written)\n")) || bytes.Contains(buf.Bytes(), []byte("Combined.nessus")) {
		t.Errorf("got:\n%s", buf.String())
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["primary"] != "a.nessus" || got["output"] != "Combined.nessus" || got["dry_run"] != false || got["hosts"] != 3.0 || got["findings"] != 7.0 {
		t.Errorf("top level: %v", got)
	}
	file := got["files"].([]any)[1].(map[string]any)
	for key, want := range map[string]any{
		"path": "b.nessus", "new_hosts": 1.0, "seen_hosts": 1.0, "findings": 2.0, "unknown_severity": 1.0,
		"duplicates_dropped": 2.0, "scan_info_skipped": 1.0, "nameless_hosts_skipped": 1.0,
	} {
		if file[key] != want {
			t.Errorf("files[1].%s = %v, want %v", key, file[key], want)
		}
	}
	if sev := file["by_severity"].([]any); len(sev) != 5 || sev[3] != 1.0 {
		t.Errorf("by_severity = %v", sev)
	}
	skipped := got["skipped"].([]any)[0].(map[string]any)
	if skipped["path"] != "bad.nessus" || skipped["reason"] != "no <Report> element" {
		t.Errorf("skipped = %v", skipped)
	}
}

func TestWriteJSONUsesEmptyListsNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := (&Summary{}).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("null")) {
		t.Errorf("got %s", buf.String())
	}
}
