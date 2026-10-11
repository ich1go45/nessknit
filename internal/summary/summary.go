// Package summary holds the counts from one merge and renders them.
package summary

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FileStats counts what one input file contributed.
type FileStats struct {
	Path            string `json:"path"`
	NewHosts        int    `json:"new_hosts"`
	SeenHosts       int    `json:"seen_hosts"`
	Findings        int    `json:"findings"`
	BySeverity      [5]int `json:"by_severity"` // index 0 (info) to 4 (critical)
	UnknownSeverity int    `json:"unknown_severity"`
	Duplicates      int    `json:"duplicates_dropped"`
	ScanInfoSkipped int    `json:"scan_info_skipped"`
	NamelessHosts   int    `json:"nameless_hosts_skipped"`
}

// CountFinding records one written finding with the given severity
// attribute value.
func (f *FileStats) CountFinding(severity string) {
	f.Findings++
	if len(severity) == 1 && severity[0] >= '0' && severity[0] <= '4' {
		f.BySeverity[severity[0]-'0']++
	} else {
		f.UnknownSeverity++
	}
}

// Skipped names an input that was not merged, and why.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Summary is the result of one run.
type Summary struct {
	Primary  string      `json:"primary"`
	Output   string      `json:"output"`
	DryRun   bool        `json:"dry_run"`
	Hosts    int         `json:"hosts"`
	Findings int         `json:"findings"`
	Files    []FileStats `json:"files"`
	Skipped  []Skipped   `json:"skipped"`
}

// Totals adds up the per-file counts.
func (s *Summary) Totals() FileStats {
	var t FileStats
	for _, f := range s.Files {
		t.NewHosts += f.NewHosts
		t.SeenHosts += f.SeenHosts
		t.Findings += f.Findings
		for i, n := range f.BySeverity {
			t.BySeverity[i] += n
		}
		t.UnknownSeverity += f.UnknownSeverity
		t.Duplicates += f.Duplicates
		t.ScanInfoSkipped += f.ScanInfoSkipped
		t.NamelessHosts += f.NamelessHosts
	}
	return t
}

// WriteJSON writes the summary as one indented JSON object. Empty
// lists are written as [] rather than null.
func (s *Summary) WriteJSON(w io.Writer) error {
	out := *s
	if out.Files == nil {
		out.Files = []FileStats{}
	}
	if out.Skipped == nil {
		out.Skipped = []Skipped{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteText writes the summary for a person to read.
func (s *Summary) WriteText(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Primary : %s\n", s.Primary)
	if s.DryRun {
		b.WriteString("Output  : (dry run, nothing written)\n")
	} else {
		fmt.Fprintf(&b, "Output  : %s\n", s.Output)
	}
	for _, f := range s.Files {
		fmt.Fprintf(&b, "\n%s\n", f.Path)
		fmt.Fprintf(&b, "  hosts    : %d new, %d already seen\n", f.NewHosts, f.SeenHosts)
		writeCounts(&b, f)
	}
	if len(s.Skipped) > 0 {
		fmt.Fprintf(&b, "\nSkipped (%d)\n", len(s.Skipped))
		for _, k := range s.Skipped {
			fmt.Fprintf(&b, "  %s: %s\n", k.Path, k.Reason)
		}
	}
	b.WriteString("\nTotal\n")
	fmt.Fprintf(&b, "  hosts    : %d\n", s.Hosts)
	writeCounts(&b, s.Totals())
	_, err := io.WriteString(w, b.String())
	return err
}

func writeCounts(b *strings.Builder, f FileStats) {
	sev := f.BySeverity
	fmt.Fprintf(b, "  findings : %d (critical %d, high %d, medium %d, low %d, info %d",
		f.Findings, sev[4], sev[3], sev[2], sev[1], sev[0])
	if f.UnknownSeverity > 0 {
		fmt.Fprintf(b, ", unknown %d", f.UnknownSeverity)
	}
	b.WriteString(")\n")
	fmt.Fprintf(b, "  dropped  : %d duplicate, %d scan-info\n", f.Duplicates, f.ScanInfoSkipped)
	if f.NamelessHosts > 0 {
		fmt.Fprintf(b, "  nameless : %d host(s) skipped\n", f.NamelessHosts)
	}
}
