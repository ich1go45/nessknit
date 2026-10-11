package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
	"github.com/ich1go45/nessknit/internal/summary"
)

// binary is the nessknit executable built once for all tests here.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nessknit-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "nessknit")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building nessknit: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type outcome struct {
	code           int
	stdout, stderr string
}

// nessknit runs the built binary in dir.
func nessknit(t *testing.T, dir string, args ...string) outcome {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return outcome{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

func (o outcome) wantCode(t *testing.T, code int) {
	t.Helper()
	if o.code != code {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", o.code, code, o.stdout, o.stderr)
	}
}

func item(plugin, output string) string { return nt.Item(plugin, "0", "tcp", "2", output) }

const broken = "<NessusClientData_v2><Report name=\"r\"><ReportHost name=\"x\">"

// scans makes a directory holding a.nessus (hosts h1, h2) and b.nessus
// (hosts h1, h3). Merged, that is 3 hosts and 4 findings with one
// duplicate dropped.
func scans(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	nt.Write(t, dir, "a.nessus", nt.File("policy A", "scan A", nt.Host("h1", item("1", "x")), nt.Host("h2", item("2", "x"))))
	nt.Write(t, dir, "b.nessus", nt.File("policy B", "scan B", nt.Host("h1", item("1", "x"), item("3", "y")), nt.Host("h3", item("4", "x"))))
	return dir
}

func hostNames(d nt.Doc) []string {
	var names []string
	for _, h := range d.Hosts {
		names = append(names, h.Name)
	}
	return names
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestMergeDirectory(t *testing.T) {
	dir := scans(t)
	o := nessknit(t, dir)
	o.wantCode(t, 0)

	doc := nt.Parse(t, filepath.Join(dir, "Combined.nessus"))
	if !reflect.DeepEqual(hostNames(doc), []string{"h1", "h2", "h3"}) || doc.Policy != "policy A" || doc.ReportName != "Combined Report" {
		t.Errorf("hosts %v, policy %q, name %q", hostNames(doc), doc.Policy, doc.ReportName)
	}
	if len(doc.Hosts[0].Items) != 2 {
		t.Errorf("h1 has %d findings, want 2", len(doc.Hosts[0].Items))
	}
	for _, want := range []string{"Primary : a.nessus", "Output  : Combined.nessus", "Total\n  hosts    : 3\n  findings : 4 (critical 0, high 0, medium 4, low 0, info 0)\n  dropped  : 1 duplicate"} {
		if !strings.Contains(o.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, o.stdout)
		}
	}
	for _, want := range []string{"[*] found 2 input file(s)", "[*] primary: a.nessus", "[*] written: Combined.nessus"} {
		if !strings.Contains(o.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, o.stderr)
		}
	}
	if exists(filepath.Join(dir, "Combined.nessus.tmp")) {
		t.Error("temporary file left behind")
	}
}

func TestRerunDoesNotMergeItsOwnOutput(t *testing.T) {
	dir := scans(t)
	nessknit(t, dir).wantCode(t, 0)
	first, _ := os.ReadFile(filepath.Join(dir, "Combined.nessus"))
	o := nessknit(t, dir, "-o", filepath.Join(dir, "Combined.nessus"), dir)
	o.wantCode(t, 0)
	second, _ := os.ReadFile(filepath.Join(dir, "Combined.nessus"))
	if !bytes.Equal(first, second) || !strings.Contains(o.stderr, "found 2 input file(s)") {
		t.Errorf("second run differs or read its own output:\n%s", o.stderr)
	}
}

func TestExplicitFilesOrderOutputAndName(t *testing.T) {
	dir := scans(t)
	out := filepath.Join(t.TempDir(), "merged.nessus")
	o := nessknit(t, dir, "--output", out, "--name", `Q3 "internal" & DMZ`, "b.nessus", "a.nessus")
	o.wantCode(t, 0)
	doc := nt.Parse(t, out)
	if !reflect.DeepEqual(hostNames(doc), []string{"h1", "h3", "h2"}) || doc.Policy != "policy B" || doc.ReportName != `Q3 "internal" & DMZ` {
		t.Errorf("hosts %v, policy %q, name %q", hostNames(doc), doc.Policy, doc.ReportName)
	}
	if exists(filepath.Join(dir, "Combined.nessus")) {
		t.Error("default output written despite --output")
	}
}

func TestFlagsMayFollowPaths(t *testing.T) {
	dir := scans(t)
	o := nessknit(t, dir, "a.nessus", "-o", "x.nessus", "b.nessus", "--json", "-q")
	o.wantCode(t, 0)
	if !exists(filepath.Join(dir, "x.nessus")) || exists(filepath.Join(dir, "-o")) {
		t.Error("-o after a path was not treated as a flag")
	}
	if !strings.HasPrefix(o.stdout, "{") || o.stderr != "" {
		t.Errorf("stdout:\n%s\nstderr:\n%s", o.stdout, o.stderr)
	}
}

func TestJSONSummary(t *testing.T) {
	dir := scans(t)
	nt.Write(t, dir, "c.nessus", broken)
	o := nessknit(t, dir, "--json")
	o.wantCode(t, 3)
	var got struct {
		Primary  string `json:"primary"`
		Output   string `json:"output"`
		DryRun   bool   `json:"dry_run"`
		Hosts    int    `json:"hosts"`
		Findings int    `json:"findings"`
		Files    []struct {
			Path       string `json:"path"`
			NewHosts   int    `json:"new_hosts"`
			SeenHosts  int    `json:"seen_hosts"`
			Duplicates int    `json:"duplicates_dropped"`
			BySeverity []int  `json:"by_severity"`
		} `json:"files"`
		Skipped []struct{ Path, Reason string } `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(o.stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, o.stdout)
	}
	if got.Primary != "a.nessus" || got.Output != "Combined.nessus" || got.DryRun || got.Hosts != 3 || got.Findings != 4 {
		t.Errorf("top level: %+v", got)
	}
	if len(got.Files) != 2 || got.Files[1].NewHosts != 1 || got.Files[1].SeenHosts != 1 || got.Files[1].Duplicates != 1 || got.Files[1].BySeverity[2] != 2 {
		t.Errorf("files: %+v", got.Files)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Path != "c.nessus" || !strings.Contains(got.Skipped[0].Reason, "not well-formed") {
		t.Errorf("skipped: %+v", got.Skipped)
	}
}

func TestSkippedInputGivesExitCode3(t *testing.T) {
	dir := scans(t)
	nt.Write(t, dir, "c.nessus", broken)
	nt.Write(t, dir, "d.nessus", "<html/>")
	o := nessknit(t, dir)
	o.wantCode(t, 3)
	if got := hostNames(nt.Parse(t, filepath.Join(dir, "Combined.nessus"))); len(got) != 3 {
		t.Errorf("hosts = %v", got)
	}
	for _, want := range []string{"[!] skipping c.nessus: not well-formed XML", "[!] skipping d.nessus: root element is <html>"} {
		if !strings.Contains(o.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, o.stderr)
		}
	}
	if !strings.Contains(o.stdout, "Skipped (2)\n  c.nessus: not well-formed XML") {
		t.Errorf("stdout:\n%s", o.stdout)
	}
}

func TestNextUsableFileBecomesPrimary(t *testing.T) {
	dir := scans(t)
	nt.Write(t, dir, "0.nessus", broken)
	o := nessknit(t, dir)
	o.wantCode(t, 3)
	if doc := nt.Parse(t, filepath.Join(dir, "Combined.nessus")); doc.Policy != "policy A" {
		t.Errorf("policy = %q, want the first usable file's", doc.Policy)
	}
	if !strings.Contains(o.stdout, "Primary : a.nessus") {
		t.Errorf("stdout:\n%s", o.stdout)
	}
}

func TestFailuresWriteNothingAndKeepExistingOutput(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, dir string) []string
		stderr string
	}{
		{"no nessus files", func(t *testing.T, dir string) []string {
			nt.Write(t, dir, "notes.txt", "x")
			return nil
		}, "no .nessus files found"},
		{"missing path", func(t *testing.T, dir string) []string {
			return []string{"absent-dir"}
		}, "absent-dir"},
		{"every input unusable", func(t *testing.T, dir string) []string {
			nt.Write(t, dir, "a.nessus", broken)
			nt.Write(t, dir, "b.nessus", "")
			return nil
		}, "none of the 2 input file(s) could be used"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			nt.Write(t, dir, "Combined.nessus", "previous output")
			o := nessknit(t, dir, c.setup(t, dir)...)
			o.wantCode(t, 1)
			if !strings.Contains(o.stderr, c.stderr) || !strings.Contains(o.stderr, "nothing written") {
				t.Errorf("stderr:\n%s", o.stderr)
			}
			if got, _ := os.ReadFile(filepath.Join(dir, "Combined.nessus")); string(got) != "previous output" {
				t.Errorf("existing output was changed to %q", got)
			}
			if exists(filepath.Join(dir, "Combined.nessus.tmp")) {
				t.Error("temporary file left behind")
			}
			if o.stdout != "" {
				t.Errorf("stdout should be empty:\n%s", o.stdout)
			}
		})
	}
}

func TestUnwritableOutputFails(t *testing.T) {
	dir := scans(t)
	o := nessknit(t, dir, "-o", filepath.Join(dir, "no-such-dir", "out.nessus"))
	o.wantCode(t, 1)
	if !strings.Contains(o.stderr, "no-such-dir") || !strings.Contains(o.stderr, "nothing written") {
		t.Errorf("stderr:\n%s", o.stderr)
	}
}

func TestExistingOutputIsOverwritten(t *testing.T) {
	dir := scans(t)
	nt.Write(t, dir, "Combined.nessus", "previous output")
	nessknit(t, dir).wantCode(t, 0)
	if got := hostNames(nt.Parse(t, filepath.Join(dir, "Combined.nessus"))); len(got) != 3 {
		t.Errorf("hosts = %v", got)
	}
}

func TestUsageErrors(t *testing.T) {
	dir := scans(t)
	for name, args := range map[string][]string{
		"unknown flag":       {"--frobnicate"},
		"quiet with debug":   {"-q", "-d"},
		"flag without value": {"-o"},
		"empty output":       {"-o", ""},
	} {
		t.Run(name, func(t *testing.T) {
			o := nessknit(t, dir, args...)
			o.wantCode(t, 2)
			if !strings.Contains(o.stderr, "nessknit: ") || !strings.Contains(o.stderr, "--help") || o.stdout != "" {
				t.Errorf("stdout:\n%s\nstderr:\n%s", o.stdout, o.stderr)
			}
			if exists(filepath.Join(dir, "Combined.nessus")) {
				t.Error("output written despite a usage error")
			}
		})
	}
}

func TestHelpAndVersion(t *testing.T) {
	dir := t.TempDir()
	for _, flag := range []string{"-h", "--help"} {
		o := nessknit(t, dir, flag)
		o.wantCode(t, 0)
		for _, want := range []string{"Usage:", "--output", "--dry-run", "--json", "--quiet", "--debug", "--name", "Exit codes:"} {
			if !strings.Contains(o.stdout, want) {
				t.Errorf("%s: help lacks %q", flag, want)
			}
		}
	}
	o := nessknit(t, dir, "--version")
	o.wantCode(t, 0)
	if !strings.HasPrefix(o.stdout, "nessknit ") || len(strings.TrimSpace(o.stdout)) <= len("nessknit") {
		t.Errorf("version output = %q", o.stdout)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	dir := scans(t)
	o := nessknit(t, dir, "--dry-run")
	o.wantCode(t, 0)
	if exists(filepath.Join(dir, "Combined.nessus")) || exists(filepath.Join(dir, "Combined.nessus.tmp")) {
		t.Error("dry run wrote a file")
	}
	if !strings.Contains(o.stdout, "Output  : (dry run, nothing written)") || !strings.Contains(o.stdout, "hosts    : 3") {
		t.Errorf("stdout:\n%s", o.stdout)
	}
}

func TestQuietAndDebug(t *testing.T) {
	dir := scans(t)
	nt.Write(t, dir, "c.nessus", broken)

	q := nessknit(t, dir, "-q")
	q.wantCode(t, 3)
	if strings.Contains(q.stderr, "[*]") || !strings.Contains(q.stderr, "[!] skipping c.nessus") || !strings.Contains(q.stdout, "Total") {
		t.Errorf("quiet must drop progress but keep warnings and the summary\nstdout:\n%s\nstderr:\n%s", q.stdout, q.stderr)
	}

	d := nessknit(t, dir, "--debug")
	d.wantCode(t, 3)
	for _, want := range []string{"[debug] index pass took", "[debug] write pass took", `[debug] host "h1" appears in 2 blocks: a.nessus, b.nessus`, `[debug] drop duplicate host="h1" plugin=1`, "[debug] memory obtained from the system"} {
		if !strings.Contains(d.stderr, want) {
			t.Errorf("debug output lacks %q:\n%s", want, d.stderr)
		}
	}
	if strings.Contains(d.stdout, "[debug]") {
		t.Error("debug output must go to stderr")
	}
}

func TestNamelessHostIsSkippedWithWarning(t *testing.T) {
	dir := t.TempDir()
	nt.Write(t, dir, "a.nessus", nt.File("p", "r", nt.Host("", item("1", "x")), nt.Host("h", item("2", "x"))))
	o := nessknit(t, dir)
	o.wantCode(t, 0)
	if !strings.Contains(o.stderr, "[!] a.nessus: skipped 1 ReportHost element(s) with no name") || !strings.Contains(o.stdout, "nameless : 1 host(s) skipped") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", o.stdout, o.stderr)
	}
	if got := hostNames(nt.Parse(t, filepath.Join(dir, "Combined.nessus"))); !reflect.DeepEqual(got, []string{"h"}) {
		t.Errorf("hosts = %v", got)
	}
}

func summaryWith(hosts, findings int) *summary.Summary {
	return &summary.Summary{Hosts: hosts, Findings: findings}
}

func TestVerifyCatchesWrongCounts(t *testing.T) {
	dir := scans(t)
	nessknit(t, dir).wantCode(t, 0)
	out := filepath.Join(dir, "Combined.nessus")
	for name, sum := range map[string][2]int{"hosts": {2, 4}, "findings": {3, 5}} {
		err := verify(out, summaryWith(sum[0], sum[1]))
		if err == nil || !strings.Contains(err.Error(), "output check failed: file holds 3 host(s) and 4 finding(s)") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := verify(out, summaryWith(3, 4)); err != nil {
		t.Errorf("correct counts: %v", err)
	}
	if err := verify(nt.Write(t, dir, "bad.xml", broken), summaryWith(0, 0)); err == nil || !strings.Contains(err.Error(), "output check failed: not well-formed") {
		t.Errorf("malformed: err = %v", err)
	}
}
