package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	nt "github.com/ich1go45/nessknit/internal/nessustest"
)

// nessknit must merge exactly as the Python script it replaces: the
// same hosts in the same order, each with the same properties and the
// same findings. The fixtures avoid the behaviours the design changed
// on purpose (a broken first file, hash collisions).
func TestParityWithPythonScript(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not found")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "testdata", "reference", "nessus_merger_v4.py")
	fixtures, err := filepath.Glob(filepath.Join(root, "testdata", "parity", "*.nessus"))
	if err != nil || len(fixtures) < 3 {
		t.Fatalf("fixtures: %v, %v", fixtures, err)
	}

	// Each tool gets its own copy of the fixtures, because the Python
	// script writes its output into the directory it reads.
	pyDir, goDir := t.TempDir(), t.TempDir()
	for _, f := range fixtures {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		nt.Write(t, pyDir, filepath.Base(f), string(data))
		nt.Write(t, goDir, filepath.Base(f), string(data))
	}

	if out, err := exec.Command(python, script, "Combined.nessus", pyDir).CombinedOutput(); err != nil {
		t.Fatalf("python script failed: %v\n%s", err, out)
	}
	nessknit(t, goDir).wantCode(t, 0)

	want := nt.Parse(t, filepath.Join(pyDir, "Combined.nessus"))
	got := nt.Parse(t, filepath.Join(goDir, "Combined.nessus"))

	if got.Policy != want.Policy || got.ReportName != want.ReportName {
		t.Errorf("policy %q / report %q, want %q / %q", got.Policy, got.ReportName, want.Policy, want.ReportName)
	}
	if len(got.Hosts) != len(want.Hosts) {
		t.Fatalf("%d hosts, want %d", len(got.Hosts), len(want.Hosts))
	}
	if len(want.Hosts) != 4 {
		t.Fatalf("the fixtures should merge to 4 hosts, the Python script gave %d", len(want.Hosts))
	}
	for i, w := range want.Hosts {
		g := got.Hosts[i]
		if g.Name != w.Name {
			t.Errorf("host %d is %q, want %q", i, g.Name, w.Name)
			continue
		}
		if !reflect.DeepEqual(g.Tags, w.Tags) {
			t.Errorf("%s properties:\n got %v\nwant %v", w.Name, g.Tags, w.Tags)
		}
		if !reflect.DeepEqual(g.Items, w.Items) {
			t.Errorf("%s findings:\n got %v\nwant %v", w.Name, g.Items, w.Items)
		}
	}
}
