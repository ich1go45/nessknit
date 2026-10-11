package inputs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func touch(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func resolve(t *testing.T, output string, paths ...string) []string {
	t.Helper()
	got, err := Resolve(paths, output)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func join(dir string, names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = filepath.Join(dir, n)
	}
	return out
}

func TestDirectoryIsSortedFilteredAndNotRecursive(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "b.nessus", "a.nessus", "C.NESSUS", "notes.txt", "x.nessus.bak")
	if err := os.MkdirAll(filepath.Join(dir, "sub.nessus"), 0o755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(dir, "sub.nessus"), "deep.nessus")

	got := resolve(t, filepath.Join(dir, "out.nessus"), dir)
	want := join(dir, "C.NESSUS", "a.nessus", "b.nessus")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPathsKeepTheOrderGiven(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	touch(t, d1, "z.nessus", "y.nessus")
	touch(t, d2, "a.nessus", "scan.xml")

	got := resolve(t, "out.nessus", filepath.Join(d1, "z.nessus"), d2, filepath.Join(d2, "scan.xml"), d1)
	want := append(join(d1, "z.nessus"), append(join(d2, "a.nessus", "scan.xml"), join(d1, "y.nessus")...)...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestNoPathsMeansCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "a.nessus")
	t.Chdir(dir)
	got := resolve(t, "Combined.nessus")
	if !reflect.DeepEqual(got, []string{"a.nessus"}) {
		t.Errorf("got %v", got)
	}
}

func TestOutputFileIsExcluded(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "a.nessus", "Combined.nessus")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skip("symlinks not available:", err)
	}
	t.Chdir(dir)
	want := join(dir, "a.nessus")

	for name, output := range map[string]string{
		"relative": "Combined.nessus",
		"absolute": filepath.Join(dir, "Combined.nessus"),
		"dotted":   filepath.Join(dir, ".", "sub", "..", "Combined.nessus"),
		"symlink":  filepath.Join(link, "Combined.nessus"),
	} {
		if got := resolve(t, output, dir); !reflect.DeepEqual(got, want) {
			t.Errorf("%s output: got %v, want %v", name, got, want)
		}
	}
	// Also when the output is named explicitly as an input.
	if got := resolve(t, "Combined.nessus", filepath.Join(dir, "Combined.nessus"), dir); !reflect.DeepEqual(got, want) {
		t.Errorf("explicit: got %v, want %v", got, want)
	}
}

func TestOutputThatDoesNotExistYetIsHarmless(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "a.nessus")
	got := resolve(t, filepath.Join(dir, "new", "out.nessus"), dir)
	if !reflect.DeepEqual(got, join(dir, "a.nessus")) {
		t.Errorf("got %v", got)
	}
}

func TestSameFileGivenTwiceIsListedOnce(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "a.nessus", "b.nessus")
	first := filepath.Join(dir, "b.nessus")
	got := resolve(t, "out.nessus", first, dir, filepath.Join(dir, ".", "a.nessus"))
	want := []string{first, filepath.Join(dir, "a.nessus")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMissingPathIsAnError(t *testing.T) {
	_, err := Resolve([]string{filepath.Join(t.TempDir(), "absent")}, "out.nessus")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want not-exist", err)
	}
}

func TestNothingFound(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "notes.txt", "Combined.nessus")
	_, err := Resolve([]string{dir}, filepath.Join(dir, "Combined.nessus"))
	if !errors.Is(err, ErrNoInputs) {
		t.Errorf("err = %v, want ErrNoInputs", err)
	}
}
