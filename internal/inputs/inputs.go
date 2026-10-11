// Package inputs turns command-line paths into the ordered list of
// .nessus files to merge.
package inputs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoInputs is returned when the paths yield no file to merge.
var ErrNoInputs = errors.New("no .nessus files found")

// Resolve expands paths into files, in the order given. A directory
// contributes the .nessus files directly inside it, sorted by name. A
// file path is taken as it is, whatever its extension. With no paths,
// the current directory is used.
//
// The output file is left out, and a file reached twice is listed
// once. Both checks compare resolved absolute paths with symlinks
// followed. A path that does not exist is an error.
func Resolve(paths []string, output string) ([]string, error) {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	seen := map[string]bool{canonical(output): true}
	var files []string
	add := func(p string) {
		if c := canonical(p); !seen[c] {
			seen[c] = true
			files = append(files, p)
		}
	}
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			add(p)
			continue
		}
		entries, err := os.ReadDir(p) // sorted by file name
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.EqualFold(filepath.Ext(e.Name()), ".nessus") {
				full := filepath.Join(p, e.Name())
				if st, err := os.Stat(full); err == nil && !st.IsDir() {
					add(full)
				}
			}
		}
	}
	if len(files) == 0 {
		return nil, ErrNoInputs
	}
	return files, nil
}

// canonical returns an absolute path with symlinks resolved. If the
// file does not exist yet, its directory is resolved instead.
func canonical(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(dir, filepath.Base(abs))
	}
	return abs
}
