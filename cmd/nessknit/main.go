// Command nessknit merges Nessus scan exports (.nessus files) into one.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/ich1go45/nessknit/internal/index"
	"github.com/ich1go45/nessknit/internal/inputs"
	"github.com/ich1go45/nessknit/internal/logx"
	"github.com/ich1go45/nessknit/internal/merge"
	"github.com/ich1go45/nessknit/internal/summary"
)

const (
	exitOK      = 0
	exitFailed  = 1 // nothing written
	exitUsage   = 2
	exitSkipped = 3 // written, but at least one input was skipped
)

const usage = `nessknit merges Nessus scan exports (.nessus files) into one.

Usage:
  nessknit [flags] <path>...

Each path is a .nessus file or a directory of them (not searched
recursively). Files are merged in the order given; the first usable
one supplies the scan policy. With no path, the current directory is
used.

Flags:
  -o, --output FILE   output file (default "Combined.nessus")
      --name NAME     report name in the merged file (default "Combined Report")
      --dry-run       run the merge and print the summary, write nothing
      --json          print the summary as JSON
  -q, --quiet         suppress progress output
  -d, --debug         print detailed diagnostics
      --version       print the version
  -h, --help          print this help

Exit codes:
  0  merged cleanly
  1  failed, nothing written
  2  bad usage
  3  merged and written, but at least one input file was skipped
`

type options struct {
	output  string
	name    string
	dryRun  bool
	json    bool
	quiet   bool
	debug   bool
	version bool
	paths   []string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// parseArgs reads flags and paths. Flags may come before, between or
// after the paths.
func parseArgs(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("nessknit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	for _, name := range []string{"o", "output"} {
		fs.StringVar(&o.output, name, "Combined.nessus", "")
	}
	fs.StringVar(&o.name, "name", "Combined Report", "")
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.BoolVar(&o.json, "json", false, "")
	for _, name := range []string{"q", "quiet"} {
		fs.BoolVar(&o.quiet, name, false, "")
	}
	for _, name := range []string{"d", "debug"} {
		fs.BoolVar(&o.debug, name, false, "")
	}
	fs.BoolVar(&o.version, "version", false, "")

	// The flag package stops at the first non-flag argument, so take
	// one path at a time and resume parsing after it.
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			return o, err
		}
		if fs.NArg() == 0 {
			break
		}
		o.paths = append(o.paths, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if o.quiet && o.debug {
		return o, errors.New("--quiet and --debug cannot be used together")
	}
	if o.output == "" {
		return o, errors.New("--output needs a file name")
	}
	return o, nil
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "nessknit: %v\nRun 'nessknit --help' for usage.\n", err)
		return exitUsage
	}
	if o.version {
		fmt.Fprintf(stdout, "nessknit %s\n", version())
		return exitOK
	}

	level := logx.Normal
	if o.quiet {
		level = logx.Quiet
	} else if o.debug {
		level = logx.Debug
	}
	log := logx.New(stderr, level)
	fail := func(format string, a ...any) int {
		log.Warnf(format, a...)
		log.Warnf("nothing written")
		return exitFailed
	}

	paths, err := inputs.Resolve(o.paths, o.output)
	if err != nil {
		return fail("%v", err)
	}
	log.Infof("found %d input file(s)", len(paths))

	// Pass 1: index every file.
	started := time.Now()
	var files []*index.File
	var skipped []summary.Skipped
	for _, p := range paths {
		f, err := index.Scan(p)
		if err != nil {
			log.Warnf("skipping %s: %v", p, err)
			skipped = append(skipped, summary.Skipped{Path: p, Reason: err.Error()})
			continue
		}
		log.Infof("indexed %s: %d host(s)", p, len(f.Hosts))
		log.Debugf("%s: %d bytes, header ends at byte %d", p, f.Size, f.HeaderEnd)
		if f.Nameless > 0 {
			log.Warnf("%s: skipped %d ReportHost element(s) with no name", p, f.Nameless)
		}
		files = append(files, f)
	}
	log.Debugf("index pass took %s", time.Since(started).Round(time.Millisecond))
	if len(files) == 0 {
		return fail("none of the %d input file(s) could be used", len(paths))
	}
	log.Infof("primary: %s", files[0].Path)

	// Pass 2: write the merged file.
	started = time.Now()
	opts := merge.Options{ReportName: o.name, Log: log}
	var sum *summary.Summary
	if o.dryRun {
		sum, err = merge.Write(io.Discard, files, opts)
	} else {
		sum, err = writeOutput(o.output, files, opts)
	}
	if err != nil {
		return fail("%v", err)
	}
	log.Debugf("write pass took %s", time.Since(started).Round(time.Millisecond))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	log.Debugf("memory obtained from the system: %.1f MB", float64(ms.Sys)/(1<<20))

	sum.Output, sum.DryRun, sum.Skipped = o.output, o.dryRun, skipped
	if o.dryRun {
		sum.Output = ""
		log.Infof("dry run: nothing written")
	} else {
		log.Infof("written: %s", o.output)
	}
	render := sum.WriteText
	if o.json {
		render = sum.WriteJSON
	}
	if err := render(stdout); err != nil {
		log.Warnf("%v", err)
		return exitFailed
	}
	if len(skipped) > 0 {
		return exitSkipped
	}
	return exitOK
}

// writeOutput merges into a temporary file beside output, checks the
// result, and renames it into place. On any error the temporary file
// is removed and an existing output file is left as it was.
func writeOutput(output string, files []*index.File, opts merge.Options) (sum *summary.Summary, err error) {
	tmp := output + ".tmp"
	fh, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			fh.Close()
			os.Remove(tmp)
		}
	}()

	w := bufio.NewWriterSize(fh, 1<<20)
	if sum, err = merge.Write(w, files, opts); err != nil {
		return nil, err
	}
	if err = w.Flush(); err != nil {
		return nil, err
	}
	if err = fh.Sync(); err != nil {
		return nil, err
	}
	if err = fh.Close(); err != nil {
		return nil, err
	}
	if err = verify(tmp, sum); err != nil {
		return nil, err
	}
	if err = os.Rename(tmp, output); err != nil {
		return nil, err
	}
	return sum, nil
}

// verify reads the written file back and checks that it is well-formed
// and holds the hosts and findings the summary says it does.
func verify(path string, sum *summary.Summary) error {
	f, err := index.Scan(path)
	if err != nil {
		return fmt.Errorf("output check failed: %w", err)
	}
	findings := 0
	for _, h := range f.Hosts {
		findings += h.Items
	}
	if len(f.Hosts) != sum.Hosts || findings != sum.Findings {
		return fmt.Errorf("output check failed: file holds %d host(s) and %d finding(s), expected %d and %d",
			len(f.Hosts), findings, sum.Hosts, sum.Findings)
	}
	return nil
}
