# nessknit

Merge several Nessus scan exports (`.nessus` files) into one.

`nessknit` is for the case where one engagement ends up as many scans:
separate subnets, separate scanners, or the same hosts scanned again
later. It produces a single `.nessus` file that imports back into
Nessus and loads into reporting tools, with duplicate findings removed.

It reads the inputs as streams, so memory use stays flat however large
the scans are.

Not affiliated with or endorsed by Tenable. Nessus is a trademark of
Tenable, Inc.

## Install

With Go 1.24 or later:

```
go install github.com/ich1go45/nessknit/cmd/nessknit@latest
```

## Usage

```
nessknit [flags] <path>...
```

Each path is a `.nessus` file or a directory of them (not searched
recursively). With no path, the current directory is used.

```
# Merge every .nessus file in the current directory into Combined.nessus
nessknit

# Merge a directory, choosing the output file and report name
nessknit -o acme-internal.nessus --name "ACME internal" scans/

# Merge named files; the first one supplies the scan policy
nessknit -o merged.nessus dmz.nessus servers.nessus workstations.nessus

# See what a merge would produce without writing anything
nessknit --dry-run scans/

# Machine-readable summary
nessknit --json -q scans/ > summary.json
```

| Flag | Meaning | Default |
|---|---|---|
| `-o`, `--output` | Output file | `Combined.nessus` |
| `--name` | Report name in the merged file | `Combined Report` |
| `--dry-run` | Run the merge and print the summary, write nothing | off |
| `--json` | Print the summary as JSON | off |
| `-q`, `--quiet` | Suppress progress output | off |
| `-d`, `--debug` | Print detailed diagnostics | off |
| `--version` | Print the version | |
| `-h`, `--help` | Print help | |

Progress, warnings and diagnostics go to stderr. The summary goes to
stdout.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Merged cleanly |
| `1` | Failed; nothing written |
| `2` | Bad usage |
| `3` | Merged and written, but at least one input file was skipped |

Check for `3` in scripts: it means a scan is missing from the result.

## How files are merged

- **Order.** Files are merged in the order given. Files from a
  directory are taken in name order.
- **Policy.** The first usable file supplies the scan policy and the
  report settings. The other files' policies are dropped.
- **Hosts.** Hosts are matched by their exact name in the file. A host
  scanned once by IP address and once by hostname stays as two hosts.
- **Findings.** When a host appears more than once, its findings are
  combined. A finding is a duplicate, and dropped, if it has the same
  plugin, port, protocol and plugin output as one already kept. The
  same plugin with different output is kept as a separate finding.
- **Host properties.** Combined across all scans of the host. Where two
  scans disagree on a property, the earlier file wins.
- **Scan information.** Plugin 19506 (Nessus Scan Information) is kept
  only from the first scan of each host.
- **Rescans.** Findings are never removed. A vulnerability fixed
  between two scans still appears in the merged file, because the
  earlier scan reported it.

The output file is never read as an input, so running `nessknit` twice
in the same directory is safe.

### Files that cannot be merged

An input is skipped, with a warning, if it is not well-formed XML, is
not UTF-8, or is not a Nessus v2 export. `nessknit` does not try to
repair broken files. The remaining files are still merged and the exit
code is `3`.

The merged file is written to a temporary file, checked, and only then
moved into place. If anything fails, an existing output file is left
untouched.

## Development

```
go test ./...          # everything, including a 150 MB memory test
go test -short ./...   # skip the memory test
```

One test compares the result against the Python script this tool
replaced (`testdata/reference/`). It needs `python3` and is skipped
without it.

Never commit real scan data. `.gitignore` excludes every `.nessus` file
outside `testdata/`, which holds hand-written fixtures only.

## Licence

MIT. See [LICENSE](LICENSE).
