# nessknit

Merge several Nessus scan exports (`.nessus` files) into one.

One engagement often ends up as many scans: separate subnets, separate
scanners, or the same hosts scanned again later. `nessknit` combines
them into a single `.nessus` file that imports back into Nessus and
loads into reporting tools, with duplicate findings removed.

- **One file out.** Hosts from every scan, each with the union of its
  findings and host properties.
- **Flat memory use.** Inputs are read as streams, so hundreds of
  megabytes of scans merge in a few megabytes of RAM.
- **Safe to run.** Inputs are never modified, and the output is checked
  before it replaces anything.
- **No dependencies.** A single binary.

Not affiliated with or endorsed by Tenable. Nessus is a trademark of
Tenable, Inc.

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [Usage](#usage)
- [Reading the summary](#reading-the-summary)
- [How files are merged](#how-files-are-merged)
- [When something goes wrong](#when-something-goes-wrong)
- [Development](#development)

## Quick start

Download the archive for your system from the
[latest release](https://github.com/ich1go45/nessknit/releases/latest),
unpack it, and put `nessknit` on your `PATH` (details under
[Install](#install)). Then:

```
cd /path/to/your/scans
nessknit --dry-run        # preview: prints what would be merged, writes nothing
nessknit                  # writes Combined.nessus in this directory
```

Then import `Combined.nessus` into Nessus (Scans > Import) or your
reporting tool.

## Install

### Download a binary (no Go needed)

Each [release](https://github.com/ich1go45/nessknit/releases/latest)
has a ready-to-run binary for these systems:

| System | File |
|---|---|
| Linux, Intel/AMD | `nessknit_<version>_linux_amd64.tar.gz` |
| Linux, ARM | `nessknit_<version>_linux_arm64.tar.gz` |
| macOS, Apple silicon | `nessknit_<version>_darwin_arm64.tar.gz` |
| macOS, Intel | `nessknit_<version>_darwin_amd64.tar.gz` |
| Windows, Intel/AMD | `nessknit_<version>_windows_amd64.zip` |
| Windows, ARM | `nessknit_<version>_windows_arm64.zip` |

**Linux and macOS.** Unpack the archive and move the binary somewhere
on your `PATH`:

```
tar -xzf nessknit_*.tar.gz nessknit
sudo mv nessknit /usr/local/bin/
nessknit --version
```

On macOS the binary is not signed, so the first run may be blocked.
Clear the download flag once and run it again:

```
xattr -d com.apple.quarantine /usr/local/bin/nessknit
```

**Windows.** Unzip the file and run `nessknit.exe` from PowerShell or
Command Prompt in that folder, or move it to a folder on your `PATH`.

**Checking the download (optional).** Each release includes
`checksums.txt`. With it in the same folder as the archive:

```
sha256sum -c --ignore-missing checksums.txt          # Linux
shasum -a 256 -c --ignore-missing checksums.txt      # macOS
```

### With Go

You need Go 1.24 or later. Check with `go version`; if it is missing,
install it from <https://go.dev/dl/>.

```
go install github.com/ich1go45/nessknit/cmd/nessknit@latest
```

This puts the `nessknit` binary in `~/go/bin`. If your shell then says
`nessknit: command not found`, that directory is not on your `PATH`.
Add this line to `~/.bashrc` or `~/.zshrc` and open a new terminal:

```
export PATH="$PATH:$HOME/go/bin"
```

Confirm it works:

```
nessknit --version
```

### From source

```
git clone https://github.com/ich1go45/nessknit.git
cd nessknit
go build -o nessknit ./cmd/nessknit
./nessknit --version
```

Copy the resulting `nessknit` file anywhere on your `PATH`, or run it
in place as `./nessknit`.

## Usage

```
nessknit [flags] <path>...
```

Each path is a `.nessus` file or a directory of them. Directories are
not searched recursively. With no path, the current directory is used.
Flags can go before, between or after the paths.

### Common tasks

Merge every `.nessus` file in the current directory:

```
nessknit
```

Merge a directory, choosing the output file and the report name shown
in Nessus:

```
nessknit -o acme-internal.nessus --name "ACME internal" scans/
```

Merge specific files in a specific order. The first file supplies the
scan policy:

```
nessknit -o merged.nessus dmz.nessus servers.nessus workstations.nessus
```

Mix directories and files:

```
nessknit -o merged.nessus week1/ week2/ retest.nessus
```

Preview a merge without writing anything:

```
nessknit --dry-run scans/
```

Get the summary as JSON for a script, with no progress output:

```
nessknit --json -q scans/ > summary.json
```

See exactly which hosts overlapped and which findings were dropped:

```
nessknit --debug scans/
```

### Flags

| Flag | Meaning | Default |
|---|---|---|
| `-o`, `--output FILE` | Output file | `Combined.nessus` in the current directory |
| `--name NAME` | Report name in the merged file | `Combined Report` |
| `--dry-run` | Run the merge and print the summary, write nothing | off |
| `--json` | Print the summary as JSON | off |
| `-q`, `--quiet` | Suppress progress output | off |
| `-d`, `--debug` | Print detailed diagnostics | off |
| `--version` | Print the version | |
| `-h`, `--help` | Print help | |

`--quiet` and `--debug` cannot be combined.

Progress, warnings and diagnostics go to stderr. The summary goes to
stdout, so it can be redirected or piped on its own.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Merged cleanly |
| `1` | Failed; nothing written |
| `2` | Bad usage |
| `3` | Merged and written, but at least one input file was skipped |

Check for `3` in scripts: it means a scan is missing from the result.

```
nessknit -q -o merged.nessus scans/
case $? in
  0) echo "merged" ;;
  3) echo "merged, but some files were skipped" >&2 ;;
  *) echo "merge failed" >&2; exit 1 ;;
esac
```

## Reading the summary

A run over two scans that share one host:

```
$ nessknit -o acme.nessus scans/
[*] found 2 input file(s)
[*] indexed scans/dmz.nessus: 2 host(s)
[*] indexed scans/servers.nessus: 2 host(s)
[*] primary: scans/dmz.nessus
[*] written: acme.nessus
Primary : scans/dmz.nessus
Output  : acme.nessus

scans/dmz.nessus
  hosts    : 2 new, 0 already seen
  findings : 6 (critical 1, high 0, medium 1, low 0, info 4)
  dropped  : 0 duplicate, 0 scan-info

scans/servers.nessus
  hosts    : 1 new, 1 already seen
  findings : 4 (critical 0, high 1, medium 0, low 1, info 2)
  dropped  : 2 duplicate, 1 scan-info

Total
  hosts    : 3
  findings : 10 (critical 1, high 1, medium 1, low 1, info 6)
  dropped  : 2 duplicate, 1 scan-info
```

- **Primary** is the file whose scan policy the output carries.
- **hosts: new / already seen** counts hosts this file introduced, and
  hosts it shares with an earlier file.
- **findings** counts what this file contributed to the output, by
  severity.
- **dropped: duplicate** counts findings left out because an earlier
  file already had the same one for that host.
- **dropped: scan-info** counts "Nessus Scan Information" entries left
  out; see the merge rules below.
- A **Skipped** section appears if any input could not be used, with
  the reason for each.

Lines starting `[*]` are progress, `[!]` are warnings, and `[debug]`
appear only with `--debug`.

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
- **Compliance checks.** These share one plugin and port and have no
  plugin output, so they are also compared by check name and result. A
  check repeated with the same result is dropped; a check whose result
  changed between scans is kept alongside the earlier one.
- **Host properties.** Combined across all scans of the host. Where two
  scans disagree on a property, the earlier file wins.
- **Scan information.** Plugin 19506 (Nessus Scan Information) is kept
  only from the first scan of each host.
- **Rescans.** Findings are never removed. A vulnerability fixed
  between two scans still appears in the merged file, because the
  earlier scan reported it. Only host properties depend on order, so
  list the newest scan first if you want its property values.

A previous output file found inside an input directory is left out, so
running `nessknit` twice in the same directory is safe.

## When something goes wrong

**`no .nessus files found`.** The paths contain no files ending in
`.nessus`. Directories are not searched recursively, so name the
subdirectories too.

**`skipping FILE: ...` and exit code 3.** That input was left out; the
rest were merged. An input is skipped if it is not well-formed XML, is
not UTF-8, or is not a Nessus v2 export. `nessknit` does not repair
broken files. Export the scan from Nessus again, then re-run.

**`output file is also an input`.** The `-o` path was also named as a
file to merge, which would overwrite it. Choose a different output
name.

**`file changed after it was indexed`.** An input was modified while
the merge was running. Re-run once nothing else is writing to it.

**`namespace prefix ... cannot be merged`.** The same host appears in
two files that define one XML namespace prefix differently. Nessus
exports do not do this; it points to a file edited or produced by
another tool.

**Nothing was written.** On any failure the output is left as it was
before the run. The merged file is written to a temporary file beside
the output, checked, and only then moved into place.

## Development

```
go test ./...          # everything, including a 150 MB memory test
go test -short ./...   # skip the memory test
go vet ./...
```

To publish a release, push a version tag. A workflow tests the code,
builds the binaries with `scripts/build-release.sh` and attaches them
to a GitHub release:

```
git tag -a v1.2.3 -m "nessknit v1.2.3"
git push origin v1.2.3
```

The code is in four small packages under `internal/`: `inputs` (which
files to merge), `index` (find each host's position in a file), `merge`
(write the combined file) and `summary` (the report). `cmd/nessknit`
ties them to the command line. The design is described in
`docs/superpowers/specs/`.

One test compares the result against the Python script this tool
replaced (`testdata/reference/`). It needs `python3` and is skipped
without it. The merge matches that script except for compliance checks,
which the script kept only from a host's first file.

Never commit real scan data. `.gitignore` excludes every `.nessus` file
outside `testdata/`, which holds hand-written fixtures only.

## Licence

0BSD: use it however you like, no attribution needed. See
[LICENSE](LICENSE).
