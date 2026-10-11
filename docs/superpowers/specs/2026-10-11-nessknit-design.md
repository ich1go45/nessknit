# nessknit design

Date: 2026-10-11
Status: awaiting review

## Purpose

`nessknit` merges several Nessus scan exports (`.nessus`,
`NessusClientData_v2`) into one file. It is a Go rewrite of a 317-line
Python script, `nessus_merger_v4.py`.

It is built for the author's own use on engagements. It should also be
usable by a stranger who finds the repository: one command to install,
a README that explains the merge rules.

The merged file is imported back into Nessus and fed to a reporting
tool. It must therefore stay importable by Nessus and be cleanly
de-duplicated.

Typical inputs are a mix of:

- scans of different host ranges (little or no overlap), and
- rescans of the same hosts over time (full overlap).

## Success criteria

1. On the same inputs, `nessknit` produces the same hosts, the same
   findings per host, and the same host properties as the Python
   script. Whitespace may differ.
2. Peak memory does not grow with total input size. It is bounded by
   the index plus one host's data.
3. A merged file built from real scans imports into Nessus. This is
   checked by hand before `v0.1.0` is tagged.

## Scope

In the first version:

- a proper command line (flags, help, exit codes);
- a merge summary, as text or JSON;
- low-memory streaming merge.

Out of the first version:

- repairing broken input files (they are skipped and reported);
- alternative overlap rules such as "newest scan wins";
- matching one host across IP and FQDN names;
- prebuilt release binaries.

The Python script's output-repair pipeline is not ported. It repaired
freshly serialised output, which cannot contain the faults it looked
for. A final well-formedness check replaces it.

## Command line

```
nessknit [flags] <path>...
```

Each path is a `.nessus` file or a directory. A directory contributes
the `.nessus` files directly inside it (extension matched without
regard to case), sorted by name, not recursively. Files are processed
in the order given. With no path, the current directory is used.

The output file is excluded from the inputs. The comparison uses
resolved absolute paths with symlinks followed.

| Flag | Meaning | Default |
|---|---|---|
| `-o`, `--output` | Output file path | `Combined.nessus` in the current directory |
| `--name` | Report name in the merged file | `Combined Report` |
| `--dry-run` | Run the full merge, print the summary, write nothing | off |
| `--json` | Print the summary as JSON | off |
| `-q`, `--quiet` | Suppress progress output | off |
| `-d`, `--debug` | Print detailed diagnostics | off |
| `--version` | Print the version | |
| `-h`, `--help` | Print usage | |

`-q` with `-d` is a usage error.

Progress, warnings and debug output go to stderr. The summary goes to
stdout, so `--json` output can be piped. `-q` suppresses progress but
not warnings or the summary.

Debug output covers: per-file index statistics; each host that appears
in more than one file and which files its blocks came from; each
duplicate finding dropped, with its key; timings per pass; peak memory.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Merged cleanly |
| `1` | Failed; nothing written |
| `2` | Bad usage |
| `3` | Merged and written, but at least one input file was skipped |

### Summary

Per input file and in total:

- hosts (new, and already seen);
- findings written, broken down by severity (0 to 4);
- duplicate findings dropped;
- hosts skipped for having no name.

Also: the primary file, the list of skipped files with the reason for
each, and the output path. JSON output carries the same fields.

## Merge rules

These reproduce the Python script except where marked **changed**.

1. **Primary.** The first usable input is the primary. Its header
   (everything before the first `ReportHost`, which includes the
   `Policy` block and the opening `Report` tag) is used for the output.
   Other files' headers are discarded. **Changed:** if the first file
   is unusable, the next usable file becomes the primary; the Python
   script aborted.
2. **Report name.** The `name` attribute of `Report` is set to the
   `--name` value. No other part of the header changes.
3. **Host identity.** Hosts are matched by the exact `name` attribute
   of `ReportHost`. A `ReportHost` with no name, or an empty one, is
   skipped with a warning.
4. **Host order.** Hosts are written in the order first seen across
   the inputs.
5. **Host properties.** The output `HostProperties` holds the `tag`
   elements from every occurrence of the host, in order of occurrence.
   For each tag `name`, the first one seen is kept and later ones are
   dropped. Tags without a `name` are kept only from the first
   occurrence. If no occurrence has `HostProperties`, none is written.
6. **First occurrence.** Every `ReportItem` of a host's first
   occurrence is copied unchanged, including any duplicates within it.
   Their keys are recorded.
7. **Later occurrences.** A `ReportItem` is copied only if its key has
   not been seen for this host. Its key is then recorded. Items with
   `pluginID` `19506` (Nessus Scan Information) are never copied from
   a later occurrence.
8. **Finding key.** `pluginID`, `port`, `protocol`, and the SHA-256 of
   the text of the item's first `plugin_output` child with leading and
   trailing whitespace removed. A missing `plugin_output` counts as
   empty text. **Changed:** the Python script used a 64-bit hash, where
   a collision would silently drop a finding.
9. **Other children.** Any child of `ReportHost` that is not
   `HostProperties` or `ReportItem` is copied from the first occurrence
   only.

**Changed:** the output defaults to the current directory. The Python
script wrote into the scan directory.

**Changed:** output is not re-indented. Elements are copied as raw
bytes, so each keeps its source file's formatting.

## Architecture

Go, standard library only. Module path
`github.com/ich1go45/nessknit` (username assumed from the local git
configuration; to be confirmed at review).

| Package | Responsibility | Depends on |
|---|---|---|
| `cmd/nessknit` | Parse flags, wire the packages, set the exit code | all below |
| `internal/inputs` | Turn paths into an ordered file list; exclude the output file | nothing |
| `internal/index` | Pass 1: scan one file and return its index | nothing |
| `internal/merge` | Pass 2: write the merged file from the indexes | `index`, `summary` |
| `internal/summary` | Hold the counts; render as text or JSON | nothing |

### Pass 1: index

Each file is read once through a streaming XML decoder. The index
records byte offsets only:

- the file's size and modification time;
- the header range: from the start of the file to the first
  `ReportHost`, or to the closing `Report` tag if there are no hosts;
- the range of the opening `Report` tag's `name` attribute value;
- for each `ReportHost`: its name, its start and end offsets, and the
  range of its `HostProperties` block if present.

A file is rejected at this stage, with a reason, if:

- it is not well-formed XML;
- it declares an encoding other than UTF-8;
- its root element is not `NessusClientData_v2`;
- it has no `Report` element.

### Pass 2: write

1. Check each indexed file's size and modification time against the
   index. A mismatch aborts the run.
2. Copy the primary's header as raw bytes, substituting the report
   name (XML-escaped) for the original attribute value.
3. For each host in first-seen order:
   1. write the opening `ReportHost` tag from the first occurrence;
   2. read the `HostProperties` range of every occurrence and write the
      merged block (rule 5);
   3. stream the first occurrence, copying each `ReportItem` and other
      child as raw bytes and recording keys (rules 6 and 9);
   4. stream each later occurrence, copying only items with new keys
      (rule 7);
   5. write the closing tag and discard the host's keys.
4. Write the closing `Report` and `NessusClientData_v2` tags.

Occurrences are read through section readers over the recorded ranges,
so no file is re-read from the start.

### Finishing

The output is written to a temporary file in the same directory as the
target. It is then read back once through the decoder to confirm that
it is well-formed and that its host and finding counts equal the
summary's. It is synced to disk and renamed over the target.

On any failure the temporary file is removed and an existing output
file is left untouched. An existing output file is overwritten on
success.

With `--dry-run`, both passes run and the output goes to a discarding
writer. The read-back check is skipped.

### Memory

Held at any time: the indexes (a few integers and a name per host),
the keys of one host, and the text of one finding.

### Known risk

The design depends on the Go XML decoder reporting exact byte offsets
for element boundaries (`Decoder.InputOffset`). The first
implementation task proves this with a test: index a fixture, slice
the file at the recorded offsets, and compare each slice with the
expected element text. Nothing else is built until that test passes.

If it cannot be made to work, the fallback is to re-serialise elements
through the encoder instead of copying raw bytes. That would need
extra tests for attribute and namespace fidelity, and the design would
be revised before continuing.

## Error handling

| Situation | Behaviour | Exit |
|---|---|---|
| No `.nessus` files found, or a path does not exist | Message; nothing written | `1` |
| Unknown flag, or `-q` with `-d` | Usage message | `2` |
| An input is rejected in pass 1 | Skip it; warn with file name and reason; list it in the summary | `3` |
| Every input is rejected | Message; nothing written | `1` |
| `ReportHost` without a name | Skip the host; warn; count it in the summary | `0` |
| An input changed or vanished between passes | Abort; remove temporary file | `1` |
| Write error or full disk | Abort; remove temporary file | `1` |
| Read-back check fails | Abort; remove temporary file; say which check failed | `1` |
| Output path already exists | Overwritten on success | `0` |

## Testing

Tests are written before the code they cover.

**Fixtures.** Small hand-written `.nessus` files in `testdata/`, each
built for one case. No real scan data is committed.

**Offset proof.** Described under "Known risk". It is the first task.

**Unit tests.**

- `inputs`: ordering; directory expansion; case-insensitive extension;
  output exclusion with relative paths, absolute paths and symlinks.
- `index`: each rejection reason; nameless hosts; `HostProperties`
  absent or not first; a `Report` with no hosts.
- `merge`: disjoint hosts; overlapping hosts; duplicate findings; the
  same plugin with different output; plugin `19506`; property union;
  the report name, including one that needs escaping; primary
  promotion when the first file is rejected.
- `summary`: text and JSON rendering.

**End-to-end tests.** Build the binary and run it against fixture
directories. Check exit code, stdout, stderr and the output file for
every row of the error-handling table that can be reproduced in a
test.

**Parity test.** Run the Python script and `nessknit` on the same
fixtures. Parse both outputs and compare, per host: the set of finding
keys with their counts, and the property names and values. The test is
skipped when `python3` is not available. Fixtures for this test avoid
the cases marked **changed**.

**Memory test.** Generate a large synthetic input (many hosts, many
findings each), merge it, and assert that peak heap stays under a
fixed bound that a full in-memory load would exceed.

**Not testable here.** Importing a merged file into Nessus. The author
does this by hand with real scans before `v0.1.0` is tagged.

## Repository

Location: `/home/ich1go/Projects/nessknit`, branch `main`.

```
nessknit/
  cmd/nessknit/          entry point
  internal/              inputs, index, merge, summary
  testdata/              hand-written fixtures
  testdata/reference/    the original Python script, for the parity test
  docs/superpowers/      design spec and implementation plan
  .github/workflows/     CI
  README.md  LICENSE  .gitignore  go.mod
```

- **README:** what the tool does, how to install it, usage examples,
  the merge rules in plain terms, exit codes, and a statement that it
  is not affiliated with Tenable.
- **Licence:** MIT.
- **`.gitignore`:** ignores every `.nessus` file outside `testdata/`,
  so client scan data cannot be committed by accident.
- **CI:** one GitHub Actions workflow that runs `go vet` and `go test`
  on each push and pull request.
- **Install:** `go install github.com/ich1go45/nessknit/cmd/nessknit@latest`.
- **Version:** `--version` reads the module version from the build
  information, so a tagged install reports its tag with no build flags.
- **Releases:** Git tags, starting at `v0.1.0`.

Pushing to GitHub is done only after the author creates the remote
repository and confirms.
