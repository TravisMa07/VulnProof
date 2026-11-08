# Source capture and provenance

PR 4 records what Semgrep reported. Source capture records the bytes selected for
the investigation. These are separate facts: capturing current code does not prove
that Semgrep scanned that code. Every scanner association remains `unverified`.

## Workflow

Run from the installed development environment. The report's paths must be relative
to the source root you select; there is no automatic prefix stripping or file search.

```sh
uv run --locked vulnproof ingest --sarif findings.sarif --output ingestion.json
uv run --locked vulnproof capture --ingestion ingestion.json \
  --source-root fixtures/cwe22/vulnerable --output .cache/investigation-001
uv run --locked vulnproof verify-source --capture .cache/investigation-001/snapshot
```

The output parent must exist, and the output directory must be new and physically
outside the selected source root, including excluded directories. Choose another
output name for subsequent captures. No existing output is replaced or removed.
Source roots and their ancestors must not be symlinks. On macOS, use `/private/tmp`
rather than the `/tmp` alias when selecting temporary sources.

```text
investigation-001/           # Exclusively reserved, owner-only directory
  snapshot/                 # Published only after successful capture and checks
    ingestion.json          # Exact original ingestion file bytes
    provenance.json         # Versioned manifest, identities, bindings, diagnostics
    source/                 # Copy for future analysis; never imported or executed
```

The original ingestion file is unchanged. Capture validates it and repeats its pure
SARIF normalization to reject records inconsistent with the retained report. The
new provenance artifact has `schema_version: "1.0"`; it does not change PR 3 evidence
contracts or PR 4's ingestion format. No runtime dependencies are added.

| Command/result | Exit | Published output |
| --- | --- | --- |
| Capture succeeds; finding files/lines present | `0` | Snapshot, with scanner bindings still unverified |
| Capture succeeds; missing/out-of-range finding locations or partial input ingestion | `1` | Snapshot with explicit reasons; original input diagnostics preserved |
| Invalid input/root, limits, known revision mismatch, concurrent change, or IO error | `2` | No completed snapshot; owned output reservation cleaned on handled failure |
| `verify-source` validates stored content and associations | `0` | JSON status `content_verified`; no files changed |
| `verify-source` detects unreadable, modified, or inconsistent content | `2` | No files changed |

JSON summaries go to stdout and fixed diagnostic messages to stderr. Unknown Git
information is a diagnostic, not a capture failure, unless a revision is required.
An empty source tree can be captured; missing finding files remain explicit.
Successful content verification is not authentication or scanner-source verification.

## Scope, exclusions, and limits

Capture reads the selected tree's regular files, including untracked and ignored
files. It does not use `.gitignore` as a source-selection policy. The fixed v1
exclusion names apply to any matching path component, whether a file or directory:

```text
.git  .venv  .cache  __pycache__  .pytest_cache  .mypy_cache
.ruff_cache  dist  build
```

Excluded entries are recorded in `excluded_paths` without traversal. Included
symlinks, sockets, FIFOs, devices, unsupported names, and root escapes reject the
whole capture. Descriptor-relative reads with `O_NOFOLLOW` prevent substitution of
an included file/directory with a symlink from causing a read through that link.
This initially supports POSIX macOS and Linux; Windows is not supported.

Limits are 1,024 included files, 4,096 encountered entries (including exclusions),
32 directory levels beneath the root, 8 MiB per file, and 64 MiB total file bytes.
Input ingestion/provenance documents are limited to 64 MiB each. Exclusions/limits
are versioned policy, persisted with the artifact, and cannot be changed by SARIF
or command arguments. Metadata and cache exclusions mean this is a source snapshot,
not an archive of every repository file or a claim about application dependencies.

Choose a narrow root: included `.env` files and other sensitive content are copied
verbatim, without redaction. No secret discovery, Git clone, checkout, dependency
installation, build hook, application import, container, or network request is part
of source capture. Runtime execution remains restricted to reviewed fixtures in
later roadmap stages.

## Content identity

Each captured file records its normalized relative POSIX path, SHA-256 of exact
bytes, byte count, executable flag (any execute bit), and line count. LF, CRLF,
and CR line boundaries are recognized; bytes are never rewritten. Location checks
establish file existence and line-range bounds only. Column units, source meaning,
and whether a finding still applies remain unverified.

The algorithm `vulnproof-source-v1` is defined as:

1. Sort included files lexicographically by their relative Unicode path strings.
2. Build an array of `[path, sha256, size_bytes, executable]` rows.
3. Encode that array with UTF-8 JSON, `ensure_ascii=False`, separators `(',', ':')`,
   no indentation, no trailing newline, and JSON booleans.
4. Prefix those bytes with ASCII `vulnproof-source-v1` and one LF byte; SHA-256 the result.

The snapshot ID is `snapshot:<fingerprint>`. A known-vector test guards the encoding.
Machine paths, timestamps, original permission bits other than executability, Git
metadata, and empty directories are not part of this identity. Included paths,
content, and executable flags determine it. Changing the policy or algorithm needs
an explicit version review rather than silently reusing the same identifier scheme.

`SourceSnapshot.files` contains the full included-file hash manifest for this
producer. Generic PR 3 `SourceSnapshot` records from other producers do not imply
a complete manifest. SHA-256 identifies content, not the truth of scanner claims
or the identity of whoever created an artifact.

## Git observations and revision requirements

When available, capture observes a full `HEAD` commit and the selected root's
repository-relative prefix. The `dirty` flag means **captured scope differs from
HEAD** under the same exclusion policy. Raw Git blob identities and executable
flags are compared with the copied bytes. Added/deleted/modified included files
count, including ignored files; unrelated repository paths and staged/index-only
differences do not. This is deliberately not a whole-repository `git status` flag.
Checkout line-ending conversion can conservatively make the raw-byte comparison dirty.

Git commands are limited to `rev-parse` and `ls-tree`, with bounded output (1 MiB
per command) and a five-second command timeout. Inherited `GIT_*` environment
overrides are removed; system/global Git config, fsmonitor, hooks, replacement
objects, lazy fetching, and transport protocols are disabled. No `status`, clean
filter, text conversion, fetch, or remote command is requested. Git itself and the
local operating environment remain trusted. Missing Git, non-Git/unborn repositories,
unsupported entries, and unavailable metadata yield unknown commit/dirty state.

Use `--expected-commit FULL_LOWERCASE_ID` to require the selected scope to equal
the observed `HEAD` revision. A different commit, dirty scope, or unavailable Git
metadata rejects the capture. Both full SHA-1 and SHA-256 commit IDs are accepted;
branches, short hashes, and arbitrary revision expressions are not resolved.

Full revision IDs in SARIF `versionControlProvenance` are also checked when Git
is available. Different declared revisions across runs, or multiple declared
repositories in one run without a mapping, reject capture. Missing/short revision
claims remain explicitly unknown; full claims without Git remain explicitly
unverified. A matching revision is a consistency check and never promotes the
scanner binding to `matched`. Dirty captures without an exact revision requirement
remain allowed and get a distinct content fingerprint.

## Publication, verification, and limitations

Capture copies and hashes files, rereads the source tree, compares file identities
and contents, checks root/Git stability, and verifies the copied bytes. Ordinary
concurrent edits fail rather than publishing a detected inconsistent capture.
This is not an atomic filesystem snapshot or protection against a hostile writer
carefully changing and restoring files around observations.

The new output directory is reserved exclusively before copying. Its private
pending child is renamed to `snapshot` only after success. The reservation can be
visible while work is in progress; consumers must use the published `snapshot`
child, never a pending directory. Other cooperating captures cannot reuse the
reservation. User-selected output locations and their owners are trusted; this
does not defend against a hostile owner of the destination directory.

Captured files/metadata and directories are made read-only. This discourages
accidental edits, not edits by an owner who can change permissions. Later consumers
must call `verify_capture` before use. It rehashes actual stored files, checks
membership/executable flags and manifest identity, validates the preserved ingestion, and
reconstructs finding associations. Empty directories are preserved during copying
but do not contribute to the fingerprint or file-membership verification.

Handled errors and interruption remove the newly owned reservation, including
read-only pending files. Abrupt termination can leave a reservation/pending copy;
there is no automatic deletion of existing output directories on retry. Publication
provides atomic visibility of completed output, not power-loss durability or
protection against later edits between verification and analysis.

Public entry points are `capture_source(ingestion, root, output, expected_commit=...)`,
`verify_capture(snapshot_directory)`, `ProvenanceDocument`, and `CaptureFailure.code`
in `vulnproof.provenance`. The [CodeQL analysis stage](codeql-analysis.md) consumes
approved fixture captures and verifies its private analysis copy without promoting
scanner bindings.

Technical references: [Python descriptor-relative file operations](https://docs.python.org/3.14/library/os.html),
[Git tree listing](https://git-scm.com/docs/git-ls-tree), and
[Git environment controls](https://git-scm.com/docs/git).
