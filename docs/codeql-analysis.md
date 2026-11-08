# Fixture-bound CodeQL analysis

PR 6 runs the pinned Python path-traversal query against a verified PR 5 capture.
It records independent CodeQL observations. Matching those observations to Semgrep
findings is available through [static correlation](static-correlation.md);
this analysis stage creates no `StaticEvidence.finding_id`,
assessment, execution plan, or exploitability verdict.

## Preparation and use

Follow [development setup](../CONTRIBUTING.md) and the
[CodeQL preparation instructions](cwe22-feasibility.md#pins-and-preparation).
The prepared tool is trusted native software supplied explicitly by the operator.
Use it under its [applicable terms and availability](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).
The two admitted fixtures are public, project-owned code; admission is not a
licensing determination for other projects.

```sh
uv run --locked python scripts/prepare_codeql.py
uv run --locked vulnproof analyze \
  --capture .cache/investigation-001/snapshot \
  --output .cache/analysis-001 \
  --codeql-bundle .cache/codeql/2.27.3/codeql
```

`--capture` selects an existing [source capture](source-provenance.md), not a
repository checkout. `--output` must be new, its parent must exist, and it must be
outside the capture. There is no output overwrite, database reuse, admission bypass,
arbitrary command/query option, automatic tool download, or source-provided configuration.
An installed wheel supports these commands outside the repository when given
absolute capture, output, and prepared-bundle paths.

| Exit | Meaning |
| --- | --- |
| `0` | Commands succeeded, integrity checks passed, and observations normalized completely |
| `1` | Attempt failed with a retained report, or normalization is partial |
| `2` | Invalid capture, unapproved content, existing output, usage, or unrecoverable IO error |
| `130` | CLI interruption or SIGTERM; process group stopped and failed report retained where IO permits |

JSON summary goes to stdout; reason codes go to stderr and the report. No path or
zero results ever establishes safety. A patched fixture's results are observations,
with no requirement that they be absent.

## Reviewed fixture admission

The packaged `vulnproof/static/fixtures.json` manifest contains an identifier,
expected fingerprint, and description for each reviewed vulnerable/patched fixture.
Actual captured bytes are verified before admission. A directory name, user label,
or fingerprint claim in JSON cannot substitute for the verification. Both fingerprints
use PR 5's `vulnproof-source-v1` algorithm, including executable flags.

The same reviewed content can be copied elsewhere and analyzed. Edits, extra included
files, renamed files, and executable-bit changes require a reviewed manifest update.
Exclusions and empty-directory identity follow PR 5's documented policy; admission
approves included content, not every excluded byte in a repository. Updating an
approval requires normal fixture/source and PR review. There is no public registry
configuration or runtime approval override.

Admission permits this static analysis only. It neither establishes safety nor
authorizes execution of the application.

## Fixed tool profile and source association

- CodeQL CLI **2.27.3**, bundled `codeql/python-queries` **1.8.13**.
- Official **`py/path-injection`**, at its fixed bundled path. Its SHA-256 is
  `c17ed4b748e8439666371723d7400aa6ae255219e20aedee73cd51f765505a74`.
- Python extraction explicitly uses `--build-mode=none`; no application imports,
  dependency installation, repository build commands, or server startup are requested.
- Query output is explicitly SARIF 2.1.0, with a maximum of four emitted paths per result.
- Two threads and 2,048 MiB are CodeQL resource settings, not OS-enforced CPU/memory limits.

Source is verified, copied into a private fresh workspace, compared with the approved
manifest, and made read-only. That private copy is the database source root. After
query execution, both the original capture and analysis copy are reverified before
results can be accepted. CodeQL's own Python extractor executes its trusted bundled
scripts even in no-build mode; log text mentioning an autobuild script does not
mean VulnProof supplied an application build command.

Commands run from the workspace with a fresh HOME/config/cache/temp location and
a deliberately constructed environment. Inherited CodeQL, Python, Java, authentication,
and user-config variables are not forwarded. `PYTHONNOUSERSITE` and `PYTHONSAFEPATH`
remain enabled; `PYTHONPATH` is explicitly the prepared bundle's `python/tools`
directory so the extractor can import its own modules, never an application path.
The trusted interpreter directory and OS default tools supply PATH. The selected
bundle, interpreter installation, operating environment, and output directory owner
remain trusted. Extraction is not sandboxed arbitrary-code execution.

Downloads occur only during explicit preparation. The analysis path does not invoke
network clients or install packs; the complete prepared bundle works offline.
This is not a network-namespace or firewall guarantee against a compromised tool.

## Artifacts and states

```text
analysis-001/
  analysis.json             # Atomically published versioned report
  diagnostics/
    version.log
    extract.log
    query.log
    raw.sarif               # Present when the tool emitted it
  work/
    source/                 # Verified private copy
    database/               # Fresh CodeQL database; no automatic reuse
    home/ config/ cache/ tmp/
```

The new directory is reserved exclusively. Work files/logs may be visible before
the report exists; consumers must read a completed `analysis.json`, never infer
success from a database or partial SARIF file. Publication uses an atomic,
no-overwrite hard link in the reserved directory and requires filesystem support.
It is not a power-loss durability guarantee. IO failure can prevent report publication.

`AnalysisDocument` version **1.0** contains a run ID, fixture ID, captured snapshot,
analysis-source binding, observed tool identity, fixed requested query profile,
command outcomes, hashed artifacts, result groups, and diagnostics. Each result
has its original SARIF reference, a normalized sink when available, and separate
alternative `StaticPath` records with their own SARIF references. Original messages,
snippets, CodeQL extensions, and unsupported data remain in raw SARIF.

`outcome` is `completed` or `failed`. `normalization` is `complete`, `partial`, or
`not_attempted`. A valid empty result array is completed analysis with zero query
results. A result without an emitted usable path remains a result with a diagnostic,
not a claim that no path exists. Failed commands, corrupt documents, integrity
failures, deadlines, and output overflow produce no usable normalized results.

For completed runs, `source.state=matched` means **CodeQL's source copy matched the
captured target**. It says nothing about Semgrep's historical input; PR 5 scanner
bindings are unchanged and remain unverified. Failed runs keep an unverified
analysis-source binding. Fixed query-profile fields describe what was requested;
observed tool/pack identity is filled only after the corresponding checks pass.

## Paths, diagnostics, and bounds

Only locations within the analyzed source copy and present in its manifest are
normalized. Relative URIs, `%SRCROOT%`, artifact-table indexes, and file URIs within
the exact analysis source root are supported; conflicting indexes/URIs, external
locations, escapes, malformed regions, and lines beyond captured content are diagnosed.
No referenced path or URL is opened by the normalizer.

Node order and duplicate nodes are preserved. A path needs at least two supported
locations and an endpoint compatible with its CodeQL result sink. If a node cannot
be represented, that whole alternative is unavailable; nodes are never dropped
to manufacture a complete path. Other complete alternatives can remain available.
Raw references preserve the unsupported alternative for review. The diagnostic
`observed_paths` count records thread flows visited before any structural rejection.

Logs are capped at **1 MiB per command**. Version, extraction, and query deadlines
are **30, 180, and 300 seconds**, respectively. The process group is terminated on
success, failure, timeout, output overflow, or handled interruption so children
cannot remain attached to a finished attempt. Raw SARIF retention is capped at
**10 MiB**; oversized output is rejected and retained only as a marked truncated
prefix after the producer is stopped. Monitoring can permit temporary overshoot;
this is not a disk quota. Database/cache sizes are not hard-limited.

SARIF normalization rejects ambiguous JSON, non-finite numbers, invalid UTF-8,
unsupported versions/producers, external property files, and failed invocations.
Bounds include depth 64, eight runs, 1,024 results, 16 visited alternatives per
result, and 1,024 nodes per complete path. Warnings/errors emitted by CodeQL remain
diagnostics, not silently accepted as complete normalization.

Artifact SHA-256 and size describe the retained bytes. `truncated=false` means no
byte prefix was discarded; a failed command may still have emitted incomplete or
invalid data. Command outcome and document validation determine usability. Logs
and raw output can include source and machine paths; there is no redaction.
Run IDs, timings, logs, and raw hashes can change across attempts. Repeatability
means source/profile binding and comparable modeled observations, not identical
database bytes or exhaustive enumeration of all possible paths.

## Tests and reproduction

```sh
uv run --locked pytest
uv run --locked python scripts/check_codeql_analysis.py
```

Default tests use a trusted fake tool and authored SARIF; they require neither
CodeQL nor Docker. The real check captures both approved fixture directories and
runs this integration. It now supplies a clearly labeled synthetic Semgrep finding
for the vulnerable fixture to demonstrate the separate correlation stage; it does
not execute Semgrep or establish scanner provenance. The vulnerable capture must
have a complete path passing through its request input and ending at its file sink,
and correlation must retain it as a candidate with unverified scanner provenance.
The separate [planning stage](validation-plans.md) must produce a draft carrying
unmet prerequisites and no execution authorization.
Patched observations are retained unchanged. Missing tools and incompatible pins
fail explicitly.

CI runs the real check in **CodeQL analysis integration** on Ubuntu 24.04 for trusted
same-repository PRs and pushes to main, with read-only repository permissions and
no secrets. Fork PR execution is skipped. Only bounded diagnostics are uploaded
for three days, never databases or intentional findings to GitHub code scanning.
The existing development and PR 2 feasibility jobs remain independent.

Public entry points are `vulnproof.static.analyze_capture`, `AnalysisDocument`,
and `AnalysisFailure.code`. Model validation checks structure and consistency;
artifact hashes are producer observations, not signatures authenticating a report.
Future consumers must validate artifacts and provenance before using them as evidence.
