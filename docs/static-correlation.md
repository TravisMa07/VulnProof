# Finding-to-path correlation

The `correlate` command links imported Semgrep findings to compatible CodeQL result
groups in the selected reviewed fixture capture. It records **candidates**, not
exploitability assessments, execution authorization, or verified scanner provenance.
It runs no scanner, extractor, application, or container and installs nothing.

## Use

After [ingestion](sarif-ingestion.md), [capture](source-provenance.md), and
[analysis](codeql-analysis.md):

```sh
uv run --locked vulnproof correlate \
  --capture .cache/investigation-001/snapshot \
  --analysis .cache/analysis-001 \
  --output .cache/correlation-001.json
```

The output must be a new file, outside both input directories, with an existing
parent directory. Publication is atomic and refuses overwrites. Exit **0** means
the correlation operation completed, including when there are no candidates,
unsupported rules, partial analysis, or a retained failed analysis. Exit **2**
means invalid inputs, integrity/admission failure, output limits, IO, or usage error.
Read the output's observation states; exit 0 is not a security verdict.

## Reviewed compatibility policy

Policy `fixture-cwe22-v1` supports only the two content-approved CWE-22 fixtures.
Its packaged reference rule is
[`cwe22-file-read.yaml`](../src/vulnproof/correlation/rules/cwe22-file-read.yaml),
with exact rule ID `vulnproof.fixture.cwe22.file-read` and a required imported
`CWE-22` tag. The reference rule models `request.args.get(...)` reaching
`open(..., "rb")`; the compatible CodeQL query is `py/path-injection` under the
existing pinned analysis profile. The rule reports the whole sink expression,
allowing overlap with CodeQL's file-open sink region.

This is a fixture-specific mapping, not general recognition of every file operation
or CWE-22 rule. No aliases, rule-name suffix matching, message heuristics, registry
lookup, or operator-supplied mappings are accepted. A missing or different rule/CWE
combination produces `unsupported_mapping`; an exact match is policy compatibility,
not proof of the imported rule's definition. The ingestion adapter already restricts
accepted scanner producers to its supported Semgrep names.

The policy records the SHA-256 of the packaged rule bytes. That identifies our
reviewed definition; it does **not** authenticate which definition an external scan
used. No Semgrep dependency is added. The integration demonstration uses explicitly
synthetic Semgrep SARIF and real CodeQL output; it does not validate execution of
the reference Semgrep rule or claim a real Semgrep-to-CodeQL end-to-end scan.
Real scanner-rule execution and additional mappings need their own validation.
Reports whose rule IDs have been prefixed must not be guessed into this mapping.

Changes to rule semantics or matching behavior require a reviewed policy-version
change and corresponding tests. Broader application support remains outside this PR.

## Identity, matching, and uncertainty

The command reverifies the capture, checks the preserved ingestion hash, and requires
the analysis's complete snapshot record to equal the selected capture's snapshot.
Identical source bytes captured under a different snapshot ID are not automatically
interchangeable. A commit ID alone never establishes content identity.

Retained command logs and SARIF must match declared sizes and hashes. For completed
analysis, the private `work/source` copy must match the capture manifest, and
normalization of retained SARIF must reproduce the recorded result groups, paths,
references, and diagnostics. Keep the analysis directory intact. Absolute SARIF
source URIs are interpreted against the selected `work/source`; moving analysis
directories containing such URIs may prevent reconstruction. Databases and scratch
HOME/config directories are not read by correlation.

Within this profile, a candidate requires a complete normalized path and overlap
between the finding's region and the CodeQL result's sink in the same relative file.
Normalization already checks that each path ends at a compatible sink. Missing
columns permit line-based overlap and produce a precision warning. There is no
nearest-line fallback, confidence score, or tie-breaker that silently selects a result.

| Per-finding status | Meaning |
| --- | --- |
| `single_candidate` | One compatible result group, possibly with several alternative paths |
| `ambiguous` | Multiple compatible result groups; all are retained |
| `no_candidate` | No usable overlapping result; never proof of safety |
| `unsupported_mapping` | The rule/CWE combination is outside the reviewed mapping |
| `location_unavailable` | The finding's file or lines are absent from the capture |
| `analysis_failed` | A mapped finding has a usable location, but analysis failed |

Checks occur in that order of prerequisites: mapping, captured location, analysis
availability, then candidate matching. Global analysis and ingestion states remain
visible even when a finding stops at an earlier prerequisite. Partial normalization
can retain candidates, while warning that other candidates may be unavailable.
Duplicate scanner occurrences remain distinct and may refer to the same path.
Suppressions and scanner levels are preserved, without filtering findings out.

**Every scanner source association remains unverified.** CodeQL's source-copy check
does not establish which source bytes Semgrep scanned. Candidate records preserve
the original imported finding and its original source binding. No `StaticEvidence`
is fabricated, no binding is promoted, and no assessment or classification is emitted.
Future consumers must preserve these limitations rather than treating a candidate
as a verified association or permission to execute a test.
The [planning stage](validation-plans.md) now consumes this graph and retains unmet
prerequisites in draft plans; ambiguous or partial analysis blocks automatic planning.

## Output and security boundaries

`CorrelationDocument` schema 1.0 contains the policy and rule-definition hash,
captured snapshot, exact ingestion/analysis document hashes, analysis ID and states,
raw SARIF hash when present, and one entry per imported finding. Entries embed the
original imported occurrence, candidate result groups with ordered alternative paths
and original SARIF references, and reasons. Root diagnostics retain ingestion and
analysis diagnostics; candidate result diagnostics retain incomplete alternatives.
Original scanner and CodeQL data remain in their hashed input artifacts.

Reads are bounded and reject symlink roots, ancestor/intermediate symlinks, devices,
and FIFOs. Existing limits apply to the capture; correlation reads at most 64 MiB
per metadata document, 1 MiB per command log (at most three), and 10 MiB of SARIF.
Output permits at most 4,096 candidate relationships and 100,000 embedded path
locations; CLI publication additionally limits serialized JSON to 64 MiB. Limit
exhaustion fails explicitly instead of silently truncating candidates.

These checks detect inconsistent or accidentally modified evidence. They do not
authenticate producers, establish signatures, or defend against an owner who can
rewrite all artifacts and hashes. Inputs must be quiescent during consumption;
ordinary changes are checked, but this is not a transactional filesystem snapshot
or a hostile-concurrent-writer defense. The selected environment and installed
VulnProof policy remain trusted. No network calls or source-code imports occur.

## Verification

Default unit tests cover matching, location precision, alternatives versus ambiguity,
duplicates, unknown mappings, unavailable locations, failed/partial analysis,
serialization, tampering, filesystem boundaries, and CLI publication.

```sh
uv run --locked pytest tests/unit/test_correlation.py
uv run --locked python scripts/check_codeql_analysis.py
```

The second command requires the separately prepared pinned CodeQL bundle. It creates
an explicitly synthetic vulnerable-fixture scanner finding, captures the fixture,
runs real CodeQL analysis, and requires one candidate with unverified scanner
provenance. Patched-fixture analysis remains observational with no absence gate.
It retains synthetic SARIF locally and bounded correlation reports alongside the
existing CI diagnostics. Application code is never imported or started.
