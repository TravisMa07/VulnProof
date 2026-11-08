# Semgrep SARIF ingestion

Ingestion records what a scanner reported. It does not establish source identity,
modeled reachability, validation support, or exploitability. No application code,
scanner, CodeQL, or Docker is executed by this stage.

## Use

After the development installation in [CONTRIBUTING.md](../CONTRIBUTING.md):

```sh
uv run --locked vulnproof ingest --sarif findings.sarif --output ingestion.json
# Equivalent module entry point:
uv run --locked python -m vulnproof ingest --sarif findings.sarif --output ingestion.json
```

Use a new output filename for each invocation. The parent directory must exist.
The output is one self-contained JSON document, written with owner-only permissions
and published atomically without replacing an existing file or symlink. Filesystems
must support same-directory hard links; publication errors fail explicitly.
Temporary files are removed on handled errors and interruption. Abrupt process
termination can leave an unpublished `.vulnproof-*` temporary file; it cannot leave
a partially written final output. Input and output directories are user-selected,
trusted locations; this does not defend against a hostile directory owner.

The importer accepts a regular local UTF-8 file without a byte-order mark. It does not consume stdin, FIFOs,
devices, remote URLs, external property files, or referenced source files. An
explicitly selected input symlink may point to a regular file. SARIF source paths
are only interpreted as data, never opened or resolved on the host.

| Exit | Meaning | Output |
| --- | --- | --- |
| `0` | All readable results imported; warnings may remain | Complete ingestion document |
| `1` | Results/runs rejected, invalid scan metadata, or scanner-reported problems | Partial ingestion document with usable findings and diagnostics |
| `2` | Usage, file IO, publication, document format, or document limit error | No new output |

A JSON summary goes to stdout after successful publication. Diagnostics go to
stderr and are also retained in the document. Scanner-controlled messages and
paths are not interpolated into terminal diagnostics. `complete` describes the
import, not the completeness or success of the scanner's analysis. For example,
a fully imported run with no invocation information has scan status `unknown`.
An empty report is not evidence that the application is safe.

## Supported input and mapping

This is a Semgrep SARIF **2.1.0 subset importer**, not a general SARIF validator.
It checks fields needed for normalization. Unknown fields remain in the original
report without being interpreted. The producer name is a reported label, not
authentication: accepted case-insensitive driver names are `Semgrep`, `Semgrep OSS`,
`Semgrep CE`, and `Semgrep Pro`.

| Input | Interpretation |
| --- | --- |
| `tool.driver.name`, `semanticVersion` (or `version`) | Reported scanner identity; omitted version stays unknown |
| `ruleId` / `ruleIndex`, or `rule.id` / `rule.index` | Driver rule identity; conflicting references and ambiguous descriptors are rejected |
| `tool.driver.rules[].properties.tags` | Explicit `CWE-N` or `CWE-N: description` tags, deduplicated and sorted; other tags preserved only in the original |
| First `locations[].physicalLocation` | Primary relative source path and positive line/column range |
| `message.text` or `message.markdown` | Required nonempty result message, retained in original data |
| `level` | Explicit result level; absent stays null, without applying descriptor defaults |
| Nonempty `suppressions` | Flagged as present; retained without filtering findings or deciding whether suppression is justified |
| `invocations` | Separate scanner status: `unknown`, `reported_success`, or `reported_problems` |

Only a direct relative artifact URI with no base or the logical `%SRCROOT%` base
is normalized. A defined host URI for `%SRCROOT%` is not followed; the relative
suffix is retained without claiming a verified source root. URI escaping is decoded
once. Absolute paths, other bases, artifact-table indexes, extension rule references,
query/fragment delimiters, invalid/double percent encoding, controls, backslashes,
root escapes, and non-normalized paths are diagnosed. Missing physical locations
or regions cannot become a `Finding`. Additional locations remain in the original
report and produce a warning; they are not expanded into additional findings.

Rules do not need to be allowlisted for ingestion. An unfamiliar rule with a usable
location is imported; missing rule descriptors/CWE tags produce unknown CWE
metadata rather than inference from a rule name. CWE syntax is checked, not
membership in a current CWE catalog. Missing rule identity is rejected.

Each supported run gets a distinct source placeholder with no content fingerprint,
file hashes, commit ID, or dirty-state claim. Findings use an `unverified` binding.
Reported source-control metadata stays in the original report; PR 5 must establish
source provenance before later stages can rely on it. The separate
[capture workflow](source-provenance.md) now records the investigation target's
content while retaining unverified scanner associations and leaving ingestion unchanged.

## Output and reproducibility

`vulnproof.ingest.ingest_sarif(data: bytes) -> IngestionDocument` is a pure importer.
`ImportFailure` exposes a stable `code` for whole-document failures. The CLI handles
file IO and publication. `argparse` adds no runtime dependency.

The versioned ingestion document (`schema_version: "1.0"`) contains:

- `raw_sarif`: the original UTF-8 text, including whitespace and line endings.
  Re-encoding this string as UTF-8 recovers the exact accepted input bytes.
- `input_sha256` and `input_size_bytes`: identity of the report, **not** of source code.
- `runs`: producer identity, readable result counts, import/rejection counts, and
  scanner status. An unreadable result array has an unknown count and a run diagnostic.
- `snapshots` and `findings`: PR 3 records with source placeholders and per-occurrence
  run/result positions, suppression presence, explicit level, and duplicate references.
- `diagnostics`: reason codes, warning/error severity, JSON Pointer, and explanation.
  Run-level rejections account for every result in that readable run array.
- `result_count` and `status`: total readable results and complete/partial import state.

`Finding.original_ref` is a fragment such as `#/runs/0/results/1` **within the
retained SARIF**, not within the ingestion document. Raw messages, fingerprints,
severity defaults, fixes, snippets, additional locations, and scanner extensions
remain accessible there. The envelope checks retained input identity, reference
and count consistency when loaded; these checks do not authenticate scanner claims.
The original report may contain sensitive scanner data; it is deliberately not redacted.

Finding IDs combine the report SHA-256 with run/result indexes. Unchanged input
bytes produce identical output without timestamps or machine-specific input paths.
Whitespace changes or reordered results change report/occurrence identity. These
are not cross-revision finding identities. Within each run, structurally identical
results are retained and reference the first imported occurrence via `duplicate_of`.
Key order is ignored for this comparison; fingerprints alone never merge findings.
No cross-run deduplication is performed.

## Errors and limits

Malformed JSON, duplicate keys at any depth, non-finite numbers, invalid UTF-8,
lone surrogate escapes, unsupported versions, and unusable top-level documents
fail without publishing an ingestion document. Limits are 10 MiB input, 64 JSON
nesting levels, 128 runs, and 10,000 total results. A run with more than 10,000 rule
descriptors is rejected with its results accounted for. Limits bound routine
processing, not every possible memory or resource attack.

Individual invalid results are rejected while siblings are retained. Reason codes
distinguish `invalid_result`, `invalid_rule_reference`, `invalid_location`,
`invalid_cwe_metadata`, and `invalid_result_metadata`. Invalid/unsupported run metadata
produces `unsupported_run`. Every original result remains in `raw_sarif` even if
normalization fails. Warnings identify unknown CWEs, duplicates, suppression presence,
additional locations, and unknown scan completion.

Unsuccessful invocations and execution/configuration notifications other than level
`none` produce `scanner_reported_problems`. Notification levels omitted by the
producer are treated as warnings. Invalid invocation metadata produces an error
and leaves scan status unknown. These import/scan states are separate from
`confirmed`, `inconclusive`, `unsupported`, and `failed` vulnerability assessments;
ingestion assigns none of those classifications.

## Verification and limitations

Automated tests use authored synthetic reports and exercise multiple runs, partial
imports, reference conflicts, metadata, path/JSON bounds, round trips, repeatability,
exit codes, no-overwrite publication, interruption, and installed entry points.
They require no scanner installation or network access.

A manual compatibility check also imported both results from Semgrep's upstream
[`notrace-cwe_tag` snapshot](https://github.com/semgrep/semgrep/blob/692bfae4ca1bf070f7e8b603037a19886fa36b4f/cli/tests/default/e2e/snapshots/test_output_sarif/test_sarif_output/notrace-cwe_tag/results.sarif).
The unmodified snapshot is 3,148 bytes, SHA-256
`540d6e9128e1c6ca91cc7d8f44f27c305785bb8229dfacf88901f0f3d3c0cf84`.
It uses masked tool-version data and synthetic CWEs; it is not a live scan or a
validated vulnerability. The download is a local ignored artifact, not a CI dependency
or vendored fixture. Compatibility with every Semgrep version/edition is not implied.

See [Semgrep's field reference](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)
and the [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
for the underlying formats. Importing finding data never authorizes application execution.
