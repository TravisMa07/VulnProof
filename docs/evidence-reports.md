# Evidence reports

`vulnproof report` reads one retained validation directory containing `result.json`
and produces `report.json` and a self-contained `report.html`. It works offline
without Docker, CodeQL, Semgrep, or application execution. It never reruns validation
or changes the recorded assessment.

```sh
uv run --locked vulnproof report \
  --validation .cache/validation --output .cache/report
```

The output directory must be new, its parent must exist, and it must be outside the
validation directory. Existing files and directories are never overwritten. Both
outputs are prepared before the destination is created; an ordinary publication
failure attempts to remove only files created by that invocation. Publishing the
two files is not a transaction: abrupt process termination can leave a partial
directory, which must not be treated as a complete report.

## What the report preserves

`report.json` uses report schema `1.0`, profile `single-validation-report-v1`, and
includes the complete original `EvidenceBundle`, the SHA-256 of the exact input
`result.json`, artifact observations, supported runtime details, and warnings.
There is no change to the evidence schema or its four classifications. Unassessed
bundles remain unassessed. Rendering does not choose a new static path or resolve
contradictory evidence.

The HTML presents the recorded decision and reasons, source identity and revision,
clean/dirty/unknown captured scope, modeled paths and selected path, dynamic oracle,
execution outcome, image identity, control and probe observations, and cleanup.
Artifact descriptors include declared and observed hashes/sizes, completeness,
integrity status, and bounded previews. Expand inventory entries to inspect details.

The end-to-end pipeline shows scanner finding and normalization → exact source and
revision → CodeQL modeled reachability → finding/path correlation and retained plan
→ explicit authorization and prepared image → restricted Docker execution → runtime
observations and cleanup → recorded assessment. Cards show the actual retained state,
including absent, incomplete, or failed evidence. Plan and preparation artifacts are
labeled by local artifact status; the report does not rerun their producers or assume
missing stages succeeded. Native scanner/static analysis is distinct from fixture
execution inside Docker. The graph does not expand supported scanners, vulnerability
classes, application onboarding, or runtime permissions.

The opening view explains the finding in plain language and shows two flow diagrams:
the selected modeled source-to-sink path and the recorded runtime control, canary,
probes, and cleanup. They are distinct evidence views, not an instrumented execution
trace. Repeated consecutive locations on one source line are grouped for readability;
paths with more than eight groups show the first and last three with an explicit
omission marker. Full paths and all metadata remain in expandable technical records.

Code excerpts appear only when a complete verified source artifact matches that
snapshot's file hash and its full text fits the retained preview. Excerpts are capped
at 240 characters. Missing, changed, binary, or preview-truncated source is labeled
unavailable. Probe input patterns abbreviate the random filename; exact reconstructed
inputs can be expanded. These are derived from the fixed driver's retained canary
path, not captured packet traces. Disclosure with unmet confirmation requirements
stays visibly unconfirmed; negative probes never imply safety.

The initial structured runtime detail supports PR 10b's `validation:attempt` artifact
and its versioned validation profile. It is decoded only after complete metadata and
matching bytes are verified. Its finding, path, image, observed snapshot fingerprint,
execution outcome, and positive-oracle state must agree with the enclosing execution
record. Unsupported, malformed, changed, missing, or inconsistent detail produces a
warning; the original evidence and raw bounded artifact preview remain available.
This compatibility check does not authenticate the driver or recompute classification.

## Recorded assessment versus artifact integrity

These are deliberately separate:

| Artifact status | Meaning |
| --- | --- |
| `verified` | Complete declared metadata matches observed hash and size. |
| `incomplete` | Bytes are readable, but a retained hash/size is unknown, or truncation is true/unknown. |
| `missing` | A referenced path is absent. |
| `changed` | Declared hash or size differs from the observed bytes. |
| `unreadable` | A safe regular-file read was not possible, including symlinks or special files. |
| `limit_exceeded` | A per-file or aggregate read bound prevented full inspection. |

Aggregate integrity is `failed` when any artifact is changed or unreadable;
`incomplete` when evidence is missing, limited, incomplete, or no artifact descriptors
exist; otherwise it is `verified`. Preview omission is separate from retained
artifact truncation: a complete verified file may have a shortened preview.

For example, a recorded `confirmed` result with a changed attempt artifact remains
**Recorded assessment: confirmed**, accompanied by **Retained artifact integrity:
failed**, a prominent warning, and no trusted structured attempt detail. This is a
presentation of the stored assessment, not a fresh confirmation.

A previously recorded disclosure remains visible when the assessment is `failed`
because cleanup or a later execution check failed. Negative probes, missing paths,
errors, and timeouts never establish safety. Matching local hashes proves neither
producer authenticity nor immunity to a coherent rewrite of all local evidence.
Checks describe observations during report preparation, not permanent file integrity.

## Read and rendering boundaries

- Input `result.json`: 64 MiB, validated against the existing evidence contract.
- Artifact descriptors: at most 256, all preserved in order; exceeding this rejects input.
- Artifact reads: at most 64 MiB per file and 128 MiB aggregate. A failed oversized
  read consumes its allowance; bounded reads can inspect one extra sentinel byte.
- Artifact previews: at most 16 KiB of input bytes each and 256 KiB aggregate.
- Structured control/probe body previews: at most 16 KiB each; full bounded driver
  observations remain in the JSON record.
- Each generated output: at most 64 MiB. Rendering beyond that rejects publication.

Files are read beneath the validation root using the shared descriptor-based helper.
Root, ancestor, and artifact symlinks, path escapes, devices, and FIFOs are not followed.
Malformed or unsupported result contracts reject reporting; missing/damaged supporting
artifacts generate a report with warnings. The result is reread before publication
to detect a changed input. Local storage and the producer remain trust boundaries;
this does not provide signed evidence or protection against every concurrent writer.

Every evidence value is escaped as text in HTML. Artifact paths are text, never
external/file links. Binary or control-bearing previews use base64; invisible control
characters in displayed metadata are escaped. The HTML contains fixed embedded CSS,
no JavaScript, forms, images, fonts, remote resources, or user-provided markup. A
restrictive content security policy allows only the exact embedded stylesheet.
Reports can contain sensitive source and evidence: choose where to share them.

## Exit status and verification

| Exit | Meaning |
| --- | --- |
| `0` | Both outputs written, artifact integrity verified, and all supplied execution records have supported consistent runtime detail. |
| `1` | Both outputs written with integrity or runtime-detail warnings. |
| `2` | Rejected input, unsupported contract, exceeded output bound, or publication error. |

These codes describe report generation. A faithfully rendered failed assessment can
exit `0`; a recorded confirmed assessment with missing evidence exits `1`.

The report contract schema is [report-v1.schema.json](../schemas/report-v1.schema.json).
Regenerate it using `uv run --locked python scripts/export_report_schema.py`; tests
check that the committed schema matches the models. JSON and HTML are deterministic
for unchanged inputs and artifact observations; no timestamp or absolute host root
is embedded.

Default tests cover all classifications, absent assessments, provenance uncertainty,
positive observations with cleanup failure, escaping, malformed records, damaged
artifacts, safe reads, limits, previews, CLI behavior, and publication failure.
The existing real CWE-22 integration also generates a report and checks that its
recorded confirmation and retained artifact integrity are preserved.

Batch summaries, HTML customization, revision comparisons, remediation tickets, and
a dashboard remain outside this PR. CWE-22 benchmark expansion is the next roadmap item.
