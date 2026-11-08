# Evidence contracts (PR 3)

These records describe one finding, its evidence, and an optional supplied assessment.
They validate internal consistency. They do not scan code, hash files, verify
producers, run applications, correlate expressions, or choose a classification.
The PR 2 feasibility script and its outputs remain unchanged.

## Public interface and records

Import the public types from `vulnproof.models`. The persistence boundary is
`EvidenceBundle.model_validate_json(payload)`, where payload is JSON text or bytes.
Serialize with `bundle.model_dump_json(indent=2)`. Validation raises Pydantic's
`ValidationError`; this PR adds no CLI or filesystem loader.

| Type | Responsibility |
| --- | --- |
| `Finding` | Scanner identity, rule, original reference, declared CWEs, location, and source binding. |
| `SourceSnapshot` | Opaque snapshot ID, optional SHA-256 content fingerprint, commit, dirty state, and known file hashes. |
| `SourceBinding` | An evidence producer's claimed association between expected and observed snapshots, with a state and reason. |
| `StaticEvidence` / `StaticPath` | Tool/query metadata, analysis outcome, ordered path locations, reasons, and artifacts. |
| `ExecutionEvidence` | Attempt outcome, oracle observation, image identity, targeted static path, reasons, and artifacts. |
| `Assessment` | Supplied classification, reasons, and explicitly selected static/path/execution references. |
| `Artifact` | Bundle-relative path, media type, optional hash/size, and known/unknown truncation state. |
| `EvidenceBundle` | Versioned envelope containing one finding, its records, and their validated reference graph. |

Supporting types are `Reason`, `ToolIdentity`, `SourceFile`, and `SourceLocation`.
Record IDs are opaque strings, unique across all record categories and path IDs
within one bundle. ID generation and content fingerprint computation are deferred
to later producer stages. Reason codes are extensible identifiers accompanied by
nonblank explanations, not a second classification system.

An unassessed bundle has `assessment: null`; ingestion and other intermediate stages
do not need to invent a verdict. This is an absent assessment, not a fifth classification.
One bundle can retain multiple paths and attempts. An assessment explicitly selects
at most one static/path pair and one attempt as its support. This avoids implicitly
mixing observations from different attempts. Other records remain available for
review. Batch storage and run-wide aggregation are outside this version.

## Source identity and provenance

A Git commit identifies committed content, not necessarily the bytes in the current
working tree. A dirty working tree can have the same parent commit and different
file content. Snapshot fingerprints identify content; they are not interchangeable
with commit IDs or Docker image IDs. Dirty content is permitted and is not itself
a failure or an untrusted state.

An opaque snapshot ID may name an investigation target whose content fingerprint
is not yet known. Its presence alone is not evidence of a captured snapshot.

Source bindings name an expected snapshot (the finding's investigation target) and
an observed snapshot when known. Every binding must reference records in the bundle.
All evidence in this single-finding envelope uses the same expected target.

| State | Representation and requirement |
| --- | --- |
| `unverified` | Default state; a reason is required. The observed snapshot may be absent. Equal hash claims never automatically promote it to matched. |
| `matched` | Explicit producer assertion; both snapshots must have equal content fingerprints. Overlapping declared file hashes must agree. A commit alone is insufficient. |
| `mismatched` | Explicit producer assertion; both snapshots must have different content fingerprints. Evidence is retained, but cannot support confirmation of the target. |

Matching is a relationship, not a global verified badge. A producer must establish
that an analysis actually used its claimed snapshot, and that execution used an
image built from its claimed source. These models compare declared identities;
they cannot establish that association from a hash supplied in JSON. An image ID
alone does not establish source provenance. Source capture and verification belong
to PR 5 and the later analysis/execution integrations.

Unknown commit, dirty state, tool version, hashes, and artifact truncation remain
`null` where the relevant fields allow it. A file list contains known hashes; it
does not assert that the list is a complete manifest. The snapshot fingerprint
algorithm and capture/verification policy are defined by the
[source provenance producer](source-provenance.md). Its complete file manifest
does not establish what a scanner or an execution image actually used.

## Observations and assessments

Static outcomes are `path_found`, `no_path_found`, `unsupported`, `failed`, and
`not_run`. Only `path_found` carries complete typed paths, each with at least two
ordered locations. Other outcomes require reasons. Partial analysis output can
remain in referenced artifacts. `no_path_found` means no modeled path was returned;
it does not establish unreachability.

Execution outcomes are `completed`, `failed`, and `not_run`. Oracle observations
are separately `observed`, `not_observed`, and `not_evaluated`. An evaluated oracle
needs an identifier; a positive observation also needs artifact references.
Failed/not-run attempts require reasons. A not-run attempt cannot claim an evaluated
oracle. Failed attempts may preserve an observation obtained before their failure,
but they cannot support confirmation under the initial completion requirement.

Classifications remain `confirmed`, `inconclusive`, `unsupported`, and `failed`.
Every supplied assessment requires reasons. There is no safe classification.
An unsuccessful completed test is representable without claiming safety.

A `confirmed` assessment is accepted only when:

- It selects an existing static path and a completed, positive execution attempt.
- That attempt explicitly targets the same static record and path.
- Finding, static evidence, and execution all claim matched provenance to the target.
- The static evidence declares a CWE present in the finding and its selected sink
  overlaps the finding location.
- The execution records an immutable image ID and references at least one hashed
  artifact explicitly declared non-truncated. Unknown truncation does not qualify.

These are necessary structural guards. Overlapping locations and declared CWEs do
not prove semantic compatibility. Hashes are not checked against real files. The
model cannot know whether an oracle was implemented correctly. A fabricated record
can be well formed. Producers remain responsible for the claims they make.

This PR does not implement a classifier or automatically derive a verdict. The
later deterministic assessment function will decide what the available evidence
supports, including precedence among non-confirming outcomes. The models constrain
its output and prevent unsupported confirmation claims. Retained non-selected
attempts are not silently used to upgrade or downgrade a supplied verdict.

## JSON, paths, schema, and compatibility

- `schema_version` is required and must equal `"1.0"`. Unknown versions fail with no
  migration, fallback, or discarded fields. Incompatible field, state, or validation
  changes require a reviewed schema-version change.
- Records reject extra fields and type coercion, including string/bool line numbers.
  Records are frozen and repeated values use tuples to avoid accidental mutation.
- JSON arrays become tuples through `model_validate_json`. When validating Python
  objects directly, supply the declared Python types, including tuples. Use
  `model_dump()` for a Python round trip and `model_dump_json()` for JSON.
- Source and artifact paths are normalized relative POSIX strings. Root escapes,
  URI/drive paths, backslashes, NUL, and redundant path components are rejected.
  Source paths are relative to the analyzed snapshot; artifact paths are relative
  to an external evidence directory. No files are opened and no symlink containment
  is checked by these lexical rules. Filesystem checks belong to later I/O stages.
- Lines and columns are 1-based. End lines are inclusive; supplied end columns are
  exclusive. Missing bounds mean unavailable information. Known bounds must be
  ordered. Region overlap is a structural check, not expression correlation.
- `schemas/evidence-bundle-v1.schema.json` is generated from the models with JSON
  Schema Draft 2020-12 metadata. Do not edit it independently.

Regenerate the schema after intentional model changes:

```sh
uv run --locked python scripts/export_evidence_schema.py
```

The existing test job compares the checked-in schema with current model output.
JSON Schema describes the structural types and field constraints. Python validators
also enforce reference relationships, normalized paths, and confirmation guards;
those checks are not all encoded in the generated JSON Schema. External consumers
must not interpret passing JSON Schema alone as full contract validation.

Use normal validation at untrusted boundaries. Pydantic's `model_construct` and
unchecked `model_copy(update=...)` intentionally bypass validation; they are not
supported loading paths. Revalidate modified data instead of treating frozen
models as an authentication or security boundary.

## Examples and acceptance

The seven JSON examples under `docs/examples/evidence/` are hand-authored explanatory
records: confirmed, inconclusive, unsupported, failed, source-mismatch, no-path,
and unassessed.
Their repeated-character hashes, scanner versions, image IDs, and artifact paths
are fictitious. They are not live scan results, fixture ground truth, or real
attestations, and do not claim the referenced files exist.

Tests cover example and JSON/Python round trips, schema drift, strict inputs,
unknown fields/versions, source references and hashes, dirty-source distinctions,
path/attempt selection, stage invariants, incomplete evidence, contradictory
confirmation claims, and validation without artifact reads. The package also needs
to expose the models when installed from its built wheel. PR 2's experiment remains
independent and its default unit tests continue to run.
