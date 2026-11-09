# Structured validation plans

The `plan` command describes the controlled CWE-22 investigation associated with a
reviewed fixture candidate. It produces **drafts**, with explicit unmet prerequisites,
or blocked entries. It executes no application, scanner, extractor, container, build,
dependency installation, or network request. A draft never authorizes execution and
never supplies an exploitability assessment.

## Use and outputs

After [capture](source-provenance.md), [analysis](codeql-analysis.md), and
[correlation](static-correlation.md):

```sh
uv run --locked vulnproof plan \
  --capture .cache/investigation-001/snapshot \
  --analysis .cache/analysis-001 \
  --correlation .cache/correlation-001.json \
  --output .cache/planning-001.json
```

The output must be new, outside the capture and analysis directories, and distinct
from the correlation input. Its parent must exist. Publication uses the existing
atomic, no-overwrite file operation. Exit **0** means planning completed, even if
every finding is blocked or there are zero findings. Exit **2** means invalid or
changed evidence, unsupported fixture binding, malformed packaged policy, limits,
IO, existing output, or invalid usage. Stdout summarizes draft/blocked counts and
`execution_authorized: false`. Detailed reasons remain in the document.

`PlanningDocument` schema **1.0** retains the complete correlation observation graph,
the SHA-256 of the exact supplied correlation bytes, catalog identity and hash,
selected fixture binding, validation template, execution requirements, and one
ordered planning disposition per imported occurrence. The embedded correlation
retains capture identity, ingestion/analysis hashes, scanner provenance, paths,
diagnostics, suppression metadata, and duplicate references.

Drafts reference the selected result group and **every** alternative path in it.
They do not assert that an HTTP probe exercises each path. Duplicate findings stay
separate; execution deduplication is not part of planning. There are no generated
runtime nonces, payload strings, image selections, Docker options, scripts, or
assessment classifications.

## Input verification and eligibility

Planning reconstructs correlation from retained capture and analysis artifacts,
using the existing integrity, fingerprint admission, artifact bounds, source-copy,
and SARIF normalization checks. The supplied correlation must equal that
reconstruction. Equivalent JSON whitespace is allowed; the exact supplied bytes
are hashed. Edited candidates, omitted findings, stale policy, and conflicting
provenance cannot silently select tests.

| Correlation observation | Planning disposition |
| --- | --- |
| Complete analysis and one candidate result group | `draft` |
| Partial analysis, including a surviving candidate | `blocked`: `analysis_partial` |
| Multiple result groups | `blocked`: `ambiguous` |
| No compatible candidate | `blocked`: `no_candidate` |
| Unsupported mapping or unavailable finding location | `blocked` with the original status |
| Failed analysis | `blocked`: `analysis_failed`, subject to the original correlation prerequisite status |

Partial analysis takes precedence because missing results may hide ambiguity.
Other blocked reasons follow correlation's prerequisite status. Original diagnostics
remain embedded, so a single primary reason does not discard other observations.
Blocked is a planning disposition, not the eventual `unsupported`, `inconclusive`,
or `failed` vulnerability classification. Missing paths and unsuccessful probes
never establish safety.

Every draft lists four unmet prerequisites:

- `scanner_source_unverified`: historical scanner source association and rule
  definition remain unverified; confirmation needs a separately reviewed solution.
- `execution_authorization_required`: explicit execution authorization and runner
  admission/policy checks must occur separately.
- `approved_image_required`: a separately prepared, reviewed immutable image must
  be bound to the fixture and execution. The planner does not inspect Docker.
- `runtime_oracle_required`: a trusted driver must implement the controls, fresh
  canary, bounded probes, and observations described by the template.

These prerequisites are recorded, not automatically satisfied by plan generation.
Scanner-source uncertainty is retained for investigation; it does not become an
execution permission or a verified finding-to-source association.

## Trusted fixture bindings and template

The packaged
[`planning/catalog.json`](../src/vulnproof/planning/catalog.json)
contains the reviewed route/input bindings for both current fixture identities,
one `cwe22-file-read-v1` template, and `fixture-isolation-v1` execution requirements.
Fixture IDs reference the existing static approval manifest; there is no second
fingerprint registry. Both bind `GET /download`, query parameter `name`, fixed
download root `/fixture/downloads`, and legitimate document `example.txt` with its
expected SHA-256. There is no external catalog option or source-directory discovery.

The template describes this ordered sequence:

1. **Legitimate-request control:** download the known document, requiring HTTP 200
   and its exact expected content. A failed control stops probes without a conclusion.
2. **Prepare a fresh canary:** the future trusted driver creates a nonce-bearing
   synthetic file under `/tmp/vulnproof`, outside the download directory. Require
   a fresh 32-byte nonce and initial absence of the selected canary path.
3. **Parent-directory traversal probe:** use the reviewed runtime canary path recipe
   to attempt leaving the download directory.
4. **Absolute-path probe:** use the same runtime canary's absolute path.

The two probe criteria require HTTP 200 and the exact fresh canary response body.
They describe positive observations, not expected behavior based on whether a
fixture is labeled vulnerable or patched. Each response is bounded to 65,536 bytes
with a three-second request timeout. Failed probes do not establish safety.

The input values in the template are fixed symbolic recipes, not interpolated SARIF
text. Runtime filename generation, nonce encoding, URL encoding, canary creation,
HTTP dispatch, and oracle evaluation belong to subsequent runner/validation work.
This PR does not modify the PR 2 driver or reuse its baked-in canary as fresh evidence.
The [PR 9 runner](docker-runner.md) implements a separate diagnostic profile;
it does not execute these canary/probe steps or satisfy the runtime-oracle prerequisite.
The patched fixture is admitted for planning, but a missing candidate never causes
the planner to invent one or produce a benchmark-only plan. Benchmark scheduling
is a separate concern.

## Execution requirements and security boundary

The plan describes a required future execution profile: non-root, read-only root,
all capabilities dropped, no new privileges, external network disabled, no published
ports or host mounts, container-local loopback, one CPU, 256 MiB memory, 64 processes,
16 MiB temporary storage with noexec/nosuid/nodev, a 60-second deadline, and 1 MiB
captured output. Require a fresh container and cleanup on every outcome. Validation
must not install dependencies or build repositories.

These are **requirements**, not measurements or guarantees that a container has
been prepared or restricted. PR 9 must bind approved images and enforce the policy;
PR 10 must implement the CWE-22 runtime oracle. Consumers must revalidate evidence,
the installed catalog, and execution authorization rather than trusting editable
JSON. Structural model validation alone does not authenticate a plan.

Planning reads correlation metadata with the shared bounded, descriptor-relative
regular-file reader. Roots, ancestors, intermediate symlinks, final symlinks,
devices, and FIFOs are rejected. Correlation input and serialized planning output
are each limited to 64 MiB; inherited correlation and source limits still apply.
Limit exhaustion fails without publishing a partial plan.

Untrusted scanner metadata can remain in the embedded evidence graph but cannot
select endpoints, templates, images, commands, mounts, or execution options. The
host, installed policy, and evidence owner remain trusted. Integrity checks are not
signatures and do not defend against an owner rewriting all evidence and hashes.
Inputs must remain quiescent; verification is not a hostile-writer transaction.

## Verification and future changes

```sh
uv run --locked pytest tests/unit/test_planning.py
uv run --locked python scripts/check_codeql_analysis.py
```

Default tests need no Docker, Semgrep, or CodeQL. The real integration requires the
separately prepared pinned CodeQL bundle, uses explicitly synthetic scanner SARIF,
and retains a vulnerable-fixture draft with unmet prerequisites. Patched observations
remain unconstrained; absent findings do not become a safety verdict. Bounded
planning reports are included with existing CI analysis diagnostics.

Public entry points are `vulnproof.planning.create_plans`, `PlanningDocument`,
`planning_catalog`, and `PlanningFailure.code`. There are no new dependencies or
migrations to existing artifact schemas. Catalog semantics, fixture bindings,
template behavior, or execution requirements need reviewed version/hash changes
and behavior/security tests. Additional templates, arbitrary applications, runtime
authorization, and final classification remain outside this PR.
