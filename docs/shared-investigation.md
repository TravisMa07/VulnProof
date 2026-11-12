# Shared investigation architecture

The active [completion roadmap](completion-roadmap.md) begins by separating installed
policy, application identity, invocation, execution observations and assessment.
This PR incorporates the reviewed Flask file-serving support. It adds no new
vulnerability class, application startup permission, or repository-provided plugin.

## Installed capabilities

`investigation.capabilities` maps producer/rule identity to a sink family, pinned
query and validator. All four current repository rules map to the Python path query
and `cwe22-file-read-v1`. The analysis stage uses the same installed query path/hash;
correlation uses the mapping's sink family. Unknown producers and rules remain
unsupported. Query and oracle registries contain only actually implemented policy.
The current executor still runs the one supported Python query once per snapshot;
this PR does not claim a multi-language or multi-query scheduler.

## Application and invocation identity

New repository attempts use schema 1.2 and retain `context` plus an explicit
`validator_id` for validation attempts (controls have no selected validator):

- `application` schema 1.0: captured source fingerprint, declared Flask object entry
  point, immutable image ID, and preparation-receipt hash. Identity is reusable across
  findings and contains no scanner finding ID.
- `invocation` schema 1.0: HTTP method, exact legitimate target, expected status/body
  hash, selected input location/name, and optional versioned request profile.
- `context` schema 1.0 combines these two contracts. They are checked against the
  enclosing attempt rather than trusted as a separate source of truth.

Shared `GetRequest` and `FixedParameter` records use the existing request builder;
path/query encoding is unchanged. The application adapter remains
`python-flask-object-v1`; command startup, services, secrets, writable state and
preparation hooks belong to PR 2 rather than placeholder executable fields here.

Attempt schemas 1.0 and 1.1 remain readable without context. Existing result/plan
profiles remain unchanged. Report preparation compares parsed runtime records so
optional new fields do not invalidate old attempts. Historical query profile 1.0
and path profile 1.1 retain their original semantics.

## Assessment and execution dispatch

The repository adapter translates retained attempts into `ValidationEvidence`:
execution, policy and cleanup states, control validity, scanner-source association,
invocation and class-specific observations. The shared assessor checks operational
prerequisites before invoking an installed oracle. An imported unverified source
cannot support a confirmation. The CWE-22 oracle validates bounded marker evidence
and exact targets as before. Four classifications and their existing reasons remain.

The packaged observer dispatches to reviewed installed handlers only, after a
successful legitimate control. Old payloads without a validator ID retain the
CWE-22 handler. Unknown handler IDs stop before application startup. The host checks
validator dispatch before execution; there is no dynamic import from repository input.
Adding a future capability requires a reviewed mapping, query/model feasibility,
planning behavior, worker, oracle, and benchmarks. A callback test proves common
gates can support another observation shape; it does not register another product
capability or establish its feasibility.

The driver changed, so existing prepared images must be rebuilt. The receipt still
binds its hash and recipe. Isolation limits, authorization and the local trust model
remain unchanged. Driver/application process separation is not hostile-code attestation.
