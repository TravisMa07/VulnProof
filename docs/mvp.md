# VulnProof MVP Plan (v0.1)

The initial implementation of the broader [VulnProof vision](../README.md): a local-first hybrid exploitability validation engine for Python Flask applications.

**Status: project scaffold.** No application code, CLI, queries, test harnesses, or CI workflows are implemented yet. Commands and capabilities described below are planned, not available.

## Purpose

VulnProof will connect static findings to bounded dynamic tests and produce reproducible evidence. The goal is to help engineers distinguish confirmed vulnerabilities from findings that need further investigation, without treating unsuccessful tests as proof of safety.

## v0.1 scope

- Ingest Semgrep SARIF and normalize findings.
- Correlate findings with source snapshots, file hashes, and commits when available.
- Use CodeQL Python taint paths to identify modeled source-to-sink flow.
- Generate structured, reviewable validation plans.
- Run isolated Docker tests only against reviewed, intentionally vulnerable fixtures and their patched counterparts.
- Start with CWE-22 path traversal, then add CWE-78 command injection.
- Correlate static paths and dynamic observations.
- Generate versioned JSON and self-contained HTML reports.
- Benchmark against vulnerable and patched fixtures.

The interface will be CLI first. v0.1 excludes dashboards, LLM integration, arbitrary repository execution, additional languages, and automatic request synthesis for unfamiliar applications.

## Initial support matrix

| Area | v0.1 support |
| --- | --- |
| Framework | Synchronous Python Flask routes |
| Attacker input | Selected query parameters; form fields deferred until after the first vertical slice |
| CWE-22 | Selected file-read sinks and reviewed path traversal templates |
| CWE-78 | Selected shell-invoking process sinks and reviewed command injection templates |
| Route and input binding | Explicit trusted fixture manifests |
| Authentication and application state | Only prerequisites declared by fixture adapters |
| Dynamic execution | Reviewed intentionally vulnerable fixtures and patched counterparts only |
| General request synthesis | Deferred |

Findings outside the trusted fixture registry may be ingested and reported statically, but cannot trigger application execution. Missing modeled paths do not establish unreachability or safety.

## Planned architecture

```text
Semgrep SARIF + exact source snapshot
                 |
       Normalize and record provenance
                 |
       Correlate CodeQL taint paths
                 |
       Build structured validation plan
                 |
       Enforce trusted-fixture policy
                 |
       Run bounded isolated Docker test
                 |
       Correlate and classify evidence
                 |
       JSON / HTML report + benchmark
```

Static analysis identifies modeled flow; it does not establish runtime exploitability. Reviewed fixture manifests will map routes, request inputs, prerequisites, and test oracles to allowlisted validation templates.

Plans will be data, not executable scripts. Untrusted SARIF fields and application content must never select shell commands, container mounts, Docker flags, or arbitrary test code.

## Evidence and classifications

Each run will record source identity, input hashes, scanner/query versions, fixture image digest, static paths, validation plan, execution outcome, and bounded dynamic evidence. Unknown or mismatched provenance must be explicit and cannot support a confirmed result.

| Classification | Meaning |
| --- | --- |
| `confirmed` | A compatible static path and successful dynamic oracle correlate to the same finding and exact source snapshot. |
| `inconclusive` | A supported attempt ran without sufficient confirming evidence, or correlation remains uncertain. |
| `unsupported` | A required mapping, analysis model, fixture adapter, or execution capability is outside supported scope. |
| `failed` | An operational, analysis, or harness error prevented a valid conclusion. |

Static state, execution state, and final classification will be recorded separately with reason codes. An absent modeled path, a timeout, an HTTP error, or an unsuccessful probe never establishes safety. Patched fixture ground truth belongs to the benchmark, not the engine's inferred classification.

## Initial validation approach

### CWE-22: path traversal

Use a fresh synthetic canary outside the fixture's permitted download directory. Verify a legitimate request first, then run bounded traversal probes. Confirmation requires observing the exact canary content through the relevant application response.

### CWE-78: command injection

Verify legitimate behavior first, then use a reviewed probe whose intended side effect is creating a fresh nonce-bearing marker inside a designated temporary directory. Confirmation requires the expected marker to be absent before the probe and present afterward. No external callbacks, real secrets, or destructive commands are needed.

## Security boundaries

- Only reviewed fixture images, pinned by digest, and allowlisted test templates may execute.
- No arbitrary repository imports, build hooks, dependency installation, Dockerfiles, or application startup during validation.
- The application and test driver will communicate over container-local loopback, with external networking disabled and no published host ports.
- Containers will run as non-root with dropped capabilities, no new privileges, a read-only root filesystem, and bounded temporary storage.
- Enforce CPU, memory, process, wall-clock, and output limits; clean up after every outcome and interruption.
- Never mount the Docker socket, host secrets, or broad host directories into fixtures.
- Validate source paths, reject root escapes and symlink escapes, bound input sizes, and escape report content.
- Prepare pinned dependencies and images separately so validation can run offline.

The host orchestrator and fixture registry are trusted. Docker reduces exposure but is not a guarantee of isolation against hostile code or kernel vulnerabilities. v0.1 is deliberately limited to trusted fixtures.

## Milestones

| Milestone | Deliverable | Acceptance gate |
| --- | --- | --- |
| M0 | Contracts, threat model, support matrix, feasibility checks | One Flask fixture yields a usable CodeQL path; container restrictions work on the development platform. |
| M1 | Ingestion, provenance, and static correlation | Malformed inputs, stale snapshots, duplicates, path escapes, and ambiguous matches receive explicit outcomes. |
| M2 | Complete CWE-22 vertical slice | Vulnerable fixtures confirm; patched counterparts never confirm; reports retain negative-result uncertainty. |
| M3 | Complete CWE-78 vertical slice | Only the permitted marker effect is observed; patched counterparts never confirm. |
| M4 | Hardening, benchmark, and documentation | Pinned offline runs reproduce classifications and pass security and acceptance checks. |

Complete CWE-22 end to end before adding CWE-78.

## Verification and benchmark plan

Begin with four vulnerable/patched fixture pairs per CWE, covering direct flow, helper functions, branching, and relevant normalization or quoting boundaries. Keep benchmark ground truth independent of engine results and include unsupported and operational-failure cases.

Test SARIF parsing, source identity, stale artifacts, sink correlation, plan validation, unauthorized execution rejection, oracle controls, fresh nonces, resource limits, network denial, cleanup, report escaping, and output schemas.

Initial release gates:

- Every declared supported vulnerable fixture is confirmed.
- No patched fixture is confirmed.
- Every confirmation includes exact provenance, compatible static evidence, and a successful dynamic oracle.
- Unsupported and failed cases have accurate reason codes.
- Classifications reproduce across three fresh runs per supported fixture.
- No unsuccessful attempt produces a safety claim.

Measure confirmation precision, recall within supported vulnerable fixtures, patched-fixture confirmation rate, outcome distribution, and median/p95 runtime. Separate cold CodeQL analysis from warm runs. A small fixture benchmark does not establish effectiveness across arbitrary real-world applications.

## Planned dependencies

Python, Flask, CodeQL CLI and Python query packs, Docker, Pydantic, Typer, Jinja2, and pytest. Semgrep will generate benchmark inputs; importing existing SARIF should not require a local Semgrep installation.

Exact versions and supported host configurations will be selected and pinned during M0. Verify CodeQL licensing for the intended analysis use before implementation, especially for private code.

## Planned CLI stages

`ingest`, `analyze`, `plan`, `validate`, `report`, and `benchmark`.

These are proposed interfaces only. Installation and usage instructions will be added once runnable functionality exists.

## Technical references

- [Semgrep CLI reference](https://semgrep.dev/docs/cli-reference)
- [CodeQL path queries](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)
- [CodeQL CLI and availability](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [Docker security](https://docs.docker.com/engine/security/)
