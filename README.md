# VulnProof

VulnProof is a local-first security platform being developed to turn vulnerability findings into reproducible evidence. It combines static analysis with controlled dynamic testing to help teams investigate exploitability, prioritize remediation, and deliver developer-ready findings.

**Status: project scaffold.** The repository currently contains documentation and directory placeholders. No application code, CLI, analysis queries, test harnesses, or CI workflows are implemented. All capabilities below describe intended functionality.

## Why VulnProof

Security scanners can produce more findings than teams can manually investigate. A finding identifies a potential issue, but developers still need to understand whether attacker-controlled input can reach the relevant code, whether the behavior can be reproduced, and what evidence supports remediation.

VulnProof aims to help application security engineers, vulnerability researchers, and developers connect those steps. Its goal is evidence-backed triage: reproducible observations, transparent uncertainty, and findings that developers can act on.

## Intended workflow

```text
Ingest findings
      |
Correlate source and revision
      |
Analyze modeled source-to-sink reachability
      |
Produce structured validation plans
      |
Run authorized, isolated tests
      |
Correlate static and dynamic evidence
      |
Generate reports and remediation artifacts
```

Each stage is intended to preserve the relationship between a finding, its exact source snapshot, the analysis performed, and the behavior observed. Developer-ready outputs should explain the affected code, reproduction conditions, supporting evidence, and limitations.

## Long-term direction

VulnProof is intended to grow into an extensible platform with:

- Scanner integrations that normalize findings into a consistent evidence workflow.
- Language and framework adapters that connect static analysis to application-specific validation.
- Additional vulnerability classes supported by reviewed test strategies and explicit confirmation criteria.
- Onboarding of explicitly authorized applications through controlled execution environments and declared prerequisites.
- Integration into developer and security workflows through machine-readable results, reports, and remediation artifacts.

Additional languages and frameworks are an extensibility direction, with no specific technologies or delivery dates committed. Broader application support will require dedicated design and validation of execution controls.

## Evidence principles

VulnProof will preserve source identity, analysis provenance, validation conditions, and bounded observations so results can be reviewed and reproduced. A static path indicates modeled flow; it does not establish runtime exploitability.

| Classification | Intended meaning |
| --- | --- |
| `confirmed` | A compatible static path and successful dynamic oracle correlate to the same finding and exact source snapshot. |
| `inconclusive` | A supported attempt ran without sufficient confirming evidence, or correlation remains uncertain. |
| `unsupported` | A required mapping, analysis model, adapter, or execution capability is outside supported scope. |
| `failed` | An operational, analysis, or harness error prevented a valid conclusion. |

Static state, execution state, and final classification will remain distinct. Unknown or mismatched provenance cannot support confirmation. Unsuccessful tests, missing modeled paths, timeouts, and errors never establish safety. Benchmark ground truth will be kept independent of inferred results.

## Security model

The intended model combines local-first processing, explicit execution authorization, bounded tests, isolation, and auditable evidence. Findings and source content are untrusted inputs; they must never supply arbitrary executable test instructions or bypass execution policy.

The initial release will execute only reviewed fixtures using allowlisted templates, pinned images, restricted networking, resource limits, and controlled temporary storage. It will exclude host secrets and Docker socket mounts, and require cleanup after every outcome.

Future onboarding of authorized applications will require additional controls for preparation, dependencies, application state, and execution. Authorization alone does not establish isolation. VulnProof does not promise safe execution of arbitrary repositories or universal exploit generation.

## Roadmap

| Stage | Planned outcome |
| --- | --- |
| 1. Establish the MVP | CLI-first Python/Flask validation on trusted vulnerable and patched fixtures. Start with CWE-22 path traversal, then CWE-78 command injection; produce JSON/HTML reports and benchmark results. Semgrep SARIF, CodeQL Python taint paths, and Docker are the initial implementation choices. |
| 2. Expand validated coverage | Add vulnerability classes and scanner, language, and framework adapters as their analysis models, test strategies, and benchmarks mature. |
| 3. Support authorized applications and workflows | Develop controlled application onboarding and integrations that deliver evidence into developer and security workflows. |

The first implementation remains deliberately bounded. Dashboards, LLM integration, arbitrary repository execution, additional languages, and general request synthesis are outside v0.1. Dashboards and LLM integration are not established roadmap commitments.

See the [MVP plan](docs/mvp.md) for the initial support matrix, validation approaches, security restrictions, milestones, acceptance criteria, benchmark methodology, dependencies, and proposed CLI stages.

## Current repository

The directories below are placeholders for planned responsibilities; their presence does not imply implemented functionality.

```text
VulnProof/
├── README.md
├── docs/                   # MVP plan and future design decisions
├── src/vulnproof/          # Planned engine components
├── schemas/                # Planned versioned artifact contracts
├── codeql/queries/         # Planned initial static analysis queries
├── fixtures/               # Planned vulnerable and patched fixtures
├── templates/              # Planned report templates
├── tests/                  # Planned unit, integration, security, and benchmark tests
└── .github/workflows/      # Future CI workflows
```

Empty directories contain `.gitkeep` placeholders. Installation and usage instructions will be added when runnable functionality exists.
