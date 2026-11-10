# Implementation roadmap

Build one roadmap item at a time. Discuss the design and tradeoffs, agree on scope
and acceptance criteria, implement on a focused branch, verify, and open a PR.
Wait for the project owner's explicit merge authorization before moving on.
Split an item if it becomes too large to review; do not combine unrelated items.

## Active expansion

Milestones A and B provide repository intake and scanning. C1 investigates repository scan snapshots with CodeQL. C2 links compatible paths to individual repository findings. D1 discovers direct Flask request bindings on correlated paths. D2 combines those observations with operator configuration to draft per-finding validation plans. Milestone E will prepare and run authorized application tests. The default investigation will cover the entire checkout, with an optional component filter. Each finding will retain its identity, evidence, and the reason it stopped or advanced. Each row is a reviewable milestone that can be split into focused PRs.

| Milestone | What it will add | Acceptance gate |
| --- | --- | --- |
| A. Whole-repository SARIF intake | Accept a checkout and SARIF 2.1.0, normalize common fields, retain producer metadata, and resolve reported source locations. | The same installation will inventory reports from two SAST producers against unfamiliar checkouts. Every input result will have an accounting entry, including unknown rules and unresolved locations. |
| B. Scan the checkout | Run pinned Semgrep with a reviewed ruleset when the operator starts with source alone. Feed the raw SARIF into A and record the tool, rules, scan scope, and source identity. | A new checkout will scan without registering its filenames or fingerprint in VulnProof. Existing SARIF with uncertain revision will retain an unverified source association. |
| C. CodeQL investigation | Prepare applicable databases from the captured source, isolate any required builds, and reuse each database across findings. Match paths by source identity, sink location, and operation. | A real finding on an unfamiliar checkout will link to a compatible CodeQL path. Results will distinguish ambiguous matches, absent paths, and analysis failures. |
| D. Application setup and test planning | Use project metadata and tests to identify startup instructions, entry points, inputs, and prerequisites. Let the operator supply missing setup through application configuration. | An inspectable plan will describe how to exercise a supported finding or identify the missing prerequisite, such as a test account or input binding. |
| E. Authorized container validation | Bind the prepared image to the captured source. Reuse the CWE-22 validator to run a legitimate control and bounded probes, retain observations, verify cleanup, and report the assessment. | Pass the cross-repository checkpoint below. |
| F. Benchmark and expand coverage | Run the four-pair CWE-22 fixture benchmark alongside unfamiliar-repository cases. Count findings imported, paths correlated, applications runnable, tests completed, and outcomes with their denominators. | Three fresh repetitions will confirm each supported vulnerable fixture, yield zero patched confirmations, and retain reasons for unsupported cases and operational failures. Stage counts and evidence will guide the next scanner, application, or vulnerability class to support. |

### Cross-repository checkpoint

At E, the first project's known vulnerable revision must yield a confirmation supported by matching source, a compatible static path, a successful control, and the observed test effect. Run the same workflow against its patched counterpart and retain the scan and test evidence. If the scanner emits zero findings, record that observation and check patched behavior independently with the reviewed probes. The patched revision must yield zero confirmations.

Then select a second unfamiliar, compatible repository and exercise a supported finding with the **same installed VulnProof build and validator**. Application-specific setup will come from configuration. Needing a code change or a new fingerprint hardcoded into VulnProof to admit that project would fail the checkpoint.

The existing vulnerable/patched fixture pair will continue to provide regression coverage throughout A–E. F will expand that suite after the cross-repository demonstration. The original MVP plan records the CWE-78 validation design and release-readiness criteria for later coverage work. See the [benchmark methodology](mvp.md#verification-and-benchmark-plan).

## Delivered foundation

Milestones 1–11 established the CLI and the working fixture-based pipeline through JSON and HTML reporting.

| Milestone | Delivered outcome |
| --- | --- |
| 1. Development foundation | Packaging, locked tools, formatting, linting, types, tests, CI, and contribution guidance. |
| 2. CWE-22 feasibility | One reviewed vulnerable/patched Flask pair, a CodeQL path, container-restriction checks, and compatibility/licensing prerequisites. |
| 3. Evidence contracts | Initial versioned records and distinct provenance, static, execution, and classification states. |
| 4. SARIF ingestion | Normalized Semgrep findings, preserved scanner information, explicit input errors, and CLI output. |
| 5. Source provenance | Immutable snapshots, hashes, commit identity, dirty/unknown states, and root-escape protection. |
| 6. CodeQL integration | Repeatable snapshot-bound analysis, path extraction, version capture, and explicit analysis failures. |
| 7. Static correlation | Compatible finding/path matches with ambiguity and identity mismatches preserved. |
| 8. Validation plans | Inspectable data-only plans from trusted manifests and templates; no application execution. |
| 9. Docker runner | Approved fixture execution, enforced limits and isolation, bounded output, and cleanup. |
| 10a. Controlled scanner provenance | Real pinned Semgrep scans of reviewed fixture bytes, verified source associations, and real CodeQL correlation acceptance. |
| 10b. CWE-22 validation | Fresh canary oracle, controls, evidence correlation, and the first complete finding-to-result workflow for the reviewed CWE-22 fixture. |
| 11. Reports | Versioned JSON and self-contained escaped HTML with evidence, reasons, and limitations. |

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development checks and the owner's diff-review and merge workflow.
