# Implementation roadmap

Build one roadmap item at a time. Discuss the design and tradeoffs, agree on scope
and acceptance criteria, implement on a focused branch, verify, and open a PR.
Wait for the project owner's explicit merge authorization before moving on.
Split an item if it becomes too large to review; do not combine unrelated items.

| PR boundary | Outcome |
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
| 10. CWE-22 validation | Canary oracle, controls, evidence correlation, and the first complete finding-to-result workflow. |
| 11. Reports | Versioned JSON and self-contained escaped HTML with evidence, reasons, and limitations. |
| 12. CWE-22 benchmark | Four vulnerable/patched pairs, unsupported/failure cases, three-run repeatability, and hardening. |
| 13. CWE-78 static support | Reviewed fixtures, sink models, mappings, and plans using the existing execution boundary. |
| 14. CWE-78 validation | Bounded marker oracle, controls, and four-pair benchmark under the same acceptance gates. |
| 15. v0.1 readiness | Offline runs after preparation, reproducibility, platform/usage documentation, and combined results. |

PR 10 is the first end-to-end checkpoint. Complete and harden CWE-22 through PR 12
before adding CWE-78. Detailed interfaces are settled during each item's design
discussion, not assumed from this roadmap.

After v0.1, consider additional coverage and adapters, controlled onboarding of
explicitly authorized applications, developer-workflow integrations, and further
languages/frameworks. Each expansion requires demonstrated feasibility and
appropriate controls. There are no delivery dates or commitments to dashboards,
LLM integration, or arbitrary repository execution.

See the [MVP plan](mvp.md) for boundaries and acceptance gates, and
[CONTRIBUTING.md](../CONTRIBUTING.md) for development and review standards.
