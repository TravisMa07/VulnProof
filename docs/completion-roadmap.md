# Completion roadmap: eight larger PRs

This sequence replaces framework-by-framework expansion as the active roadmap.
Target v1.0: ten bounded capabilities, reusable application onboarding, a unified
investigation workflow, and reproducible release evidence. "Most repositories" is
an ambition, not a release claim. Each supported capability covers defined behaviors,
not every instance of its CWE.

Use descriptive `feat/`, `fix/`, `docs/`, and `chore/` branches and stacked PRs.
Discuss each subsystem, implement, provide its complete uncommitted diff, then
commit/push/open the PR after owner authorization. The owner may defer merging while
implementation continues. No automatic merges. This supersedes the earlier requirement
to wait for each merge before beginning the next item.

| PR | Combined deliverable | Gate |
| --- | --- | --- |
| 1. Shared investigation architecture | Validator contracts, installed rule/query mappings, application and invocation records, shared assessment gates, CWE-22 adaptation, and reviewed file-serving support. | Historical evidence remains readable and CWE-22 regressions pass. A different oracle can consume shared evidence without copying common gates. |
| 2. Application onboarding and sandbox execution | Passive inspection, reviewable setup, authorized preparation, lifecycle/readiness, synthetic state/reset, general HTTP invocation, focused harnesses, and isolated observers/services. | Two independently developed applications run through reusable configuration; preparation, execution, network, interruption and cleanup controls pass. |
| 3. Command, SQL, template injection | Complete supported static mappings, plans, oracles, reports and benchmarks. | Repeatable vulnerable/patched cases; unsuccessful controls stop testing; unsupported and inconclusive outcomes retained. |
| 4. SSRF and XXE | Supported network/parser behaviors with isolated synthetic services. | Observations attributable to selected inputs; external egress blocked; negative/failure cases tested. |
| 5. Archive traversal and unsafe deserialization | Artifact preparation, bounded invocation, independent side-effect observations and assessment. | Synthetic effects contained; harness assumptions and application reachability distinguished. |
| 6. XSS and authorization | Isolated browser, test identities, declared access policies and controls. | Observed browser execution or an explicitly forbidden operation; repeatable patched/vulnerable cases. |
| 7. Integrated product and demonstrations | Unified resumable command, onboarding guidance, cross-class reports, second execution ecosystem and consolidated external demonstrations. | One installed build validates supported findings in at least three independent repositories across four capabilities. Every finding accounted for. |
| 8. Release hardening and v1.0 | Combined benchmark, compatibility, installation, documentation, reports and release artifacts. | Fresh-install reproduction; three fresh confirmations for advertised vulnerable benchmark cases; zero patched confirmations; execution/cleanup checks pass. |

Path traversal plus the nine additional capabilities forms the ten-capability target.
Only path traversal currently has an installed validator. These rows do not register
unsupported future capabilities as implemented product behavior.

Test independent applications from PR 2 onward; PR 7 consolidates evidence. Keep
application-specific facts in configuration. Add a framework adapter only when a
selected demonstration requires it. Stop feature expansion after PR 7; PR 8 addresses
release blockers and publishes results. Dashboards, LLM integration, and automatic
arbitrary-repository execution are outside completion requirements.

Static feasibility precedes promised mappings. Missing CodeQL paths remain missing;
operator configuration cannot replace them. Authorization and browser evidence need
their own criteria rather than being forced into taint-path semantics. Harness
observations and application-level evidence stay separate. Failed tests never prove
safety. If a capability cannot meet its gate, record the blocker and make an explicit
release-scope decision instead of counting nominal implementation as coverage.

The support matrix must list tested behaviors, execution ecosystems and scanner/tool
boundaries. Publish stage denominators: findings ingested, mappings supported,
paths correlated, applications runnable, tests completed and classifications.
Curated regression applications are not proof of broad production-repository support.
