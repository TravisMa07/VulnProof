# VulnProof

VulnProof is a local-first security platform being developed to turn vulnerability findings into reproducible evidence. It combines static analysis with controlled dynamic testing to help teams investigate exploitability, prioritize remediation, and deliver developer-ready findings.

The goal is to point VulnProof at an unfamiliar repository and investigate findings across the entire checkout. A user can provide an existing SARIF report or have VulnProof scan the repository with Semgrep. For each finding, VulnProof aims to trace relevant data flow with CodeQL, exercise supported behavior in an authorized container test, and report what the evidence establishes. Users can narrow an investigation to a component when useful.

## Why VulnProof

Security scanners can produce more findings than teams can manually investigate. A finding identifies a potential issue, but developers still need to understand whether attacker-controlled input can reach the relevant code, whether the behavior can be reproduced, and what evidence supports remediation.

VulnProof aims to help application security engineers, vulnerability researchers, and developers connect those steps. Its goal is evidence-backed triage: reproducible observations, transparent uncertainty, and findings that developers can act on.

## Intended workflow

An engineer clones a document service and supplies its SAST report. VulnProof will resolve the reported locations against the checkout and investigate every finding. With just the checkout, the engineer can generate the inventory by running the packaged Semgrep rules.

```text
Checkout + existing SARIF       Checkout scanned with Semgrep
                       \       /
                        Findings
                           |
              Identify source and revision
                           |
             Correlate applicable CodeQL paths
                           |
           Plan how to exercise each finding
                           |
          Run an authorized, isolated test when ready
                           |
       Report every finding, its evidence, and any stopping reason
```

For one file-read alert, CodeQL might trace a download parameter to a file read. If an authorized container test then returns the contents of a controlled file outside the download folder, the engineer will see both the modeled path and the observed disclosure. A second finding might have a path but require a test account before the application can be exercised. A third might refer to a file missing from the checkout. All three will appear in the investigation, with the last completed stage and the evidence or prerequisite that determined the outcome.

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

Today, dynamic validation runs reviewed fixtures in prepared images with restricted networking, bounded resources, and cleanup checks. Onboarding an unfamiliar application will require isolated preparation, a source-bound image, explicit authorization, and a test plan that accounts for dependencies, application state, and secrets.

## Roadmap

Repository intake now accepts a checkout and embedded SARIF 2.1.0 results from multiple producers. A local Semgrep scan can now produce that same inventory from source. Subsequent milestones will add CodeQL investigation, application setup, and authorized container tests. The expansion checkpoint will use the same installed build and validator on a second compatible repository with application configuration. The four-pair CWE-22 benchmark will follow that demonstration. See the [active expansion sequence and acceptance gates](docs/roadmap.md#active-expansion).

The [original MVP plan](docs/mvp.md) documents the fixture baseline, evidence semantics, security controls, and benchmark methodology.
The [CWE-22 feasibility experiment](docs/cwe22-feasibility.md) covers the initial
reviewed fixture pair, static-path check, and restricted container checks.
The [evidence contracts](docs/evidence-contracts.md) describe the versioned records,
source bindings, observation states, and assessment validation boundaries.

## Current CLI workflow

Use `vulnproof intake --repo /path/to/checkout --sarif findings.sarif --output inventory.json` for a whole-checkout inventory. See [repository intake](docs/repository-intake.md) for the optional component filter, supported fields, and result accounting.

To start with source alone, use the [repository scan command](docs/repository-scan.md). It captures the checkout and inventories findings from the packaged rules.

The fixture pipeline’s importer supports a subset of Semgrep SARIF 2.1.0. Controlled scanning, CodeQL analysis, and dynamic validation currently use the reviewed CWE-22 Flask fixture pair. The commands below demonstrate that workflow using a Semgrep report for the vulnerable fixture.

### Import scanner findings

Follow the [development setup](CONTRIBUTING.md#development-environment), then import the report.

```sh
uv run --locked vulnproof ingest --sarif findings.sarif --output ingestion.json
```

The output retains the original report alongside normalized findings and import
diagnostics. It does not verify source identity or assess exploitability.
See [SARIF ingestion](docs/sarif-ingestion.md) for supported inputs, exit codes,
limits, and examples. No scanner installation is needed to import existing reports.

Capture the selected source tree for investigation, then check the stored content:

```sh
mkdir -p .cache
uv run --locked vulnproof capture --ingestion ingestion.json \
  --source-root fixtures/cwe22/vulnerable --output .cache/investigation-001
uv run --locked vulnproof verify-source --capture .cache/investigation-001/snapshot
```

The output directory must be new, its parent must exist, and it must be outside
the selected source root. Capture records exact file hashes and available Git
observations without claiming that the scanner used those bytes. See
[source provenance](docs/source-provenance.md) for policy, limits, and verification
boundaries. Application execution is not part of this workflow.

Run the pinned CodeQL query against an approved fixture capture:

```sh
uv run --locked vulnproof analyze --capture .cache/investigation-001/snapshot \
  --output .cache/analysis-001 --codeql-bundle .cache/codeql/2.27.3/codeql
```

Prepare the tool separately as described in [CodeQL analysis](docs/codeql-analysis.md).
Results preserve modeled paths and diagnostics; matching them to scanner findings
is a separate stage:

```sh
uv run --locked vulnproof correlate --capture .cache/investigation-001/snapshot \
  --analysis .cache/analysis-001 --output .cache/correlation-001.json
```

See [static correlation](docs/static-correlation.md) for the initial fixture-specific
rule mapping, integrity checks, and candidate semantics. Scanner source association
remains unverified; candidates and missing paths do not establish exploitability or
safety.

Describe a reviewed fixture test without executing it:

```sh
uv run --locked vulnproof plan --capture .cache/investigation-001/snapshot \
  --analysis .cache/analysis-001 --correlation .cache/correlation-001.json \
  --output .cache/planning-001.json
```

See [validation plans](docs/validation-plans.md) for the trusted fixture template,
blocked cases, execution requirements, and unmet prerequisites. Drafts do not
authorize execution or verify scanner provenance. Execution requires the separate
authorization and evidence checks described below.

The [restricted Docker runner](docs/docker-runner.md) can now execute explicitly
authorized fixture diagnostics and a legitimate download using separately prepared
images. It verifies the execution policy and container cleanup. The separate
[CWE-22 validation command](docs/cwe22-validation.md) adds fresh-canary probes and
JSON assessments for reviewed fixtures under explicit validation authorization.

The [controlled scanner](docs/controlled-scans.md) runs pinned Semgrep against
approved fixture bytes and verifies a separate source association. Imported findings
remain unchanged. Real Semgrep-to-CodeQL integration is checked independently of
Docker; its verified source association supports the separate dynamic confirmation stage.

Generate offline JSON and self-contained HTML from retained validation evidence:

```sh
uv run --locked vulnproof report --validation .cache/validation --output .cache/report
```

See [evidence reports](docs/evidence-reports.md) for artifact integrity, bounded
previews, exit codes, and interpretation. Reports preserve the recorded assessment
and separately identify missing, changed, or incomplete evidence.

## Current repository

Most component directories below remain placeholders for planned responsibilities; their presence does not imply implemented platform functionality.

```text
VulnProof/
├── README.md
├── CONTRIBUTING.md          # Setup, checks, and review workflow
├── pyproject.toml          # Package and development-tool configuration
├── uv.lock                 # Locked development dependencies
├── tools/semgrep/          # Separate pinned scanner tool environment
├── docs/                   # MVP plan and future design decisions
├── src/vulnproof/          # CLI, ingestion, source capture, evidence contracts, planned components
├── schemas/                # Versioned evidence schema
├── codeql/queries/         # Planned initial static analysis queries
├── fixtures/               # Reviewed CWE-22 pair and planned fixtures
├── templates/              # Planned report templates
├── tests/                  # Automated checks and planned test categories
└── .github/workflows/      # Development checks
```

Empty directories contain `.gitkeep` placeholders. See [CONTRIBUTING.md](CONTRIBUTING.md)
for development installation, checks, code standards, and the commit/PR workflow.
