# Scan a checkout with Semgrep

From the VulnProof development checkout, prepare the pinned tool once, then choose a fresh output directory outside the project being scanned. Its parent must already exist.

```sh
uv run --locked python scripts/prepare_semgrep.py
uv run --locked vulnproof scan --repo /path/to/project \
  --semgrep-environment .cache/semgrep/1.184.0 --output /path/to/new-scan
```

The command captures the whole checkout by default. Add `--component packages/search` to capture one directory and keep repository-relative finding locations. The tool installation is trusted and must be separate from the selected repository and output. The native scanner uses the [controlled scan environment](controlled-scans.md), a local rules file and bounded process supervision. Scanning reads the selected source without building the application.

## Scope and rule coverage

Capture includes regular files, including untracked files, and omits Git metadata and the named build and cache directories in the [source capture policy](source-provenance.md). A symlink, special file, or exceeded capture limit in the included scope stops the command. The current limits are 1,024 files, 4,096 entries, 32 directory levels, 8 MiB per file and 64 MiB total. Select a smaller component if needed. The output contains a private copy of the captured scope and may include sensitive files.

The v1 ruleset checks two patterns. In `.py` files it follows a request query value into the path argument of `open`. In `.js` files it checks direct evaluation of a query property. VulnProof passes eligible paths explicitly from a separate directory containing only their captured bytes. Repository ignore files and inline suppressions do not control this profile. Inspect the recorded target lists for coverage.

## Read the result

- `snapshot/` contains captured files. The versioned `scan.json` records their repository-relative paths, hashes and combined fingerprint, the optional observed Git HEAD, tool and rule identities, intended and reported target paths, command outcomes and result count. Local edits are represented by their captured bytes. HEAD alone does not establish a clean revision.
- `diagnostics/raw.sarif` feeds the same [inventory](repository-intake.md) as an imported report. `inventory.json` resolves locations against the private capture. Its generic source association stays unverified. The separate controlled scan receipt binds this invocation to its inputs and raw SARIF digest. The scanner's JSON coverage, logs and rules are retained alongside the snapshot.
- Exit 0 means the scanner completed on eligible targets and intake completed. Zero findings means these rules reported no matches. Exit 1 means incomplete coverage or intake (`partial`), or no eligible files (`no_applicable_targets`). Inspect scanner notifications and errors in the diagnostics. Exit 2 reports a failure such as invalid input, capture limits, or scanner failure. A failure before the scanner starts can leave a partial output directory. Use a fresh directory for a retry.

Dynamic validation currently runs only on approved fixtures.

## Investigate a captured checkout with CodeQL

Prepare the trusted CodeQL bundle using the [CodeQL setup instructions](codeql-analysis.md). Run the following command against the directory produced by a repository scan.

```sh
uv run --locked vulnproof investigate --scan /path/to/new-scan \
  --codeql-bundle .cache/codeql/2.27.3/codeql --output /path/to/new-investigation
```

The command checks the captured files against the scan receipt, copies them into a private working directory, and extracts one Python database with build mode set to none. It runs the bundled Python path-injection query once and records repository-relative path nodes in `investigation.json`. The report includes the component, source fingerprint, scan receipt hash, tool and query identity, commands, diagnostics, and raw SARIF reference. Component captures limit analysis to that subtree. Local artifact hashes establish consistency with the supplied receipt and assume the operator trusts its origin.

Exit 0 means analysis and normalization completed, including when the query returned zero paths. Exit 1 covers partial normalization, an unsupported snapshot without Python files, or a failed attempt. Exit 2 indicates rejected input or an output setup error. See the report and diagnostic logs for the reason. A modeled path records static evidence.

## Connect findings to CodeQL paths

For an existing SARIF file use the following preparation command. It captures the current checkout, inventories the report against that copy, and records an unverified scanner revision. Use the same optional component directory and capture limits as for a local scan.

```sh
vulnproof prepare-repository --repo /path/to/project --sarif findings.sarif --output evidence
```

An existing intake inventory can be supplied with `--inventory inventory.json` in place of `--sarif`. Preparation reuses its component and embedded SARIF and verifies its recorded file observations against the new capture.

For a local Semgrep scan use its existing output directory as `evidence`. Both workflows use these commands. An existing investigation for the same receipt can be reused.

```sh
vulnproof investigate --scan evidence --codeql-bundle .cache/codeql/2.27.3/codeql --output analysis
vulnproof correlate-repository --scan evidence --investigation analysis --output correlation.json
```

The correlator rechecks captured files, regenerates the inventory from raw SARIF and checks the investigation against its receipt and raw CodeQL evidence. It writes one entry per input occurrence, including duplicates. Candidate result and path IDs refer to the nodes in the investigation report. Exit 0 indicates that correlation produced a report. Check its counts and analysis completeness to interpret coverage. Inconsistent evidence produces exit 2.

The first shipped mapping covers the Semgrep OSS repository request-file-read rule and CodeQL Python path injection. It compares the reported region with the first argument of a direct Python open call and requires the CodeQL sink to identify that argument's full span. A sink reported with coarser coordinates can therefore have no candidate. Several compatible sinks, or a coarse scanner region spanning multiple plausible calls, yield an ambiguous result. Several paths to one sink are retained together. The mapping describes the path passed to open and makes no claim about its access mode.

Unknown mappings, missing locations, unsupported analysis and analysis failures have explicit outcomes. A completed query with no compatible path yields no candidate. Partial analyses can omit candidates. Imported producer and rule identities are declarations from the report. Captured source hashes rely on trusted local evidence storage.

## Discover application entry points

After correlation, run discovery on the same retained artifacts.

```sh
vulnproof discover-repository --scan evidence --investigation analysis \
  --correlation correlation.json --output discovery.json
```

Discovery rebuilds correlation, verifies the supplied inputs and reads the captured Python modules named by candidate paths. It performs static inspection without importing the application. Each finding keeps its correlation disposition and path references. Each distinct path has its own observations. Follow a binding's source locations to review its application declaration, handler, HTTP method, route and literal query key.

The first adapter recognizes direct Flask imports, a module-level application assignment, literal method decorators or a literal route with explicit methods, and query lookups using request.args.get. A plain route defaults to GET. The application symbol and declaration file identify the application in source. Discovery anchors each path at the first source node after any Flask request import. It binds a query input when its expression matches a CodeQL node's exact span in that handler. A path reaching only the handler produces an unresolved input. Several plausible routes remain visible.

Factories, imported application objects, dynamic registrations, parameterized route paths and unsupported expressions can leave gaps. A component capture may omit the module that registers a route. The adapter limits parsing to 256 KiB per module and 512 tokens per logical statement. Inspect each path's gaps and its binding-level gaps, as well as the correlation and analysis status. Exit 0 means the discovery document was written, including when there are no candidate paths. Inconsistent evidence is rejected. The repository planner accepts operator configuration and control expectations.

## Draft a validation plan

```sh
vulnproof plan-repository --scan evidence --investigation analysis \
  --correlation correlation.json --discovery discovery.json --output initial-plans.json
```

Read each finding's disposition and reasons. For a single supported file-open sink with complete analysis, the planner uses discovery to identify a handler. An endpoint profile supplies application-specific details. Pass it explicitly with `--config app.json` and choose a new output path. This example expects a response body whose SHA-256 you have independently recorded for the control document.

```json
{
  "schema_version": "1.0",
  "endpoints": [{
    "file": "exports/web.py",
    "handler": "export",
    "download_root": "/srv/downloads",
    "control_value": "manual.txt",
    "control_sha256": "62527d78c70ef8f47bffc15e6c5352dd6f0a751b97f620013e52c25a138aa62f"
  }]
}
```

Each captured file and handler pair can have one profile. Optional fields are `entry_point` (captured Python file and application symbol, e.g. `exports/web.py:service`), `method` (GET), `route` (local literal path), and `query_key`. A profile can fill missing values or select among discovered alternatives. A conflicting declaration blocks the finding and records both values. An incomplete analysis or competing sink results require further investigation.

The output retains every occurrence, all candidate path IDs, source locations and the origin of each selected field. Follow the draft's support references into the path bindings. The control must return HTTP 200 and exactly the expected body digest. The shared template describes fresh canary preparation, bounded requests and how to interpret observations. A failed control stops probing. An unsuccessful probe leaves safety undetermined.

A successful planning command exits 0 even if every occurrence is blocked. Modified evidence, invalid configuration or an existing output file cause an error. Planning only reads local artifacts. Drafts retain scanner provenance and require a source-bound image, execution authorization and a trusted runtime driver in the execution stage.

## Preparing the application image

After planning, [repository image preparation](repository-images.md) packages the
retained snapshot with explicit hashed dependencies. It does not start the application
or authorize execution. [Repository controls](repository-controls.md) provide E2
startup and legitimate-request checks. E3a adds [repository validation](repository-validation.md).

[Repository validation](repository-validation.md) now provides E3a bounded CWE-22 attempts and JSON
classifications. [Repository reports](repository-reports.md) provide offline HTML flows and a
complete finding inventory. E3c, the cross-repository demonstration, is the next step.
