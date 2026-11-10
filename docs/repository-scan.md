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

Exit 0 means analysis and normalization completed, including when the query returned zero paths. Exit 1 covers partial normalization, an unsupported snapshot without Python files, or a failed attempt. Exit 2 indicates rejected input or an output setup error. See the report and diagnostic logs for the reason. A modeled path records static evidence. Linking it to an individual scanner finding belongs to C2.
