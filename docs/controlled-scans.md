# Controlled fixture scans

PR 10a adds real Semgrep scans of the two approved CWE-22 fixture fingerprints.
It establishes scanner-to-source association for PR 10b's future evidence assembly.
It does not execute Flask, run validation probes, or produce assessments.

## Preparation and reproduction

Use the documented Python 3.14.10 and uv 0.13.6 development environment. Preparation
requires networking. Semgrep OSS 1.184.0 and its transitive dependencies have a
separate hash-bearing `tools/semgrep/uv.lock`; they are not runtime dependencies.
The preparation script checks that lock against the packaged scanner profile and
installs binary wheels only. Unsupported wheel platforms fail preparation.

```sh
uv sync --locked
uv run --locked python scripts/prepare_semgrep.py
mkdir -p .cache
uv run --locked vulnproof scan-fixture \
  --source-root fixtures/cwe22/vulnerable \
  --semgrep-environment .cache/semgrep/1.184.0 \
  --output .cache/vulnerable-scan
uv run --locked vulnproof verify-scan \
  --scan .cache/vulnerable-scan --output .cache/vulnerable-association.json
```

Outputs must be new. Source must match an approved fixture; output and tool
environment must be outside it. The environment is a trusted, operator-prepared
tool installation. Its marker records the reviewed lock, not a cryptographic
attestation of every installed file. Keep that environment private and trusted.

The native scanner receives a private copy and the packaged
`vulnproof.fixture.cwe22.file-read` rule. It receives a minimal environment without
inherited credentials, registry configuration, or user Git configuration. OSS mode,
metrics off, version checks off, and local explicit configuration avoid intentional
service calls. This native process is not network-sandboxed; offline operation can
be enforced externally after preparation. The fixture is read as source and is
never imported or executed. No repository-provided build, plugin, or command runs.

## Evidence and failure behavior

`scan.json` records tool/rule/profile identity, source manifest, command outcomes,
and hashed retained evidence. `diagnostics/` contains raw SARIF and stdout/stderr;
`capture/snapshot/` contains the normal provenance capture; `work/` retains private
scanner inputs. The original selected source is captured after scanning so its Git
revision and dirty state remain meaningful. Both original and private-copy content
must match the scanned manifest after execution. Snapshot identity describes exact
bytes and is distinct from a clean commit claim.

`verify-scan` rechecks artifacts, input copy, current policy, normalization, and
capture relationships. It emits pairs of original and derived findings. Only the
derived source binding changes to `matched`; occurrence IDs, locations, scanner
metadata, and original records remain intact. Ingestion, correlation, and planning
records are not rewritten. Imported SARIF alone cannot use this route to acquire
verified provenance. The association is not execution authorization or confirmation.

Version checks have a 30-second deadline; scans have a 120-second deadline, with
Semgrep's own 10-second rule timeout. Each stage retains at most 1 MiB combined
stdout/stderr; SARIF is limited to 10 MiB. Polling can allow transient disk overshoot;
these are retained-output bounds, not filesystem quotas. Process groups are stopped
on completion and failure. Interrupted executions retain a failed receipt when
possible. Failures cannot establish association; malformed or partial SARIF,
out-of-scope rules/locations, changed inputs, or incomplete logs are rejected.

The receipt is local evidence from a trusted producer, not a signature. A party
that can coherently rewrite all receipts and artifacts is outside this trust model.
Protect the working directory and prepared tools. Empty results and unsuccessful
scans never establish safety.

## Acceptance and CI

```sh
uv run --locked python scripts/prepare_codeql.py
uv run --locked python scripts/check_controlled_scan.py
```

This runs actual Semgrep and CodeQL for both fixtures. The vulnerable fixture must
yield a real finding and a unique compatible CodeQL candidate on the same snapshot.
Patched results remain observations without an absence-of-findings requirement.
No synthetic scanner report supports this acceptance gate. Unit tests use explicit
fake tools for failures, tampering, duplicates, and CLI publication behavior.

CI runs the integration on trusted same-repository PRs and main pushes with read-only
permissions and a 20-minute timeout. Bounded diagnostics are retained for three
days; databases and scanner environments are excluded. Intentional findings are
not uploaded to GitHub code scanning.

Changing scanner version, lock, or rule requires a reviewed profile update and
rerunning real-tool acceptance. Semgrep's CLI is used in accordance with its OSS
licensing; CodeQL retains its documented [usage prerequisites](codeql-analysis.md).
