# Repository CWE-22 validation

`vulnproof validate-repository` implements E3a. It reconstructs a selected repository
plan, checks its prepared image, runs a fresh legitimate control, and exercises the
reviewed CWE-22 file-read template in a restricted container. The output is a
versioned JSON result with the evidence and classification for that occurrence.

## Run an attempt

Keep the retained artifacts from [repository investigation](repository-scan.md),
the original endpoint configuration, and a [prepared image](repository-images.md).
Rebuild images after installing this version: the packaged driver's hash has changed.
Preparation receipt schema 1.1 remains in use. The runtime rejects a stale driver.

```sh
uv run --locked vulnproof validate-repository \
  --scan .cache/repository-scan \
  --investigation .cache/repository-investigation \
  --correlation .cache/repository-correlation.json \
  --discovery .cache/repository-discovery.json \
  --plan .cache/repository-plan.json \
  --config endpoints.json \
  --prepared-image .cache/repository-image-001/prepared-image.json \
  --finding-id FINDING_ID \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/repository-validation-001 \
  --authorize-validation
```

Use `/var/run/docker.sock` on Linux. Select a new output directory outside retained
inputs. `--authorize-validation` authorizes the selected attempt. A previous control
attempt provides setup evidence, while this attempt runs its own control in a fresh
container. Valid blocked findings produce a JSON result describing their remaining
gaps without starting a container. Invalid or changed input evidence is rejected.

The command supports the currently planned Flask GET/query file-read behavior.
The configured download directory must exist inside the image. After a successful
HTTP 200 control with the expected body hash, the observer resolves that directory
and checks that the fresh marker directory lies outside it. A missing directory,
existing marker directory, or overlapping boundary stops validation with a reason.
The observer exclusively creates a randomly named file with a fresh synthetic
marker under `/tmp/vulnproof`, then runs the template's parent-directory and absolute
path checks. Responses are bounded to 65,536 bytes with three-second socket timeouts.
Redirects are retained as responses. The normal runtime deadline, output budget,
isolation checks, and cleanup rules apply. See [repository controls](repository-controls.md).

## Evidence and classifications

`result.json` schema 1.0, profile `repository-validation-v1`, includes the selected
finding disposition, source fingerprint, original plan hash, scanner-source state,
classification/reason, and the full attempt when execution occurred. `plan.json`
retains the supplied verified plan. `runtime/attempt.json`, its reservation, and
bounded diagnostic logs retain execution and cleanup observations.

Validation attempts use profile `repository-validation-attempt-v1` and authorization
scope `repository_cwe22_validation`. The request records the control and declared
boundary/input binding. Driver observations include the resolved boundary, fresh
marker, exclusive-creation observation, exact attempted request targets, statuses,
body lengths/digests, truncation, and operational failures. Response bodies are not
retained. The marker is synthetic test data. Logs can contain application output.

| Classification | Evidence requirement or reason |
| --- | --- |
| `confirmed` | Controlled scanner provenance, a reproduced compatible plan, a valid control, complete matching marker disclosure, accepted runtime state, and verified cleanup. |
| `inconclusive` | Completed bounded checks without marker disclosure, unresolved imported scanner provenance, or missing planning prerequisites. |
| `unsupported` | Unsupported scanner mapping, request method, or application object. |
| `failed` | Analysis, admission, startup, control, boundary, probe, integrity, timeout, output, or cleanup failure preventing an accepted assessment. |

All candidate paths and the supporting request-path references remain in the
attempt. Runtime observations establish endpoint behavior. Intermediate CodeQL
nodes retain their status as modeled flow. Imported SARIF retains its uncertainty
even if a marker response is observed. An unsuccessful probe never establishes safety.
A failure after an observed response retains that response while preventing confirmation.

Exit 0 means a result was published with `confirmed`, `inconclusive`, or `unsupported`.
Exit 1 means a retained `failed` result. Exit 2 means authorization, invalid initial
evidence, usage, or output rejection. Interruption attempts cleanup and result
publication, then exits 130. Host or daemon failure can prevent cleanup/publication;
retain the runtime reservation for the recovery procedure in the runner guide.

The local trust model includes the Docker daemon, dependencies, installed driver,
and preparation receipts. The application and observer share a container and UID.
Their process separation supports reliable output handling but does not authenticate
observations against deliberately hostile application code. Existing runtime
restrictions remain enforced for every admitted attempt.

## Verification and next stages

Default tests exercise explicit authorization, result accounting, scanner provenance,
marker/request consistency, cleanup gates, and preservation of control behavior.
Real Docker tests exercise generated vulnerable and patched applications and failed
controls. A further opt-in test uses actual pinned Semgrep and CodeQL output through
planning, preparation, the installed CLI, and container validation.

After preparing the tools and Linux wheels described in the existing guides:

```sh
VULNPROOF_TEST_SEMGREP=.cache/semgrep/1.184.0 \
VULNPROOF_TEST_CODEQL=.cache/codeql/2.27.3/codeql \
VULNPROOF_CONTROL_DOCKER_SOCKET="$HOME/.docker/run/docker.sock" \
VULNPROOF_CONTROL_WHEELHOUSE=.cache/repository-control-wheels \
VULNPROOF_CONTROL_PLATFORM=linux/arm64 \
uv run --locked pytest tests/integration/test_repository_validation_docker.py -q
```

The trusted-PR/main CI job prepares pinned tools and wheels before running these
checks on Linux AMD64, with read-only repository permissions. Generated source,
build contexts, and application logs are kept out of public diagnostic uploads.

E3b [repository reports](repository-reports.md) render repository results and their
complete investigation flow in offline HTML. E3c will demonstrate vulnerable/patched revisions and a second unfamiliar
compatible repository with the same installed build. The generated applications
used here establish the E3a acceptance gate.

## Fixed query parameters

Endpoint configuration schema `1.1` accepts an ordered `fixed_query` list alongside
`query_key`, `control_value`, and `control_sha256`. For example:

```json
{
  "schema_version": "1.1",
  "endpoints": [{
    "file": "exports/web.py",
    "handler": "export",
    "entry_point": "exports/web.py:service",
    "download_root": "/application",
    "query_key": "document",
    "control_value": "manual.txt",
    "control_sha256": "REPLACE_WITH_SHA256_OF_LEGITIMATE_RESPONSE",
    "fixed_query": [
      {"name": "model", "value": "demo & ü"},
      {"name": "version", "value": ""}
    ]
  }]
}
```

The hash above is an explanatory placeholder, not runnable configuration. Route and
method may be discovered or explicitly supplied under the existing conflict rules.
The control target is `/export?model=demo+%26+%C3%BC&version=&document=manual.txt`.
Both bounded probes preserve `model` and `version` and replace only `document`.
These are ordinary query values, not a credentials or secret-injection mechanism.

Plans from configuration 1.1 use plan schema 1.1. Drafts using fixed parameters retain
an `http_request` profile (schema 1.0); runtime attempts carrying it use attempt schema
1.1. Historical configuration, plans and attempts retain their original single-query
semantics. The HTML report identifies the varied parameter and retains exact targets.

Duplicate names, overlap with the varied parameter, and embedded route queries or
fragments are rejected. Fixed values may be empty or Unicode. Profiles allow up to
64 fixed parameters, 256 characters per name, 4,096 characters per fixed value, and
16,384 characters per encoded request target. Missing application-required values
can fail the legitimate control; such failures never establish safety.

Rebuild prepared images before using this version: the packaged driver changed.
The existing preparation receipt binds its hash and rejects stale images. No new
container permissions, network access, startup hooks, or request methods are enabled.

## Route parameters

Route profiles support one direct Flask GET binding of the form
`/download/<path:document>`. Endpoint configuration schema `1.2` declares
`path_parameter: "document"` instead of `query_key`. Keep `control_value`,
`control_sha256`, `download_root`, and optional `fixed_query` as before. The source
route and handler argument must agree with the declaration and retained CodeQL path.
No configuration value can substitute for absent static evidence.

Plans containing route requests use schema 1.2. Their `http_request` uses schema 1.1;
within that explicitly versioned representation the legacy field `query_key` names
the selected **path** argument. Attempt schema 1.1 can retain either request profile.
Earlier query profiles keep schema 1.0 and their original encoding semantics.

The builder substitutes the selected value once, percent-encodes path data while
preserving slashes, and appends unchanged fixed query values. It does not normalize
`..`, follow redirects, or retry alternative encodings. Exact requests and HTTP
responses are retained. An absolute-path candidate may be rejected or redirected by
Flask routing before the handler runs; this is an observation, not a safety verdict.
Authority-shaped targets beginning `//` are rejected. Unsupported converters,
multiple route parameters, Blueprint registration, and file-serving APIs remain gaps.

Actual Semgrep/CodeQL checks found a modeled argument-to-open path using
`@app.route(..., methods=["GET"])`. With the pinned CodeQL bundle, the equivalent
`@app.get(...)` example yielded no path. The pipeline preserves that absence. The
patched inline allowlist also yielded no CodeQL path; independent runtime checks
use explicitly authored static evidence and do not claim a controlled confirmation.

The scanner adds `vulnproof.repository.route-file-read`. Correlation accepts the
reviewed current ruleset and the previous query-only ruleset SHA-256
`ab7be84091543e7f00b97d73eff516bded34e9e9d11b68841773c7adcf890fb3` for historical
controlled scans; unknown rule hashes remain rejected. Existing query discovery is
unchanged. Rebuild prepared images because this change updates the packaged driver.

## Flask file-serving APIs

Repository scans now include two distinct mappings:

- `vulnproof.repository.send-file`: request input flowing into Flask `send_file`'s
  first argument or `path_or_file` keyword.
- `vulnproof.repository.send-from-directory`: request input flowing into the
  **filename** argument of Flask `send_from_directory`, positional or `path=`.

Correlation resolves explicit top-level Flask imports, aliases, and module-qualified
calls before matching scanner and CodeQL argument spans. It rejects unresolved,
reimported, reassigned, or shadowed API names and expanded `*args`/`**kwargs` calls.
Resolution is deliberately conservative: even shadowing in another scope can leave
a call unsupported. Source inspection is bounded to 256 KiB per module; it never
imports application modules. Calls through wrappers and dynamically modified imports
are not established by this resolver. Directory arguments are not interchangeable
with filename arguments; dynamic-directory validation is outside this mapping.

Both APIs reuse existing query or route request profiles and the current restricted
marker validator. No runner permissions, image recipe, or result semantics change.
The supplied `download_root` remains the intended application boundary; its
configuration does not establish that the application enforces containment.

Observed with the pinned tools: the aliased `send_file(name)` case produced a
Semgrep finding and CodeQL path. The ordinary contained
`send_from_directory('/application', name)` case produced a Semgrep finding but no
CodeQL path. The latter remains accounted for without a runnable draft; the tool
does not suppress it or manufacture a path. Independent container tests with clearly
authored static evidence exercise the legitimate response and refusal of the marker
requests. These observations do not establish universal safety for file-serving APIs.

The correlator retains the sink family in its per-occurrence record. Neighboring
calls or other API families cannot corroborate it unless their precise relevant
argument matches. Historical query-only and route/open ruleset hashes remain
recognized; unknown hashes remain rejected. The new scanner rules change scan
receipts, so image preparation must correspond to the chosen retained scan.
Blueprint registration and external-application preparation remain subsequent work.

A further pinned-tool observation: `send_file(path_or_file=name)` was reported by
Semgrep but yielded no CodeQL path, unlike the positional form. Keyword argument
resolution is supported, but that does not supply missing CodeQL evidence. Its
runtime behavior is covered independently with authored evidence. Flask's relative
`send_file` paths resolve against the application root directory; the legitimate
control and intended boundary must reflect that location rather than assuming the
process working directory. The test applications place a synthetic legitimate file
there. No external application source is rewritten by this feature.
