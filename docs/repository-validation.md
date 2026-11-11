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

E3b will render repository JSON results and their complete investigation flow in
HTML. E3c will demonstrate vulnerable/patched revisions and a second unfamiliar
compatible repository with the same installed build. The generated applications
used here establish the E3a acceptance gate.
