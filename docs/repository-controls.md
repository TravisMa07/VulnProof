# Repository application controls

`vulnproof check-repository` implements E2: start one prepared application and check
the legitimate request from one D2 draft. It reports application/control observations,
not vulnerability classifications. E3a provides separately authorized [repository validation](repository-validation.md).
A passing control establishes the expected normal response under these runtime
conditions; it does not establish exploitability or safety.

## Prepare and select a draft

Keep the scan/import, investigation, correlation, discovery, endpoint configuration,
and plan artifacts from [repository investigation](repository-scan.md). Prepare the
application using [repository image preparation](repository-images.md).

**Rebuild E1 images with the current preparation command.** Preparation receipts
now use schema 1.1 and include the packaged control driver's SHA-256. Images and
receipts from schema 1.0 remain historical preparation evidence but cannot be run
by this command. Changed driver/recipe hashes also require rebuilding. Endpoint and
image configuration schemas remain 1.0. Existing fixture commands are unchanged.

Choose one `finding_id` whose disposition is `draft`. Supply the same endpoint
configuration used for planning; omit `--config` only if the original plan had none.
Authorization applies only to this attempt's legitimate control.

```sh
uv run --locked vulnproof check-repository \
  --scan .cache/repository-scan \
  --investigation .cache/repository-investigation \
  --correlation .cache/repository-correlation.json \
  --discovery .cache/repository-discovery.json \
  --plan .cache/repository-plan.json \
  --config endpoints.json \
  --prepared-image .cache/repository-image-001/prepared-image.json \
  --finding-id FINDING_ID \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/repository-control-001 \
  --authorize-execution
```

Use `/var/run/docker.sock` on Linux. The output parent must exist and the output
directory must be new and outside the input evidence/preparation directories.
The same command runs from an installed wheel without a VulnProof checkout.
The runtime does not build images, pull images, install dependencies, or accept
custom shell commands, startup scripts, Docker flags, host mounts, or environment
secrets. An unavailable daemon fails explicitly.

## Admission and startup

Before creating a container, the command reconstructs D2 planning from retained
evidence and compares it to the supplied plan. It requires one selected draft and
verifies the preparation's source fingerprint, scan receipt hash, application entry
point, installed driver/recipe hashes, and generated dependency-list hash. It
inspects the immutable local image and its expected configuration. Invalid evidence,
blocked findings, stale preparation, and missing authorization are rejected before
application execution.

The packaged observer starts the declared Flask application object in a separate
Python process inside the container. Entry points use captured Python module paths
such as `exports/web.py:service`; package-relative imports work from `/application`.
Modules and package components must have Python identifier names. Application
factories, custom startup commands, external services, credentials, and setup scripts
are unsupported. Missing symbols, missing dependencies, import failures, debug mode,
and startup deadlines have explicit failure reasons. The application must have
Flask debugging disabled. The driver does not invoke a reloader or debugger.

The observer and application communicate over container-local loopback. Application
stdout/stderr goes to diagnostic stderr; the observer reserves stdout for its
structured JSON result. A distinct readiness pipe announces the loopback port.
This separation prevents ordinary application logging from corrupting the result.
It is **not** an isolation boundary against deliberately hostile application code:
both processes share the container and UID. Dependencies, the local daemon, the
installed driver, and preparation receipts remain within the trusted local workflow.
Receipts are not signed attestations and do not authenticate an adversarial builder.

## Restrictions and control

The runner reuses the fixture isolation policy and checks the effective created
container configuration before starting it:

- UID/GID `10001:10001`, read-only root filesystem, all capabilities dropped, and
  `no-new-privileges`; no host mounts, devices, host namespaces, or published ports.
- Network mode `none`, one CPU, 256 MiB memory with no extra swap, and 64 processes.
- A 16 MiB `/tmp` tmpfs with `noexec,nosuid,nodev`, no restart or image healthcheck,
  and Docker logging disabled.
- A 60-second attached-execution deadline and a shared 1 MiB captured-output budget
  including management and cleanup, with the existing cleanup reserve.

Before application import, the observer checks its non-root identity, capabilities,
no-new-privileges, root write denial, temporary writes, and active loopback-only
interfaces. Configuration inspection and these measured behaviors do not prove
resistance to every container escape or resource attack.

Startup has a 10-second readiness deadline. The observer sends exactly the planned
GET request with a three-second socket timeout. It does not follow redirects or use
proxy environment settings. The response must be HTTP 200, at most 65,536 bytes,
and match the planned SHA-256. A larger response is explicitly marked truncated;
no full-body digest is claimed for it. The outer deadline also bounds slow streaming.
Raw response bodies are not saved. Logs and request details remain local private
artifacts and may contain application output.

## Results and cleanup

`attempt.json` version 1.0, profile `repository-control-v1`, records the finding,
candidate and path IDs, supporting path IDs, source/plan/preparation/driver hashes,
planned request, original scanner-source uncertainty, authorization scope, requested
restrictions, policy verification, driver observations, command logs, exit/OOM state,
and cleanup. The original plan and preparation receipt remain unauthorized drafts;
the attempt alone records authorization for `repository_control_only`.

Execution (`not_started`, `completed`, `failed`, `timed_out`, `output_limit`, or
`interrupted`), control (`passed`, `failed`, or `not_run`), and cleanup (`not_needed`,
`verified_absent`, or `unverified`) remain distinct. A completed observation may
report a failed control. Startup failure does not establish a vulnerability verdict.
No confirmation, safety conclusion, or automatic next-stage run is produced.

An ownership reservation is saved before container creation. Cleanup checks that
ownership label, removes only the attempt's container, and verifies absence after
success, failure, partial creation, timeout, output overflow, or interruption. SIGINT
and SIGTERM attempt bounded cleanup and publication. Daemon/host failure or SIGKILL
can prevent them; retain the exact reservation and use the recovery procedure in
[the runner guide](docker-runner.md#results-interruption-and-recovery). Unverified
cleanup always prevents overall success. Images and build cache are retained.

Exit codes: **0** means a passed control plus verified cleanup; **1** means the
retained attempt did not meet those conditions; **2** means pre-attempt admission,
usage, or input/output rejection; **130** means interruption with cleanup attempted.
Current HTML reporting consumes validation evidence, not these standalone control
attempts. E3b will connect repository validation results to reporting.

## Verification

Default tests reconstruct plans from explicitly synthetic scanner/CodeQL evidence
and use a fake Docker executable. They test admission, stale images, command policy,
control observations, failed state, output bounds, timeouts, and cleanup. They do
not claim that authored static evidence proves analysis accuracy.

Prepare the existing reviewed Flask dependencies before real execution tests:

```sh
mkdir -p .cache/repository-control-wheels
uv run --isolated --no-project --python 3.14.10 --with pip==26.2.2 python -m pip download \
  --require-hashes --only-binary=:all: \
  --platform manylinux2014_aarch64 --python-version 3.14 --implementation cp --abi cp314 \
  -r fixtures/cwe22/requirements.lock --dest .cache/repository-control-wheels

VULNPROOF_CONTROL_DOCKER_SOCKET="$HOME/.docker/run/docker.sock" \
VULNPROOF_CONTROL_WHEELHOUSE=.cache/repository-control-wheels \
VULNPROOF_CONTROL_PLATFORM=linux/arm64 \
uv run --locked pytest tests/integration/test_repository_controls_docker.py -q
```

These commands target Linux ARM64, including Apple Silicon Docker Desktop. Use
`manylinux2014_x86_64` and `linux/amd64` for an x86 Linux target, with a separate
wheelhouse. The CI job downloads native Linux AMD64 wheels from the same hashed
fixture lock before testing, and never downloads dependencies during control runs.
It runs on trusted same-repository PRs/main, with read-only permissions and no secrets.
No source-containing build contexts or application logs are uploaded.

The real suite uses two generated application layouts with relative imports and
checks normal controls, output separation, wrong bodies, redirects, response bounds,
startup/import/dependency failures, and cleanup after deadline/overflow/interruption.
All application imports occur inside containers. The static evidence in this suite
is synthetic; this is a control/lifecycle acceptance gate, not the E3 vulnerable and
patched cross-repository validation checkpoint.

[Repository validation](repository-validation.md) now provides E3a bounded CWE-22 attempts and JSON
classifications. Repository HTML integration and the cross-repository demonstration
are the next E3b/E3c steps.
