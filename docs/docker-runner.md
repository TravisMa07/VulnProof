# Restricted fixture diagnostics

PR 9 runs **diagnostics and one legitimate download**, not the CWE-22 validation
template. The separate reviewed driver checks its restrictions before importing
the fixture inside the container. It makes no traversal requests, creates no canary,
and emits no exploitability assessment. Fresh-canary validation remains PR 10.

## Preparation

Install Docker Desktop (macOS, Linux containers) or rootful Docker Engine (Linux). Start
the daemon and select its local Unix socket explicitly. The verified local setup
uses `/Users/travisma/.docker/run/docker.sock`; GitHub's Ubuntu runner uses
`/var/run/docker.sock`. `docker context inspect --format '{{.Endpoints.docker.Host}}'`
can help identify a local endpoint; VulnProof does not inherit that context.

From the development checkout:

```sh
uv run --locked python scripts/prepare_runner_images.py \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/prepared-runner-001
```

Use `/var/run/docker.sock` on the supported Linux setup. Both output and its parent
follow the existing new-output convention: parent exists, destination does not.
Preparation may download the pinned base and dependency wheels. It does not start
the application. It builds two images from fresh contexts containing exactly the
approved Dockerfile, driver, application, fixture lockfile, and legitimate document.

The recipe pins `python:3.14.10-slim-bookworm` at multi-platform digest
`sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527`
and reuses the fixture's hash-pinned dependency lock. Installed
[`runner/approvals.json`](../src/vulnproof/runner/approvals.json) records exact build
input hashes for each existing fixture ID. Source fingerprints are referenced from
the existing static approval manifest, not a second editable source registry.
Changed inputs require source/recipe review and an approval update; there is no
arbitrary build context, Dockerfile, image, or command argument.

`prepared-images.json` version 1.0 records installed approval hash, recipe hashes,
fixture fingerprints, and immutable image IDs. Builds, inspections, and bounded
logs are retained in the preparation directory. Images and build cache remain in
Docker for subsequent offline runs; preparation is never invoked by the runner.
The preparation script needs the checkout; runtime works from an installed wheel.

## Execute an explicitly selected diagnostic

Use the retained [planning inputs](validation-plans.md). Select one `finding_id`
whose planning disposition is `draft`:

```sh
uv run --locked vulnproof check-runner \
  --capture .cache/investigation-001/snapshot \
  --analysis .cache/analysis-001 \
  --correlation .cache/correlation-001.json \
  --plan .cache/planning-001.json \
  --prepared-images .cache/prepared-runner-001/prepared-images.json \
  --finding-id FINDING_ID \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/runner-attempt-001 \
  --authorize-execution
```

Authorization applies **only** to `fixture-diagnostics-v1`. It cannot override
admission, accept a blocked plan, or authorize the future vulnerability template.
The original draft stays `execution_authorized: false`. Historical scanner provenance
and the fresh-canary runtime oracle remain unresolved; no confirmation is produced.

The runner reconstructs planning from the retained capture, analysis, and correlation
before accepting the supplied plan. It validates the preparation record against
installed recipe approvals, selected fixture fingerprint, and exact local image ID.
It inspects the image's Linux OS, fixed command/user/workdir, and absence of volumes,
entrypoint hooks, build triggers, and health checks. Runtime never pulls images,
builds repositories, installs dependencies, or accepts arbitrary Docker options.

The new private attempt directory must be outside the capture and analysis directories
and must differ from the selected metadata input paths. `reservation.json` records
the unique container name and image ID **before** container creation. After creation,
the effective configuration must pass inspection before `start --attach` is allowed.

## Enforced requirements and measurements

- UID/GID `10001:10001`, read-only root, all capabilities dropped, and no new privileges.
- No privileged mode, added devices, host namespaces, host mounts, or published ports.
- Network mode `none`; application and driver share container-local loopback.
- One CPU, 256 MiB memory with no additional swap, and 64 processes.
- Only `/tmp` is explicitly writable via a 16 MiB tmpfs with noexec/nosuid/nodev.
  Docker-managed kernel pseudo-filesystems are not treated as ordinary host mounts.
- No restart policy or image health checks; daemon log driver `none` avoids log accumulation.
- The attached execution command has a 60-second deadline. Management calls have
  separate deadlines (normally 15 seconds, creation 30); cleanup/reaping adds time.
- All retained subprocess output shares a 1 MiB budget, including management and
  cleanup logs. Reserve 64 KiB for cleanup; the driver receives the remaining normal
  budget. Each management response is additionally capped at 64 KiB. Overflow
  retains a marked prefix, fails the operation, and still attempts cleanup.

The driver measures effective UID/GID, no-new-privileges, capabilities, read-only
root, denied root writes, permitted temporary writes, active loopback-only interfaces,
disabled Flask debugging/static serving, and a legitimate `example.txt` response.
The response must be HTTP 200, at most 65,536 bytes, and match the reviewed document
SHA-256, with a three-second HTTP timeout. These checks are identical for vulnerable
and patched images; fixture ground truth never determines a security verdict.

Inspection establishes configuration, and driver checks establish specific observed
behaviors. They do not prove resistance to every escape, CPU/memory attack, or kernel
vulnerability. Resource checks inspect effective limits rather than stress-testing
every form of resource exhaustion.

## Endpoint, environment, and trust

The endpoint is an explicit absolute Unix socket path. Relative, TCP/SSH URI, control
character, and parent-traversal selections are rejected. The local Linux-container
daemon is checked before creation. Its reported CPU quota, memory/swap, and PID-limit
capabilities must all be present; unsupported/rootless backends are rejected without
relaxing restrictions. The operator must trust the socket owner and daemon;
a Unix socket forwarded by another service is not detectable as a remote
backend. Local socket symlinks such as `/var/run/docker.sock` remain operator-selected
endpoints, not evidence paths.

Docker runs with an explicit `--host`, private empty configuration and HOME/temp
directories, and a minimal constructed environment. Ambient Docker contexts,
credentials, API overrides, proxies, and Python variables are not forwarded.
Preparation may reference the selected trusted CLI's bundled build-plugin directory;
runtime uses no build plugin. The selected Docker executable and host remain trusted.

Preparation records are **not signed attestations**. A trusted owner could rewrite
image IDs and all hashes. Admission prevents accidental mix-ups and unsupported
inputs within the local trust model; it does not authenticate an untrusted record
or defend against a malicious daemon. Inputs must remain quiescent. An installed
policy and its receipts must come from the reviewed preparation workflow.

## Results, interruption, and recovery

`attempt.json` version 1.0 records input hashes, fixture/image/profile identity,
selected finding/result/path references, diagnostic authorization scope, requested
restrictions, command logs, policy verification, driver observations, container exit
and OOM state, reasons, and a separate cleanup observation. Logs combine stdout and
stderr for review; JSON parsing uses stdout separately. Raw inspect logs preserve
observed configuration. Driver success requires all expected checks and no extras;
CLI success alone is insufficient without the inspected container exit/OOM state.

Execution is `not_started`, `completed`, `failed`, `timed_out`, `output_limit`, or
`interrupted`. Cleanup is `not_needed`, `verified_absent`, or `unverified`. These are
attempt observations, not the four vulnerability classifications. Completed diagnostics
with unverified cleanup still cause CLI failure.

Exit **0** requires completed diagnostics and verified absence. Exit **1** means
the retained attempt did not meet both conditions. Exit **2** means authorization,
evidence, admission, output, or usage rejection before an attempt. Exit **130** means
Ctrl-C/SIGTERM interrupted execution; cleanup and report publication are attempted.
Missing Docker, invalid endpoints, or an unavailable daemon produce explicit reasons
and a non-successful retained attempt where the private directory is writable.

Container cleanup runs after success, failure, partial creation, timeout, output
overflow, and interruption. Terminating a CLI process alone does not stop a container.
Cleanup checks the unique ownership label before forced removal, then independently
checks absence. It never removes a differently labeled container or prunes unrelated
resources. Repeated SIGINT/SIGTERM are deferred during the bounded cleanup section.

Daemon failure can prevent removal or verification. `cleanup: unverified` is not
success. Retain the reservation and inspect the exact recorded name against the
explicit daemon when it returns; verify its `vulnproof.attempt` label before manually
removing that container. Host termination, SIGKILL, or IO failure may prevent final
publication; the early reservation supports recovery. No automatic broad pruning
or guarantee of immediate cleanup after host/daemon failure is claimed.

## Verification

Default development checks use a fake executable and real subprocesses, including
SIGTERM, without contacting Docker. Real integration is separately opt-in:

```sh
uv run --locked pytest tests/integration/test_runner_docker.py \
  --run-runner-docker \
  --runner-docker-socket "$HOME/.docker/run/docker.sock" \
  --runner-prepared-images .cache/prepared-runner-001/prepared-images.json
```

Explicit integration requests require both setup arguments; missing tools, images,
daemon, or unsupported restrictions fail rather than skip. The five checks exercise
both diagnostic images, shortened execution timeout, reduced output budget, and
rejection before startup, with actual removal/absence checks. Static inputs in this
suite are explicitly synthetic, including the patched fixture's authored candidate;
the suite tests orchestration, not analysis accuracy or exploitability.

The separate **Docker runner integration** CI job uses Ubuntu 24.04, a 20-minute
timeout, read-only repository permissions, no secrets, and trusted same-repository
PRs/main pushes only. Fork execution is skipped. It prepares images before testing
and uploads bounded diagnostic copies for three days, never databases/build contexts
or intentional findings to code scanning. Default development checks remain independent
of Docker and CodeQL.

Public runtime entry points are `vulnproof.runner.run_diagnostics`, `RunnerAttempt`,
`runner_approval`, and `RunnerFailure.code`. No new dependencies are added. Application
source approvals, existing artifact schemas, and the PR 2 feasibility driver are unchanged.

Docker option references: [container creation](https://docs.docker.com/reference/cli/docker/container/create/),
[execution options](https://docs.docker.com/reference/cli/docker/container/run/),
and [tmpfs mounts](https://docs.docker.com/engine/storage/tmpfs/).
