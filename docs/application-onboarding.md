# Application onboarding and sandbox execution

This implements completion-roadmap PR 2. The three stages are passive inspection,
explicitly authorized image preparation, and separately authorized application
exercise. They accept a retained whole-checkout scan or an explicitly scoped capture.
No repository filenames or fingerprints are hardcoded into the onboarding engine.

## Workflow

```sh
uv run --locked vulnproof inspect-application \
  --scan .cache/repository-scan --output .cache/onboarding-draft.json

# Supply a reviewed application configuration and retain its resulting plan.
uv run --locked vulnproof inspect-application \
  --scan .cache/repository-scan --config application.json \
  --output .cache/onboarding.json

uv run --locked vulnproof prepare-application \
  --scan .cache/repository-scan --config application.json \
  --plan .cache/onboarding.json --wheelhouse .cache/application-wheels \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/application-image --authorize-preparation

uv run --locked vulnproof exercise-application \
  --scan .cache/repository-scan --config application.json \
  --plan .cache/onboarding.json \
  --preparation .cache/application-image/prepared-application.json \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/application-exercise --authorize-execution
```

Use `/var/run/docker.sock` on Linux. Select new output files/directories outside all
retained inputs and ensure their parents exist. Existing outputs are not overwritten.
Missing tools or an unavailable daemon fail explicitly; no feasibility test is silently
skipped by these commands. Default pytest skips opt-in Docker integration tests.

Inspection reads source, metadata, declarations, tests and simple route syntax as
**data**. It records paths/hashes and bounded startup/route hints. Hints do not prove
that startup works and are never executed automatically. Without configuration it
lists missing startup, dependency, invocation/control and state-review information.
Unsupported or dynamic metadata can remain unresolved. YAML build descriptions are
identified but not interpreted or executed. Inspection examines at most 128 Python
files and retains 256 observations, marking omitted inspection work.

The profile describes application-specific setup, independent of scanner IDs. A
configured onboarding plan has no execution authorization. Plan, source and config
are rechecked before preparation and execution; changed evidence is rejected.

## Application configuration schema 1.0

| Field | Meaning |
| --- | --- |
| `kind` | `http` for application controls or `harness` for focused component/test execution. |
| `command` | Nonempty argv array executed only inside the target container. No host shell interpretation. |
| `workdir` | Optional captured relative directory under `/application`. |
| `wheels` | Explicit Linux Python wheel filenames and SHA-256 values. May be empty for stdlib-only applications. |
| `environment` | Explicit application environment, never copied from the host. PATH, HOME and loader overrides are reserved. |
| `image_directories` | Optional initially absent directories to create under `/application`, for applications requiring existing instance directories. They remain read-only at runtime. |
| `seeds` | Relative paths and synthetic text written into fresh `/tmp/vulnproof-state`. |
| `initialize` | Ordered argv arrays for database/state preparation inside the restricted target container. |
| `port` | Application port, default 8000. Bind the application to `0.0.0.0` in its namespace so the observer can reach it. No ports are published. |
| `readiness` | Local GET target, expected HTTP status, and timeout (1–20 seconds). Readiness alone is not a legitimate control. |
| `controls` | Ordered HTTP method, encoded local target, optional headers/UTF-8 body, expected status and exact expected response-body SHA-256. Required for HTTP mode. |

HTTP methods are GET, POST, PUT, PATCH, DELETE and HEAD. JSON and form bodies are
explicit UTF-8 text with the appropriate Content-Type header. Headers are ASCII,
unique by case-insensitive name; host, framing and connection-management overrides
are rejected. The observer does not follow redirects or implicitly retry controls.
It does not automatically extract tokens or retain a browser cookie jar. Use only
synthetic test identities: profiles and diagnostic logs may contain their declared
values. A production secret manager or general login discovery is not implemented.

The target receives `VULNPROOF_STATE_DIR=/tmp/vulnproof-state`. Each attempt gets a
fresh container and SQLite/files must be initialized there; no persistent host volume
is attached. For an isolated synthetic HTTP callback service, a control target or
body may contain `${TEST_SERVICE_URL}`. The observer substitutes its internal address
and fresh `/callback/<nonce>` path. The service records bounded method/path/body
hash observations, accepts GET/POST, and returns `VulnProof isolated test service\n`.
It has no application-management or record-overwrite endpoint.

Profiles are capped at 24 KiB encoded JSON to bound command/configuration transport.
There are at most 64 command arguments, 8 initializers, 32 synthetic files, 32
application environment values, 32 headers per control, and 16 controls. A response
is limited to 64 KiB, with a 1 MiB aggregate read budget. Request bodies are limited
to 16,384 characters, and all profile fields are additionally constrained by the total
profile budget. Large datasets belong to later reviewed preparation support.

## Preparation boundaries

Preparation uses the pinned Debian slim Python base and explicit hashed wheels,
installed offline before source is copied. Transitive dependencies must be declared;
`pip check` verifies them. Use the Linux wheel-preparation instructions in
[repository images](repository-images.md). Existing repository Dockerfiles, package
scripts and dependency downloads are not run automatically. The first command
adapter uses Python's prepared runtime; other runtime ecosystems remain PR 7 work.
Projects requiring system packages, source distributions, custom build recipes or
additional database servers remain setup gaps rather than receiving weaker isolation.

Two immutable images are produced. The target image contains source/dependencies;
the observer image contains only the pinned base and installed stdlib worker, with
no application source or wheels. Preparation does not start the application.
Initialization argv runs later under execution authorization and runtime limits.
The receipt binds source, plan, application configuration, worker/recipe identity,
and both immutable image IDs. It assumes the operator trusts the local daemon,
reviewed dependencies and receipt origin; it is not signed build attestation.

## Execution boundaries and evidence

HTTP mode uses separate target and observer containers on a fresh internal bridge
with Docker's `gateway_mode_ipv4=isolated`. IPv6 is disabled. This requires a rootful
Linux-container daemon supporting isolated gateway mode; it was verified locally
with Docker 29.8.0. Unsupported daemons fail without a less restrictive fallback.
Internal DNS locates the target. There are no published ports, host mounts, Docker
socket mounts, shared process/IPC namespaces, or added capabilities. Both containers
run as non-root with read-only root filesystems, no-new-privileges, one CPU, 256 MiB
memory including swap allowance, 64 processes and 16 MiB temporary storage each.
Creation inspections verify these settings before startup. The observer attempts one
bounded connection to the TEST-NET address `203.0.113.1:9`; a failed connection is an
observation, not proof of every egress or kernel-escape property. Isolation relies on
Docker's inspected network policy and the trusted daemon.

The application worker allows 60 seconds including initialization; each initializer
has at most 15 seconds. The observer has a 45-second operation budget, individual
HTTP socket timeouts of at most three seconds, and the host bounds attachment at
50 seconds. Harness attachment is bounded at 60 seconds. Docker management and
cleanup calls have their own finite bounds. The 60-second worker limit is not a
claim that image preparation or cleanup fits within that same deadline.

Target stdout/stderr is captured separately from observer output. An aggregate
16 KiB target-log budget stops excessive output and marks truncation. Live status
includes bounded diagnostics and initializer history. Host Docker command output
uses the existing 1 MiB attempt budget with a reserved cleanup allowance. Logs are
observations from the target; they are not authenticated application assertions.
The observer independently records HTTP responses, exact targets, request-body hashes
and explicit-header hashes (transport adds Host/framing). It checks its own UID,
capabilities, no-new-privileges, read-only root, temporary writes and absence of a
default IPv4 route. The host rechecks control
counts, statuses and digests. It does not import target code.

Harness mode runs the declared test/component command, retains bounded output and
checks the container exit state. Its evidence level is explicitly `harness`;
successful execution does not establish externally reachable application behavior.
The HTTP observer does not attest a focused harness's internal assertions.

`result.json` profile `application-exercise-v1` retains the verified onboarding plan,
preparation receipt, source identity, invocation observations, policy state, commands,
callback nonce, application status and cleanup results. `vulnerability_assessment`
is always null: this stage establishes setup/control evidence, not a new vulnerability
confirmation. Class-specific workers/oracles are integrated in subsequent capability
PRs. The legacy finding-to-validation commands and historical receipts remain intact.

A reservation is published before resource creation. Containers are removed only
when their ownership label matches; the network is removed only after owned endpoints
are gone. Absence is independently checked. Failure, timeout, SIGINT and SIGTERM all
attempt cleanup and retain outcomes. Interruption exits 130 after publication when
possible. Daemon/host failure can prevent cleanup or publication: retain the reservation,
inspect the named containers' `vulnproof.attempt` labels and network's
`vulnproof.onboarding` label before manually removing only those matching resources.
Never use global container/network pruning as recovery. Prepared images are retained
for reuse and are not automatically deleted.

Exercise exits 0 only for completed controls/harness execution, 1 for retained failure,
and 2 for rejected inputs/authorization/publication errors. These are lifecycle codes,
not classifications. Preparation has independent authorization and failures retain
available diagnostics. Runtime startup never uses a previous control as proof that
a fresh attempt will work.

## Pinned upstream demonstrations

The reproduction script checks two independently developed upstream examples, with
no source modification:

- [Flask tutorial at 49943b5](https://github.com/pallets/flask/tree/49943b5a94413a530761350f04e896f76e8d620e/examples/tutorial): application factory, prepared instance directory, fresh SQLite database and synthetic user; hello and form-login controls.
- [Werkzeug Basic-auth example at 0f43c6e](https://github.com/pallets/werkzeug/blob/0f43c6ebd426039e4b99ec22535c2c8a2ec2f69f/examples/httpbasicauth.py): command-based WSGI startup and an Authorization header using a synthetic identity.

Acquire clean checkouts at those exact commits and prepare the pinned Linux Flask
wheelhouse. To generate inspectable source captures, profiles and plans without Docker:

```sh
uv run --locked python scripts/check_application_onboarding.py \
  --flask-checkout /path/to/flask --werkzeug-checkout /path/to/werkzeug \
  --wheelhouse .cache/repository-control-wheels --output .cache/onboarding-plans
```

Review each generated `application.json` and `onboarding.json`, then use the three
CLI stages above for each application. For an authorized automated reproduction,
select a fresh output directory and add:

```sh
--docker-socket "$HOME/.docker/run/docker.sock" \
--authorize-preparation --authorize-execution
```

The script checks commit identity and a clean selected component, uses the same
installed engine for both, and records summary results. It intentionally selects
`examples/tutorial` and `examples` as components; it does not claim whole-repository
coverage for these runs. It supplies empty SARIF inventories solely to prepare source
for onboarding—no finding, taint path or vulnerability conclusion is fabricated.
These are upstream example applications, not demonstrations of vulnerability coverage
across arbitrary production repositories. The broader PR 7 evidence gate remains.

Default tests require no Docker. The separate trusted same-repository CI job exercises
synthetic apps and rejection/failure/cleanup behavior; upstream downloads and execution
are opt-in reproduction work rather than automatic execution of external repositories
on every PR.
