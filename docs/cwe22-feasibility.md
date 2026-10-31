# CWE-22 feasibility experiment (PR 2)

This development experiment checks the first static-analysis and restricted-runtime
building blocks. It is not the VulnProof CLI, a general runner, or a vulnerability
classification engine. Do not run the intentionally vulnerable applications on
the host or expose their HTTP server to other machines.

## Fixture and expected behavior

The two apps expose `GET /download?name=...` and differ in file handling:

- `vulnerable/app.py` joins the user-selected name to `/fixture/downloads` and opens
  the resulting path without containment enforcement.
- `patched/app.py` delegates to Flask's `send_from_directory` with a fixed directory.

Each image includes `downloads/example.txt` and the synthetic `canary.txt` outside
that download directory. No host files, secrets, symlinks, uploads, authentication,
or databases are involved. Both apps disable debugging and automatic static serving.

| Request | Vulnerable | Patched |
| --- | --- | --- |
| `name=example.txt` | 200, exact document | 200, exact document |
| `name=../canary.txt` | 200, exact canary | 404, no canary |
| `name=/fixture/canary.txt` | 200, exact canary | 404, no canary |
| Missing or empty name | 400 | 400 |
| Nonexistent document | 404 | 404 |

The HTTP driver runs inside each image and compares status and content. It starts
a loopback WSGI server on an ephemeral port; no host port is published. This is a
fixed synthetic control experiment, not the later fresh-nonce validation oracle.
The framework-based patch does not establish protection against symlink or
concurrent-filesystem attacks, which are outside this fixture.

## Pins and preparation

- CPython 3.14.10, from `python:3.14.10-slim-bookworm`.
- Multi-platform base index:
  `sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527`.
  The fixed index selects native amd64 in CI and arm64 on Apple Silicon.
- Flask 3.1.3; all transitive packages are pinned in `fixtures/cwe22/uv.lock`.
  The Docker build uses its hash-locked `requirements.lock` export.
- Official CodeQL bundle 2.27.3, including `codeql/python-queries` 1.8.13.
  Platform-specific archive names and SHA-256 digests are pinned in the preparation
  script. Linux x86-64 uses the smaller Python-only bundle; macOS uses the full bundle.
- Only the official `py/path-injection` query is run. No custom query models or
  query copies are introduced. The resolved pack version is recorded with results.

CodeQL preparation supports macOS (including Apple Silicon) and Linux x86-64.
The container checks support Docker Desktop on macOS and Docker Engine in Ubuntu
CI. Other hosts are not validated by this PR.

Use CodeQL subject to its [upstream terms and availability](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).
This experiment analyzes only the project's public, project-owned fixture source.
Do not infer authorization or licensing for unrelated private/proprietary code.
Docker installation and usage also remain subject to its applicable terms.

From the repository root, follow [development setup](../CONTRIBUTING.md), start
Docker Desktop (or Docker Engine on Linux), and prepare the pinned CodeQL bundle:

```sh
uv sync --locked
uv run --locked python scripts/prepare_codeql.py
```

Preparation downloads into `.cache/codeql/2.27.3/`, checks the committed SHA-256,
and extracts with Python's data-safe tar filter. It does not install a global CLI.
It needs network access and sufficient disk space; the macOS archive is roughly
0.9 GB before extraction. Re-running preparation verifies the cached archive again.

To intentionally update fixture dependencies, change the fixture's project file,
run `uv lock --project fixtures/cwe22`, and regenerate the checked-in export:

```sh
uv export --project fixtures/cwe22 --locked --no-dev --no-emit-project --no-header --format requirements-txt --output-file fixtures/cwe22/requirements.lock
```

Flask is also a development-only dependency of the root project so mypy can check
the fixture code without importing or executing it. It is not a VulnProof runtime
dependency. Keep the two direct Flask pins aligned when updating them.

## Run the fixed experiments

```sh
uv run --locked python scripts/feasibility.py static
uv run --locked python scripts/feasibility.py container
uv run --locked python scripts/feasibility.py all
```

The entry point accepts only those three check names. It accepts no repository,
image, path, Docker option, or executable arguments. Missing tools or an unavailable
Docker daemon cause explicit failure; they do not turn the experiment into a skip.

Static analysis extracts the two source directories separately, without importing
or starting either application. A vulnerable result must have rule ID
`py/path-injection`, a sink on the fixture's `open()` line, and one nonempty path
that passes through the request-parameter read before ending at that sink. CodeQL
may start its path at the Flask `request` import; the first node need not be the
parameter read. Patched findings are retained and reported as observations, with
no required finding count and no suppression.

The container stage first builds both images from the fixture-only build context.
Only build/preparation may download packages. Execution uses the resulting image
IDs, not mutable tags, and performs no builds or dependency installation.

## Restrictions and their verification

Every execution requests and inspects:

- UID/GID 10001, a read-only root filesystem, dropped capabilities, and no new privileges.
- No external network, published ports, privileged mode, or host mounts.
- One CPU, 256 MiB memory with no additional swap, and 64 processes.
- A 16 MiB `/tmp` tmpfs with `noexec`, `nosuid`, and `nodev`.
- No daemon log accumulation; client output is bounded separately.

Inside the container, the driver checks its UID, effective capabilities,
`NoNewPrivs`, the read-only filesystem flag and write rejection, temporary writes,
and network-namespace interfaces. It verifies loopback HTTP through the cases above.
The network check reads interface flags in the process's network namespace and
requires loopback to be the only active interface. The kernel may expose inactive
fallback tunnel devices even with `--network=none`; their mere presence is not
treated as external connectivity. Configuration inspection independently checks
that Docker's network mode is `none`.

Each execution has a 60-second client deadline and a 1 MiB combined-output limit.
The script terminates the client process group and attempts forced container removal
after success, errors, timeouts, and interruption. Successful runs additionally
verify container absence. Cleanup errors fail the experiment. A host crash or
unreachable daemon can prevent cleanup; inspect `docker ps -a` for containers
whose names start with `vulnproof-cwe22-` before retrying after such a failure.
Built images remain in the local Docker cache for reuse and inspection.

Resource configuration inspection does not prove resistance to every resource
attack. Docker is not claimed to contain arbitrary hostile code or kernel exploits.
The fixed experiment contains no resource-exhaustion probes or external callbacks.

## Artifacts, checks, and interpretation

Each invocation prints a fresh ignored `.cache/feasibility/<run-id>/` directory.
It contains CodeQL databases and a `diagnostics/` subdirectory with raw SARIF,
bounded command logs, tool/pack versions, immutable image IDs, container inspection,
HTTP checks, cleanup records, and stage summaries. Databases are not CI artifacts.

Commands fail on nonzero exit, output overflow, or deadline expiration. Command
logs are capped at 1 MiB each. SARIF above that size is retained outside the upload
directory and fails the static check. No intentional findings are uploaded to
GitHub code scanning. CI uploads only the bounded diagnostics for three days.

The existing development checks include unit tests for path acceptance, output
limits, timeouts, nonzero exits, policy mismatches, and cleanup on failures. They
do not import fixture applications or require CodeQL/Docker. The separate
**CWE-22 feasibility** job performs real analysis and container checks on trusted
same-repository PRs and pushes to `main`; it skips fork PR execution. Neither job
uses secrets or a privileged `pull_request_target` workflow.

An unsuccessful request, absent static path, or patched fixture observation never
proves safety. Ground truth comes from the reviewed fixture and explicit behavior
checks; the full VulnProof classification/correlation stages remain future work.
