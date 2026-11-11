# Repository image preparation

`vulnproof prepare-repository-image` implements E1: build a source-bound image from
an existing repository scan/import snapshot. It does not start the application,
run a control request, execute a vulnerability test, or authorize execution.
E2 will introduce controlled application startup; E3 will add validation and reports.
The existing fixture runner remains unchanged and does not admit these images.

## Inputs and preparation

Use a retained `scan` or `prepare-repository` directory. Source is copied from its
`snapshot`, verified against every captured file and its fingerprint, and placed
under `/application` inside the image. The live checkout is never read. Captured
non-code files are included, so a captured `downloads/manual.txt` becomes
`/application/downloads/manual.txt`. Review the captured file inventory before
building: anything captured, including sensitive data, becomes part of the image.
Missing assets require a new capture; this command does not collect them from the
live checkout. A component-only capture must contain its required application files.

Prepare a directory of explicitly trusted wheels for CPython 3.14 on the chosen
Linux platform. Include pinned transitive dependencies. Dependency acquisition is
a separate operator preparation step; this command does not resolve or download
packages. Source distributions, editable installs, repository setup scripts,
custom Dockerfiles, and native compilation are not supported. Prebuilt compatible
native wheels may be supplied. Hashes identify the reviewed files, not their safety.

Create a JSON configuration (the placeholder hash below must be replaced):

```json
{
  "schema_version": "1.0",
  "entry_point": "exports/web.py:service",
  "platform": "linux/arm64",
  "wheels": [
    {
      "filename": "example_package-1.0-py3-none-any.whl",
      "sha256": "REPLACE_WITH_THE_WHEEL_SHA256"
    }
  ]
}
```

Use `linux/amd64` for the other supported target. Each wheel filename must be a
plain filename inside `--wheelhouse`; URLs, paths, pip options, and duplicate
filenames are rejected. Use `shasum -a 256 /path/to/wheelhouse/*.whl` to compute
hashes after acquiring and reviewing dependencies. Record the complete wheel set
in configuration. Limits are 128 wheels, 64 MiB per wheel, and 256 MiB in total.
Package versions are pinned by the exact wheel filenames and content hashes.
Pip checks compatibility, install validity, and dependency completeness in the
build; dependency failures never trigger an online fallback. Extras-dependent
requirements must be explicitly included by the operator; pip check does not
establish extras completeness.

The entry point must name a captured `.py` file and an application symbol. The
symbol is recorded, not imported or checked for existence. Use the same entry
point as D2's endpoint profile. Build configuration is separate from D2's endpoint
configuration: it describes the application image, rather than a particular
finding, route, or control. E1 does not claim a plan is runnable or verify agreement
with a supplied plan. The later runner must check entry point and source identity
against a reconstructed plan before execution.

```sh
mkdir -p .cache
uv run --locked vulnproof prepare-repository-image \
  --scan .cache/repository-scan \
  --config application-image.json \
  --wheelhouse /absolute/path/to/reviewed-wheels \
  --docker-socket "$HOME/.docker/run/docker.sock" \
  --output .cache/repository-image-001
```

Use `/var/run/docker.sock` on Linux. The output parent must exist, and the output
directory must be new and separate from inputs. Symlinked evidence and wheel
files are rejected. Run the same command as `vulnproof` from an installed wheel;
no VulnProof checkout or fixture registry is required.

## Build policy and receipt

The installed recipe pins
`python:3.14.10-slim-bookworm@sha256:516b51cb9db2ef061e465c803e50f64361b82cefd91e525b889b967b83e83527`.
Only this recipe is executed. A captured repository Dockerfile or `setup.py` is
ordinary source data, not build instructions. Pip installs only the declared
wheel files using generated hash-required requirements, no index, no dependency
downloads, and no source distributions. Installation and metadata dependency
checks occur before application source is copied into the image.

Build RUN steps have network mode `none`. Docker may contact its registry to pull
the pinned base image; this is preparation, not offline execution. No credentials,
SSH forwarding, build secrets, host directories, application startup commands,
or arbitrary Docker flags are accepted. The selected Docker CLI, daemon, pinned
base, and declared dependencies are trusted. Dependencies can contain executable
code, including Python startup hooks; wheel-only installation is not a sandbox
for hostile dependency packages. Build isolation does not inherit the fixture
runner's runtime resource limits. Use a trusted local builder; stronger build
resource controls remain separate work.

The image has UID/GID `10001:10001`, `/application` as its working directory, no
entrypoint or healthcheck hook, and a default command that exits without importing
the application. Inspection checks these settings and the requested Linux
architecture. It does not prove application readiness or general image safety.

`prepared-image.json` version 1.0 records:

- Scan receipt hash and captured source fingerprint, without upgrading imported
  scanner revision uncertainty.
- Configuration bytes hash, entry point, selected platform, and each wheel hash.
- Installed recipe and generated requirements hashes, pinned base reference, and
  immutable local image ID.
- `application_started: false` and `execution_authorized: false`.

This is a local reproducibility receipt, not a signed attestation. The builder and
receipt owner remain trusted. A later execution stage must revalidate its inputs
and image; file hashes alone cannot authenticate an adversarial builder.

`preparation.json` retains the outcome and command records; bounded logs live in
`diagnostics/`. A failure after output creation leaves diagnostics and no success
receipt. Input rejection can occur before output creation. Exit 0 means preparation
completed; exit 2 means failure or invalid input; Ctrl-C/SIGTERM returns 130. The Docker
client has a ten-minute build deadline and bounded output (64 KiB per management
command within its shared budget). Very verbose builds can fail that budget.
Stopping the client does not guarantee cancellation of daemon-side build work.

Build contexts, images, and Docker cache are retained for review/reuse. No application
containers are created by this command, and it never prunes unrelated Docker state.
Interrupted builds may leave daemon cache/images; inspect your selected daemon
before removing exact image IDs. Do not share source-containing build artifacts
as public CI diagnostics.

## Verification

Default tests use a fake Docker boundary and require no daemon. They verify source
and wheel mismatches, changed build inputs, invalid configuration, image policy,
output conflicts, missing Docker, and failure diagnostics. The existing development
CI runs these tests with formatting and strict type checking. A separate trusted-PR/main
Ubuntu job runs real preparation for linux/amd64 with read-only permissions and no
application execution. It does not upload source-containing build artifacts.

Opt into real builds with:

```sh
VULNPROOF_PREPARATION_DOCKER_SOCKET="$HOME/.docker/run/docker.sock" \
VULNPROOF_PREPARATION_PLATFORM=linux/arm64 \
uv run --locked pytest tests/test_repository_preparation.py -q
```

The real checks prepare two generated checkouts with different entry-point paths
using the same code and a synthetic local wheel. Their application modules raise
if imported, and repository build scripts are deliberately invalid. Missing Docker
or failed builds fail an explicitly selected run. This verifies preparation, not
the roadmap's vulnerable/patched cross-repository validation checkpoint.

References: [pip hash-checked installation](https://pip.pypa.io/en/stable/topics/secure-installs/)
and [Docker build options](https://docs.docker.com/reference/cli/docker/buildx/build/).
