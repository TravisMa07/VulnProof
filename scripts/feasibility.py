"""Fixed PR 2 experiments, not a general repository or container execution API."""

import argparse
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import time
from pathlib import Path
from types import FrameType
from typing import Any
from urllib.parse import unquote
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/cwe22"
CODEQL_VERSION = "2.27.3"
CODEQL = ROOT / ".cache/codeql" / CODEQL_VERSION / "codeql/codeql"
OUTPUT_LIMIT = 1024 * 1024
VARIANTS = ("vulnerable", "patched")


def interrupt(_signum: int, _frame: FrameType | None) -> None:
    """Let termination signals unwind the same cleanup path as Ctrl-C."""
    raise KeyboardInterrupt


class ExperimentError(RuntimeError):
    """An experiment could not establish its acceptance criteria."""


def stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=5)
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # Reap remaining descendants even if their immediate parent has already exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def run_logged(
    command: list[str],
    log: Path,
    timeout: float,
    *,
    limit: int = OUTPUT_LIMIT,
    expected: tuple[int, ...] = (0,),
) -> str:
    """Bound combined output and wall time, including on interruption."""
    log.parent.mkdir(parents=True, exist_ok=True)
    output = bytearray()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector, log.open("wb") as target:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ExperimentError(f"Deadline exceeded ({timeout}s); see {log}")
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = limit - len(output)
                    output.extend(chunk[:available])
                    target.write(chunk[:available])
                    target.flush()
                    if len(chunk) > available:
                        raise ExperimentError(f"Output truncated at {limit} bytes; see {log}")
            try:
                returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise ExperimentError(f"Deadline exceeded; see {log}") from error
            if returncode not in expected:
                raise ExperimentError(f"Command exited {returncode}; see {log}")
    finally:
        stop_process(process)
        process.stdout.close()
    return output.decode("utf-8", errors="replace")


def location_covers(location: dict[str, Any], line: int) -> bool:
    physical = location.get("physicalLocation", {})
    uri = unquote(physical.get("artifactLocation", {}).get("uri", ""))
    region = physical.get("region", {})
    return (
        uri == "app.py"
        and region.get("startLine", 0) <= line
        and region.get("endLine", region.get("startLine", 0)) >= line
    )


def require_vulnerable_path(sarif: dict[str, Any], source: str) -> None:
    lines = source.splitlines()
    input_line = next(i for i, line in enumerate(lines, 1) if "request.args.get" in line)
    sink_line = next(i for i, line in enumerate(lines, 1) if "open(path," in line)
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if result.get("ruleId") != "py/path-injection":
                continue
            if not any(location_covers(loc, sink_line) for loc in result.get("locations", [])):
                continue
            for flow in result.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    locations = [item.get("location", {}) for item in thread.get("locations", [])]
                    if (
                        len(locations) >= 2
                        and any(location_covers(loc, input_line) for loc in locations[:-1])
                        and location_covers(locations[-1], sink_line)
                    ):
                        return
    raise ExperimentError("No py/path-injection path from the fixture request input to open().")


def static(directory: Path) -> None:
    if not CODEQL.is_file():
        raise ExperimentError(
            "CodeQL missing. Run: uv run --locked python scripts/prepare_codeql.py"
        )
    diagnostics = directory / "diagnostics"
    version = json.loads(
        run_logged([str(CODEQL), "version", "--format=json"], diagnostics / "version.log", 30)
    )
    if version.get("version") != CODEQL_VERSION:
        raise ExperimentError(f"Expected CodeQL {CODEQL_VERSION}.")
    queries = list(
        CODEQL.parent.glob("qlpacks/codeql/python-queries/*/Security/CWE-022/PathInjection.ql")
    )
    if len(queries) != 1:
        raise ExperimentError("Expected exactly one bundled official Python path-injection query.")
    query = queries[0]
    pack_file = query.parents[2] / "qlpack.yml"
    pack = pack_file.read_text()
    pack_version = re.search(r"^version:\s*(\S+)", pack, re.MULTILINE)
    if pack_version is None:
        raise ExperimentError("Cannot resolve bundled query-pack version.")
    (diagnostics / "query-pack.txt").write_text(
        f"CodeQL {CODEQL_VERSION}\ncodeql/python-queries {pack_version[1]}\n{query}\n"
    )
    for variant in VARIANTS:
        database = directory / f"{variant}-database"
        source_root = FIXTURES / variant
        run_logged(
            [
                str(CODEQL),
                "database",
                "create",
                str(database),
                "--language=python",
                f"--source-root={source_root}",
                "--threads=2",
            ],
            diagnostics / f"{variant}-extraction.log",
            180,
        )
        result = diagnostics / f"{variant}.sarif"
        run_logged(
            [
                str(CODEQL),
                "database",
                "analyze",
                str(database),
                str(query),
                "--format=sarifv2.1.0",
                "--sarif-add-snippets",
                f"--output={result}",
                "--threads=2",
                "--ram=2048",
            ],
            diagnostics / f"{variant}-analysis.log",
            300,
        )
        if result.stat().st_size > OUTPUT_LIMIT:
            result.replace(directory / f"oversized-{variant}.sarif")
            raise ExperimentError("SARIF exceeded the diagnostic size limit; not accepted.")
        sarif = json.loads(result.read_text())
        if variant == "vulnerable":
            require_vulnerable_path(sarif, (source_root / "app.py").read_text())
        else:
            count = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
            print(
                f"OBSERVATION: patched fixture has {count} static finding(s); retained unchanged."
            )


def require_container_policy(inspect: dict[str, Any], image: str) -> None:
    host = inspect["HostConfig"]
    checks = {
        "immutable image": inspect["Image"] == image,
        "non-root user": inspect["Config"]["User"] == "10001:10001",
        "read-only root": host["ReadonlyRootfs"] is True,
        "network disabled": host["NetworkMode"] == "none",
        "no published ports": not host.get("PortBindings") and not host.get("PublishAllPorts"),
        "no privileged mode": not host["Privileged"],
        "all capabilities dropped": host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"),
        "no new privileges": any(
            value in ("no-new-privileges", "no-new-privileges:true")
            for value in host.get("SecurityOpt", [])
        ),
        "one CPU": host["NanoCpus"] == 1_000_000_000,
        "256 MiB memory": host["Memory"] == 256 * 1024 * 1024,
        "no additional swap": host["MemorySwap"] == host["Memory"],
        "64 processes": host["PidsLimit"] == 64,
        "no host mounts": not host.get("Binds")
        and not host.get("Mounts")
        and all(mount["Type"] == "tmpfs" for mount in inspect.get("Mounts", [])),
        "bounded temporary storage": host.get("Tmpfs")
        == {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
        "no daemon log accumulation": host["LogConfig"]["Type"] == "none",
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ExperimentError("Container policy mismatch: " + ", ".join(failed))


def container(directory: Path) -> None:
    if shutil.which("docker") is None:
        raise ExperimentError("Docker CLI missing. Install Docker Desktop or Docker Engine.")
    diagnostics = directory / "diagnostics"
    try:
        run_logged(
            ["docker", "info", "--format={{.ServerVersion}}"], diagnostics / "docker.log", 15
        )
    except ExperimentError as error:
        raise ExperimentError("Docker daemon unavailable. Start Docker and retry.") from error
    images: dict[str, str] = {}
    # Preparation completes for both images before any fixture executes.
    for variant in VARIANTS:
        image_file = directory / f"{variant}-image.id"
        run_logged(
            [
                "docker",
                "build",
                "--pull",
                "--iidfile",
                str(image_file),
                "--build-arg",
                f"VARIANT={variant}",
                str(FIXTURES),
            ],
            diagnostics / f"{variant}-build.log",
            600,
        )
        image = image_file.read_text().strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
            raise ExperimentError("Build did not produce an immutable image ID.")
        images[variant] = image
        (diagnostics / f"{variant}-image.txt").write_text(image + "\n")
    for variant, image in images.items():
        name = f"vulnproof-cwe22-{variant}-{uuid4().hex}"
        created = False
        try:
            run_logged(
                [
                    "docker",
                    "create",
                    "--name",
                    name,
                    "--network=none",
                    "--read-only",
                    "--user=10001:10001",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--cpus=1",
                    "--memory=256m",
                    "--memory-swap=256m",
                    "--pids-limit=64",
                    "--log-driver=none",
                    "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                    image,
                ],
                diagnostics / f"{variant}-create.log",
                30,
            )
            created = True
            inspection = json.loads(
                run_logged(
                    ["docker", "inspect", name],
                    diagnostics / f"{variant}-inspect.json",
                    15,
                )
            )[0]
            require_container_policy(inspection, image)
            run_logged(
                ["docker", "start", "--attach", name],
                diagnostics / f"{variant}-http.log",
                60,
            )
            # docker start --attach can return zero independently of the container's exit status.
            state = json.loads(
                run_logged(
                    ["docker", "inspect", "--format={{json .State}}", name],
                    diagnostics / f"{variant}-state.json",
                    15,
                )
            )
            if state["Running"] or state["ExitCode"] != 0 or state["OOMKilled"]:
                raise ExperimentError(f"{variant} fixture failed: {state}")
        finally:
            # Attempt cleanup even if create timed out after the daemon accepted it.
            run_logged(
                ["docker", "rm", "--force", name],
                diagnostics / f"{variant}-cleanup.log",
                20,
                expected=(0,) if created else (0, 1),
            )
        absence = run_logged(
            ["docker", "ps", "--all", "--quiet", "--filter", f"name=^/{name}$"],
            diagnostics / f"{variant}-absence.log",
            15,
        )
        if absence.strip():
            raise ExperimentError(f"Container cleanup failed: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=("static", "container", "all"))
    arguments = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupt)
    directory = ROOT / ".cache/feasibility" / uuid4().hex
    directory.mkdir(parents=True)
    diagnostics = directory / "diagnostics"
    diagnostics.mkdir()
    print(f"Artifacts: {directory}", flush=True)
    failed = False
    summaries: list[str] = []
    for name, check in (("static", static), ("container", container)):
        if arguments.check not in (name, "all"):
            continue
        try:
            check(directory)
        except (ExperimentError, OSError, ValueError, KeyError) as error:
            summaries.append(f"FAIL: {name}: {error}")
            failed = True
        except KeyboardInterrupt:
            summaries.append(f"FAIL: {name}: interrupted; cleanup attempted")
            (diagnostics / "summary.txt").write_text("\n".join(summaries) + "\n")
            print(summaries[-1], flush=True)
            return 130
        else:
            summaries.append(f"PASS: {name}")
        print(summaries[-1], flush=True)
        (diagnostics / "summary.txt").write_text("\n".join(summaries) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
