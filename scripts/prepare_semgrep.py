"""Install a separately locked tool environment; downloads occur only in preparation."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from vulnproof.scanning import scan_profile
from vulnproof.scanning.models import ToolPreparation

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    project = ROOT / "tools/semgrep"
    profile = scan_profile()
    if hashlib.sha256((project / "uv.lock").read_bytes()).hexdigest() != profile.lock_sha256:
        raise SystemExit("Tool lock differs from reviewed scanner profile")
    uv = shutil.which("uv")
    if uv is None or subprocess.check_output([uv, "--version"], text=True).split()[:2] != [
        "uv",
        "0.13.6",
    ]:
        raise SystemExit("Preparation requires uv 0.13.6 on PATH")
    destination = ROOT / ".cache/semgrep" / profile.version
    env = dict(os.environ, UV_PROJECT_ENVIRONMENT=str(destination))
    subprocess.run(
        [
            uv,
            "sync",
            "--project",
            str(project),
            "--locked",
            "--no-dev",
            "--no-install-project",
            "--no-build",
            "--python",
            sys.executable,
        ],
        env=env,
        check=True,
    )
    record = ToolPreparation(
        schema_version="1.0",
        profile=profile.id,
        version=profile.version,
        python="3.14",
        uv="0.13.6",
        lock_sha256=profile.lock_sha256,
    )
    (destination / "prepared.json").write_text(record.model_dump_json(indent=2) + "\n")
    print(f"Prepared pinned Semgrep under {destination}")


if __name__ == "__main__":
    main()
