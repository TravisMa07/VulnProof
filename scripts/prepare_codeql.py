"""Download the fixed official CodeQL bundle into ignored project-local storage."""

import hashlib
import platform
import tarfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.27.3"
ASSETS = {
    "Darwin": (
        "codeql-bundle-osx64.tar.zst",
        "c773b4654a641d02967f40d994bab1850fd8bc3bddb3d20f9af17b0cca3c9a29",
    ),
    "Linux": (
        "codeql-bundle-python-linux64.tar.zst",
        "ffb149bcbb0818f1017bec9f68d7b84693a7b0ac4a69b7be390a4f2825c3a170",
    ),
}


def main() -> None:
    system = platform.system()
    if system not in ASSETS or (
        system == "Linux" and platform.machine() not in ("x86_64", "AMD64")
    ):
        raise SystemExit("Supported preparation hosts: macOS and Linux x86-64.")
    name, expected = ASSETS[system]
    destination = ROOT / ".cache" / "codeql" / VERSION
    archive = destination / name
    destination.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        url = (
            "https://github.com/github/codeql-action/releases/download/"
            f"codeql-bundle-v{VERSION}/{name}"
        )
        partial = archive.with_suffix(".partial")
        print(f"Downloading official CodeQL {VERSION}: {name}", flush=True)
        try:
            with urlopen(url, timeout=60) as source, partial.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
            partial.replace(archive)
        finally:
            partial.unlink(missing_ok=True)
    with archive.open("rb") as downloaded:
        actual = hashlib.file_digest(downloaded, "sha256").hexdigest()
    if actual != expected:
        archive.unlink()
        raise SystemExit("CodeQL checksum mismatch; archive removed. Do not use it.")
    print("SHA-256 verified; extracting the pinned bundle.", flush=True)
    with tarfile.open(archive, "r:zst") as bundle:
        bundle.extractall(destination, filter="data")
    print(f"Prepared CodeQL under {destination}")


if __name__ == "__main__":
    main()
