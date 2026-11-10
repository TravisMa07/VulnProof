"""Prepare only the reviewed validation images; downloads/builds are allowed here."""

import argparse
import sys
from pathlib import Path

from vulnproof.runner import RunnerFailure
from vulnproof.validation.preparation import prepare_images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-socket", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New preparation directory")
    args = parser.parse_args()
    try:
        record = prepare_images(
            Path(__file__).resolve().parents[1], args.docker_socket, args.output
        )
        print(f"Prepared {len(record.images)} images: {args.output / 'prepared-images.json'}")
        return 0
    except (RunnerFailure, OSError, ValueError) as exc:
        print(f"Preparation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
