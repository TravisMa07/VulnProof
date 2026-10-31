"""Smoke checks for the installed distribution, without adding src to sys.path."""

from importlib import import_module
from importlib.metadata import distribution
from importlib.resources import files


def test_installed_distribution_exposes_importable_package() -> None:
    installed = distribution("vulnproof")
    package = import_module(installed.metadata["Name"])

    assert package.__spec__ is not None
    assert package.__spec__.name == "vulnproof"
    assert files(package).joinpath("py.typed").is_file()
