"""Real runner checks are opt-in; explicit requests never silently skip missing setup."""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("runner Docker integration")
    group.addoption("--run-runner-docker", action="store_true", default=False)
    group.addoption("--runner-docker-socket")
    group.addoption("--runner-prepared-images")


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("--run-runner-docker") and (
        not config.getoption("--runner-docker-socket")
        or not config.getoption("--runner-prepared-images")
    ):
        raise pytest.UsageError(
            "Real runner checks require --runner-docker-socket and --runner-prepared-images; prepare images first"
        )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if not config.getoption("--run-runner-docker"):
        for item in items:
            if "runner_docker" in item.keywords:
                item.add_marker(
                    pytest.mark.skip(
                        reason="Use --run-runner-docker with explicit socket and preparation"
                    )
                )
