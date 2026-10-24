import importlib
import importlib.metadata
from importlib.metadata import version as distribution_version

import pytest

from langgraph_secure_agents import __version__


def test_package_exposes_version() -> None:
    assert __version__ == distribution_version("langgraph-secure-agents")



def test_source_checkout_version_falls_back_without_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import langgraph_secure_agents as package

    def missing_distribution(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    with monkeypatch.context() as patcher:
        patcher.setattr(importlib.metadata, "version", missing_distribution)
        importlib.reload(package)
        assert package.__version__ == "0+unknown"

    importlib.reload(package)
