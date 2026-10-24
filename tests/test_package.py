from importlib.metadata import version as distribution_version

from langgraph_secure_agents import __version__


def test_package_exposes_version() -> None:
    assert __version__ == distribution_version("langgraph-secure-agents")
