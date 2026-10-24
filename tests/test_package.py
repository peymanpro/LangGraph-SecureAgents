from importlib.metadata import version as distribution_version

from langgraph_secure_agents import __version__


def test_package_exposes_version() -> None:
    assert __version__ == distribution_version("langgraph-secure-agents")



def test_source_checkout_version_falls_back_without_distribution_metadata(
    monkeypatch: object,
) -> None:
    import importlib
    import importlib.metadata

    import langgraph_secure_agents as package

    real_version = importlib.metadata.version

    def missing_distribution(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    try:
        importlib.metadata.version = missing_distribution  # type: ignore[method-assign]
        importlib.reload(package)
        assert package.__version__ == "0+unknown"
    finally:
        importlib.metadata.version = real_version  # type: ignore[method-assign]
        importlib.reload(package)
