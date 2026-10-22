from __future__ import annotations

import pytest

from langgraph_secure_agents._resolver_safety import call_resolver_without_mutation


class Uncopyable:
    def __deepcopy__(self, memo: dict[int, object]) -> Uncopyable:
        raise RuntimeError("copy disabled")


class Uncomparable:
    def __deepcopy__(self, memo: dict[int, object]) -> Uncomparable:
        return Uncomparable()

    def __eq__(self, other: object) -> bool:
        raise RuntimeError("comparison disabled")


def test_uncopyable_resolver_input_fails_closed() -> None:
    with pytest.raises(ValueError, match="safely copyable"):
        call_resolver_without_mutation(lambda value: "resource", Uncopyable())


def test_unverifiable_resolver_mutation_fails_closed() -> None:
    with pytest.raises(ValueError, match="could not be checked safely"):
        call_resolver_without_mutation(lambda value: "resource", Uncomparable())
