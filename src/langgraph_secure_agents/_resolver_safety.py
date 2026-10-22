"""Internal helpers for fail-closed, side-effect-free policy resolvers."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")


def call_resolver_without_mutation(
    resolver: Callable[P, R],
    *args: P.args,
    **kwargs: P.kwargs,
) -> R:
    """Call a trusted resolver on detached inputs and reject input mutation.

    Resource/action resolvers participate in the authorization decision. Letting
    them mutate a request object can cause the checked resource to differ from
    the resource later consumed by the protected operation. Inputs are deep-copied
    and snapshotted; if copying or comparison cannot be performed safely, the
    caller fails closed before the protected operation executes.
    """

    try:
        resolver_args = deepcopy(args)
        resolver_kwargs = deepcopy(kwargs)
        args_before = deepcopy(resolver_args)
        kwargs_before = deepcopy(resolver_kwargs)
    except Exception as exc:
        raise ValueError("resolver inputs must be safely copyable") from exc

    result = resolver(*resolver_args, **resolver_kwargs)

    try:
        mutated = resolver_args != args_before or resolver_kwargs != kwargs_before
        if not isinstance(mutated, bool):
            mutated = bool(mutated)
    except Exception as exc:
        raise ValueError("resolver input mutation could not be checked safely") from exc

    if mutated:
        raise ValueError("authorization resolvers must not mutate their inputs")

    return result
