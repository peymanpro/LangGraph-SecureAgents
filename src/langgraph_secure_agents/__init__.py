"""Reusable security primitives for LangGraph agents."""

from importlib.metadata import PackageNotFoundError, version

from .guard import AuthorizationDenied, protect_callable
from .models import AccessRequest, Decision, DecisionReason, Effect, PolicyRule, Principal
from .policy import PolicyEngine

try:
    __version__ = version("langgraph-secure-agents")
except PackageNotFoundError:
    # Source checkouts that have not been installed do not have distribution metadata.
    __version__ = "0+unknown"

__all__ = [
    "AccessRequest",
    "AuthorizationDenied",
    "Decision",
    "DecisionReason",
    "Effect",
    "PolicyEngine",
    "PolicyRule",
    "Principal",
    "__version__",
    "protect_callable",
]
