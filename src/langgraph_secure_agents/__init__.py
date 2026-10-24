"""Reusable security primitives for LangGraph agents."""

from importlib.metadata import PackageNotFoundError, version

from .bundle import (
    DiagnosticSeverity,
    PolicyBundle,
    PolicyDiagnostic,
    SimulationCase,
    SimulationReport,
)
from .guard import AuthorizationDenied, protect_callable
from .models import (
    AccessRequest,
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Decision,
    DecisionReason,
    Effect,
    PolicyRule,
    Principal,
)
from .policy import ConditionTrace, PolicyEngine, PolicyExplanation, RuleTrace

try:
    __version__ = version("langgraph-secure-agents")
except PackageNotFoundError:
    # Source checkouts that have not been installed do not have distribution metadata.
    __version__ = "0+unknown"

__all__ = [
    "__version__",
    "AccessRequest",
    "AttributeCondition",
    "AttributeReference",
    "AuthorizationDenied",
    "ConditionOperator",
    "ConditionTrace",
    "Decision",
    "DecisionReason",
    "DiagnosticSeverity",
    "Effect",
    "PolicyBundle",
    "PolicyDiagnostic",
    "PolicyEngine",
    "PolicyExplanation",
    "PolicyRule",
    "Principal",
    "protect_callable",
    "RuleTrace",
    "SimulationCase",
    "SimulationReport",
]
