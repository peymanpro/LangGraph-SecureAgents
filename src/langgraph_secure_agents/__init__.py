"""Reusable security primitives for LangGraph agents."""

from importlib.metadata import PackageNotFoundError, version

from .approvals import ApprovalStore, SQLiteApprovalStore
from .audit import AuditEvent, AuditEventCallback, create_opentelemetry_callback
from .audit_store import AuditRecord, SQLiteAuditSink
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
from .policy_registry import PolicyRegistry, PolicySnapshot, PolicyUpdateConflict

try:
    __version__ = version("langgraph-secure-agents")
except PackageNotFoundError:
    # Source checkouts that have not been installed do not have distribution metadata.
    __version__ = "0+unknown"

__all__ = [
    "__version__",
    "ApprovalStore",
    "SQLiteApprovalStore",
    "AuditEvent",
    "AuditRecord",
    "SQLiteAuditSink",
    "AuditEventCallback",
    "create_opentelemetry_callback",
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
    "PolicyRegistry",
    "PolicySnapshot",
    "PolicyUpdateConflict",
    "PolicyRule",
    "Principal",
    "protect_callable",
    "RuleTrace",
    "SimulationCase",
    "SimulationReport",
]
