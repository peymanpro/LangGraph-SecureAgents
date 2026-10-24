from __future__ import annotations

from pathlib import Path

from examples.secure_agent_workflow import run_demo


def test_end_to_end_demo_denies_cross_tenant_and_blocks_approval_replay(
    tmp_path: Path,
) -> None:
    report = run_demo(tmp_path)

    assert report.own_tenant_result == "Customer 101 profile: standard account"
    assert report.cross_tenant_result == "Authorization denied."
    assert report.approved_refund_result == "Refund issued for invoice-9001."
    assert report.replay_result == "Approval response invalid; tool was not executed."

    assert report.executed_operations == (
        "read_customer:customer-101",
        "issue_refund:invoice-9001",
    )
    # LangGraph restarts an interrupted node from its beginning on resume,
    # so the pending decision is recorded again before each resumed decision.
    assert report.audit_reasons == (
        "explicit_allow",
        "default_deny",
        "approval_required",
        "approval_required",
        "human_approved",
        "approval_required",
        "approval_required",
        "approval_invalid",
    )
    assert report.audit_integrity_valid is True
    assert (tmp_path / "approvals.sqlite3").exists()
    assert (tmp_path / "authorization-audit.sqlite3").exists()
