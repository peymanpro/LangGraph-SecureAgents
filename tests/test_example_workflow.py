from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from examples.policy_guarded_workflow import PayrollContext, build_payroll_workflow, run_request


def test_workflow_allows_only_matching_role_action_and_resource() -> None:
    graph = build_payroll_workflow()

    allowed = run_request(
        graph,
        employee_id="employee-7",
        context=PayrollContext(principal_id="alice", roles=("hr",)),
    )
    wrong_resource = run_request(
        graph,
        employee_id="employee-8",
        context=PayrollContext(principal_id="alice", roles=("hr",)),
    )
    wrong_role = run_request(
        graph,
        employee_id="mallory",
        context=PayrollContext(principal_id="mallory", roles=("guest",)),
    )

    assert allowed["report"] == "Employee 7: salary band P4"
    assert allowed["error"] is None

    assert wrong_resource["report"] is None
    assert wrong_resource["error"] is not None

    assert wrong_role["report"] is None
    assert wrong_role["error"] is not None

def test_langgraph_node_guard_example_runs_without_external_services() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "langgraph_protected_node.py")],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Denied before the node ran: default_deny" in result.stdout
    assert "Security check passed: denied operation caused no side effect." in result.stdout
