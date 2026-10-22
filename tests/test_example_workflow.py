from __future__ import annotations

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
