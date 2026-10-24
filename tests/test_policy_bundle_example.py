from __future__ import annotations

import runpy
from pathlib import Path

import pytest


def test_policy_bundle_workflow_example_runs_end_to_end(capsys: pytest.CaptureFixture[str]) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    example_path = repository_root / "examples" / "policy_bundle_workflow.py"
    namespace = runpy.run_path(str(example_path), run_name="policy_bundle_example")

    namespace["main"]()
    output = capsys.readouterr().out

    assert "Policy: payroll-access v1.0.0" in output
    assert "Lint findings: 0" in output
    assert "Candidate-versus-baseline simulation:" in output
    assert '"total": 4' in output
    assert '"allowed": 1' in output
    assert '"denied": 2' in output
    assert '"approval_required": 1' in output
    assert '"changed": 3' in output
    assert "Why the cross-tenant request was denied:" in output
    assert "condition_failed" in output
