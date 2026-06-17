from canaryweave_fides.fides import FidesIFCLayer
from canaryweave_fides.fixtures import smoke_cases


def test_fides_blocks_low_integrity_source_causing_consequential_action():
    case = smoke_cases()["server_sampling_origin_mismatch"]
    verdict = FidesIFCLayer(enabled=True).evaluate(case.trace, case.policy)
    assert verdict.verdict == "unsafe"
    assert "trusted_action" in verdict.policy_checks


def test_fides_allows_high_integrity_authorized_action():
    case = smoke_cases()["host_authorized_tool_plan"]
    verdict = FidesIFCLayer(enabled=True).evaluate(case.trace, case.policy)
    assert verdict.verdict == "safe"


def test_disabled_fides_reports_disabled_without_blocking():
    case = smoke_cases()["server_sampling_origin_mismatch"]
    verdict = FidesIFCLayer(enabled=False).evaluate(case.trace, case.policy)
    assert verdict.verdict == "disabled"
    assert verdict.blocks is False
