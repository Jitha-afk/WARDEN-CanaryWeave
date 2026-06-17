from pathlib import Path

import pytest

from canaryweave_fides.rule_schema import RuleValidationError, validate_rule


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOC_ROOTS = [ROOT / "README.md", ROOT / "docs", ROOT / "design", ROOT / "rules", ROOT / "data"]


def _rich_rule():
    return {
        "id": "cwfr-rich-0001",
        "name": "RichStructuredRule",
        "version": "0.2.0",
        "category": "mcp_agentic_misuse/tool_authority_confusion",
        "severity": "high",
        "scope": "event_window",
        "description": "Detects untrusted tool-plan facts with denied authority.",
        "meta": {
            "author": "Project Open Hand Monk",
            "status": "experimental",
            "license": "MIT",
            "created": "2026-06-03",
            "updated": "2026-06-03",
            "attack_refs": [{"framework": "ATT&CK", "technique_id": "T1059", "tactic": "Execution"}],
            "defense_refs": [{"framework": "D3FEND", "technique_id": "D3-AM", "name": "Access Mediation"}],
            "false_positive_guidance": ["Authorized host-generated tool plans."],
        },
        "keywords": [
            {"name": "path_traversal_shape", "type": "regex", "pattern": "safe-placeholder", "case_sensitive": False},
        ],
        "semantics": [
            {"name": "unauthorized_resource_access", "description": "Requests access outside an allowed resource boundary.", "threshold": 0.72},
        ],
        "fides": [
            {"name": "policy_violation_judge", "prompt": "Assess whether redacted facts violate the declared policy.", "threshold": 0.65},
        ],
        "signals": [
            {"name": "source_is_untrusted", "type": "event_field_in", "field": "origin", "values": ["server_sampling", "tool_output"]},
            {"name": "capability_not_granted", "type": "capability_policy", "relation": "not_in_allowed_capabilities"},
        ],
        "condition": "signals.source_is_untrusted and (signals.capability_not_granted or fides.policy_violation_judge)",
        "recommended_action": "block_and_audit",
        "fixtures": {"positive": ["synthetic_authority_boundary"], "negative": ["synthetic_authorized_host_action"]},
        "safety_notes": "Synthetic structural fixture only; no source payload text.",
    }


def test_rich_warden_rule_accepts_meta_keyword_semantic_and_fides_sections():
    rule = validate_rule(_rich_rule())

    assert rule.id == "cwfr-rich-0001"
    assert rule.meta["status"] == "experimental"
    assert rule.keywords[0].name == "path_traversal_shape"
    assert rule.semantics[0].threshold == 0.72
    assert rule.fides_checks[0].threshold == 0.65
    assert rule.condition == "signals.source_is_untrusted and (signals.capability_not_granted or fides.policy_violation_judge)"


def test_rich_warden_rule_rejects_unknown_namespaced_condition_reference():
    data = _rich_rule()
    data["condition"] = "signals.source_is_untrusted and fides.missing_check"

    with pytest.raises(RuleValidationError, match="fides.missing_check"):
        validate_rule(data)


def test_rich_warden_rule_validates_threshold_ranges():
    data = _rich_rule()
    data["semantics"][0]["threshold"] = 1.5

    with pytest.raises(RuleValidationError, match="threshold"):
        validate_rule(data)


def test_public_docs_do_not_reference_inspiration_project_name():
    banned = "nova"
    offenders = []
    for root in PUBLIC_DOC_ROOTS:
        paths = [root] if root.is_file() else list(root.rglob("*"))
        for path in paths:
            if path.is_file() and path.suffix in {".md", ".yaml", ".yml", ".war"}:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
                if banned in text:
                    offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
