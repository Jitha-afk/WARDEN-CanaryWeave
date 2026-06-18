from pathlib import Path

import pytest

from canaryweave_fides.rule_loader import parse_ruleset
from canaryweave_fides.rule_schema import RuleValidationError


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOC_ROOTS = [ROOT / "README.md", ROOT / "docs", ROOT / "design", ROOT / "rules", ROOT / "data"]


RICH_CONDITION = (
    "$source_is_untrusted and "
    "($no_grant or $policy_violation_judge or $unauthorized_resource_access or $path_traversal_shape)"
)

RICH_RULE = """rule RichStructuredRule {{
    meta:
        id          = cwfr-rich-0001
        version     = 0.2.0
        severity    = high
        scope       = event_window
        action      = block_and_audit
        technique   = T1059 (Execution, analogical)
        defense     = D3-AM (Access Mediation)
        author      = "Project Open Hand Monk"
        status      = experimental
        description = "Detects untrusted tool-plan facts with denied authority."
        safety      = "Synthetic structural facts only; no source payload text."
    patterns:
        $path_traversal_shape = /safe-placeholder/i
    signals:
        $source_is_untrusted = origin(server_sampling, tool_output)
        $no_grant            = capability(not_in_allowed)
    semantics:
        $unauthorized_resource_access = "Requests access outside an allowed resource boundary." (0.72)
    judge:
        $policy_violation_judge = "Assess whether redacted facts violate the declared policy." (0.65)
    condition:
        {condition}
}}
""".format(condition=RICH_CONDITION)


def test_rich_warden_rule_accepts_meta_patterns_semantics_and_judge_sections():
    (rule,) = parse_ruleset(RICH_RULE)

    assert rule.id == "cwfr-rich-0001"
    assert rule.meta["status"] == "experimental"
    assert rule.patterns[0].name == "path_traversal_shape"
    assert rule.semantics[0].threshold == 0.72
    assert rule.judge_checks[0].threshold == 0.65
    assert rule.condition == RICH_CONDITION


def test_rich_warden_rule_rejects_unknown_condition_reference():
    text = RICH_RULE.replace(RICH_CONDITION, "$source_is_untrusted and $missing_check")

    with pytest.raises(RuleValidationError, match="missing_check"):
        parse_ruleset(text)


def test_rich_warden_rule_validates_threshold_ranges():
    text = RICH_RULE.replace("(0.72)", "(1.5)")

    with pytest.raises(RuleValidationError, match="threshold"):
        parse_ruleset(text)


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
