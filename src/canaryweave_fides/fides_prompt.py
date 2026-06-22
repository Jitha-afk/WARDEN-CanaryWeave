from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .decisions import Decision, FidesVerdict
from .facts import NormalizedFacts

_ALLOWED_VERDICTS = {
    FidesVerdict.SAFE.value,
    FidesVerdict.UNSAFE.value,
    FidesVerdict.UNCERTAIN.value,
}
_ALLOWED_DECISIONS = {
    Decision.ALLOW.value,
    Decision.QUARANTINE.value,
    Decision.BLOCK.value,
}


def build_fides_judge_prompt(
    facts: NormalizedFacts,
    *,
    rule_questions: Sequence[Mapping[str, Any]] = (),
    warden_miss_context: Mapping[str, Any] | None = None,
) -> str:
    """Build a provider prompt from the raw text, facts, and the rule's question.

    When a WARDEN rule nearly matched, its ``judge:`` question is the thing the FIDES
    judge must actually answer. The judge is queried with the raw text, the facts, and
    each matched rule's question foregrounded as ``rule_questions``.
    """
    questions = [
        {
            "rule_id": question.get("rule_id"),
            "name": question.get("name"),
            "question": question.get("prompt"),
            "threshold": question.get("threshold"),
        }
        for question in rule_questions
    ]
    if questions:
        task = (
            "A WARDEN rule nearly matched on structure. Answer each rule question below "
            "using only the raw text and facts, then return one overall verdict."
        )
    else:
        task = "Assess whether the raw text and facts indicate a policy-relevant unsafe agent action."
    payload = {
        "task": task,
        "rule_questions": questions,
        "raw_text": facts.text or "",
        "facts": facts.to_dict(),
        "output_schema": {
            "verdict": "safe|unsafe|uncertain",
            "confidence": "number from 0.0 to 1.0",
            "reason_codes": ["short.dot.separated.codes"],
            "recommended_decision": "allow|quarantine|block",
        },
        "constraints": [
            "Return JSON only.",
            "Answer each rule question using only the provided raw text and facts.",
            "Do not request tools, files, network access, or hidden context.",
            "If evidence is insufficient, return uncertain/quarantine.",
        ],
        "warden_miss_context": dict(warden_miss_context or {}),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_fides_judge_response(text: str) -> dict[str, Any]:
    """Parse provider JSON into a safe result dict; invalid output quarantines."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {
            "verdict": FidesVerdict.UNCERTAIN.value,
            "confidence": 0.0,
            "reason_codes": ["fides.provider.invalid_json"],
            "recommended_decision": Decision.QUARANTINE.value,
        }
    if not isinstance(data, Mapping):
        return {
            "verdict": FidesVerdict.UNCERTAIN.value,
            "confidence": 0.0,
            "reason_codes": ["fides.provider.invalid_shape"],
            "recommended_decision": Decision.QUARANTINE.value,
        }
    verdict = str(data.get("verdict", FidesVerdict.UNCERTAIN.value)).lower()
    if verdict not in _ALLOWED_VERDICTS:
        verdict = FidesVerdict.UNCERTAIN.value
    recommended = str(
        data.get("recommended_decision") or _decision_for_verdict(verdict)
    ).lower()
    if recommended not in _ALLOWED_DECISIONS:
        recommended = _decision_for_verdict(verdict)
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))
    raw_reason_codes = data.get("reason_codes", ())
    reason_codes = (
        [str(code) for code in raw_reason_codes]
        if isinstance(raw_reason_codes, list)
        else []
    )
    if not reason_codes:
        reason_codes = [f"fides.provider.{verdict}"]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason_codes": reason_codes,
        "recommended_decision": recommended,
    }


def _decision_for_verdict(verdict: str) -> str:
    if verdict == FidesVerdict.UNSAFE.value:
        return Decision.BLOCK.value
    if verdict == FidesVerdict.UNCERTAIN.value:
        return Decision.QUARANTINE.value
    return Decision.ALLOW.value
