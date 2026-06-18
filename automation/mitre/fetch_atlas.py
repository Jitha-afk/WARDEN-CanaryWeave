"""Fetch and normalize MITRE ATLAS (adversarial ML / LLM threat) data.

ATLAS does not publish a STIX bundle, so this reads the official hosted YAML
export (following its git symlink chain) and projects techniques, tactics, and
mitigations onto the shared ``NormalizedTechnique`` schema. Every ATLAS
technique is treated as LLM/ML-relevant by definition.

Run directly:
    python fetch_atlas.py [--refresh]
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import yaml

import common
import config
from common import NormalizedTechnique, log

ATLAS_BASE_URL = "https://atlas.mitre.org"


def _technique_url(tid: str) -> str:
    return f"{ATLAS_BASE_URL}/techniques/{tid}"


def _tactic_url(tid: str) -> str:
    return f"{ATLAS_BASE_URL}/tactics/{tid}"


def _mitigation_url(mid: str) -> str:
    return f"{ATLAS_BASE_URL}/mitigations/{mid}"


def _relationships_of(rels: dict, source_id: str, rel_type: str) -> list[dict]:
    entry = rels.get(source_id) or {}
    return entry.get(rel_type, []) or []


def normalize_atlas(doc: dict) -> tuple[list[NormalizedTechnique], list[dict], list[dict]]:
    tactics_by_id: dict[str, dict] = doc.get("tactics", {})
    techniques_by_id: dict[str, dict] = doc.get("techniques", {})
    mitigations_by_id: dict[str, dict] = doc.get("mitigations", {})
    relationships: dict = doc.get("relationships", {})

    # Invert mitigation -> technique into technique -> [mitigations].
    mitigations_for_technique: dict[str, list[dict]] = defaultdict(list)
    for mid, mobj in mitigations_by_id.items():
        for rel in _relationships_of(relationships, mid, "mitigates"):
            target = rel.get("target")
            if target:
                mitigations_for_technique[target].append({"id": mid, "name": mobj.get("name", "")})

    # Count case-study employment as a rough prevalence signal.
    employed_count: dict[str, int] = defaultdict(int)
    for src, entry in relationships.items():
        for rel in (entry or {}).get("employs", []) or []:
            target = rel.get("target")
            if target:
                employed_count[target] += 1

    techniques: list[NormalizedTechnique] = []
    for tid, obj in techniques_by_id.items():
        is_sub = tid.count(".") >= 1 and len(tid.split(".")) == 3
        parent_id = tid.rsplit(".", 1)[0] if is_sub else None

        tactic_ids = [r.get("target") for r in _relationships_of(relationships, tid, "achieves") if r.get("target")]
        tactic_names = [tactics_by_id[t]["name"] for t in tactic_ids if t in tactics_by_id]

        references = []
        for ref in obj.get("references") or []:
            if isinstance(ref, dict):
                references.append({"source": ref.get("source", ""), "id": None, "url": ref.get("url", "")})

        techniques.append(
            NormalizedTechnique(
                framework=common.FRAMEWORK_ATLAS,
                id=tid,
                name=obj.get("name", ""),
                description=(obj.get("description", "") or "").strip(),
                tactics=tactic_ids,
                tactic_names=tactic_names,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                detection="",  # ATLAS is attack-focused; defense lives in mitigations.
                data_components=[],
                mitigations=mitigations_for_technique.get(tid, []),
                platforms=list(obj.get("platforms", []) or []),
                url=_technique_url(tid),
                stix_id=obj.get("uuid"),
                references=references,
                domain="atlas",
                extra={
                    "maturity": obj.get("maturity"),
                    "case_study_uses": employed_count.get(tid, 0),
                },
            )
        )
    techniques.sort(key=lambda t: t.id)

    tactic_records = [
        {"shortname": tid, "id": tid, "name": tobj.get("name", ""), "url": _tactic_url(tid)}
        for tid, tobj in tactics_by_id.items()
    ]
    mitigation_records = [
        {
            "id": mid,
            "name": mobj.get("name", ""),
            "description": common.first_line(mobj.get("description", "")),
            "url": _mitigation_url(mid),
        }
        for mid, mobj in mitigations_by_id.items()
    ]
    return techniques, tactic_records, mitigation_records


def fetch_atlas(*, refresh: bool = False) -> dict:
    raw_path = config.RAW_DIR / "atlas.yaml"
    if refresh or not raw_path.exists():
        text, resolved = common.fetch_text_follow_symlink(config.ATLAS_YAML_URL)
        common.write_text(raw_path, text)
        log(f"downloaded ATLAS YAML from {resolved} -> {raw_path.name} ({len(text):,} bytes)")
    else:
        log(f"using cached {raw_path.name} (use --refresh to re-download)")
        text = raw_path.read_text(encoding="utf-8")

    doc = yaml.safe_load(text)
    techniques, tactic_records, mitigation_records = normalize_atlas(doc)

    out_path = config.NORMALIZED_DIR / "atlas.json"
    common.dump_framework(
        out_path,
        framework=common.FRAMEWORK_ATLAS,
        source=config.ATLAS_YAML_URL,
        source_version=f"ATLAS format {doc.get('format-version')} ({doc.get('matrix', {}).get('name', 'ATLAS')})",
        techniques=techniques,
        tactics=tactic_records,
        mitigations=mitigation_records,
        extra={"case_study_count": len(doc.get("case-studies", {}) or {})},
    )
    return {"techniques": len(techniques), "normalized": str(out_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch + normalize MITRE ATLAS (adversarial ML).")
    parser.add_argument("--refresh", action="store_true", help="Re-download the ATLAS YAML even if cached.")
    args = parser.parse_args()
    summary = fetch_atlas(refresh=args.refresh)
    log(f"ATLAS done: {summary}")


if __name__ == "__main__":
    main()
