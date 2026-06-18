"""Fetch and normalize MITRE D3FEND (defensive countermeasures).

D3FEND is not part of ``mitreattack-python`` and ships no STIX bundle, so this
reads the JSON-LD ontology (for technique ids, names, and definitions) and the
inferred D3FEND<->ATT&CK mapping API (for each countermeasure's tactic and the
offensive techniques it counters). The two are joined on the ontology URI local
name. D3FEND records become ``defense`` anchors on WARDEN rules.

Run directly:
    python fetch_d3fend.py [--refresh]
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Any

import common
import config
from common import NormalizedTechnique, log

D3FEND_TECH_URL = "https://d3fend.mitre.org/technique/d3f:{local}/"


def _lit(value: Any) -> str:
    """Flatten a JSON-LD literal (str / {'@value'} / list) to a string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("@value", ""))
    if isinstance(value, list):
        for item in value:
            text = _lit(item)
            if text:
                return text
    return ""


def _lit_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_lit(v) for v in value if _lit(v)]
    text = _lit(value)
    return [text] if text else []


def _local_name(uri: str) -> str:
    return uri.split("#")[-1].split("/")[-1].replace("d3f:", "")


def _parse_jsonld(doc: dict) -> dict[str, dict]:
    """local_name -> {id, name, definition, synonyms, parents}."""
    techniques: dict[str, dict] = {}
    for node in doc.get("@graph", []) or []:
        d3_id = _lit(node.get("d3f:d3fend-id"))
        if not d3_id.startswith("D3-"):
            continue
        local = _local_name(node.get("@id", ""))
        parents = [
            _local_name(ref.get("@id", ""))
            for ref in node.get("rdfs:subClassOf", []) or []
            if isinstance(ref, dict) and str(ref.get("@id", "")).startswith("d3f:")
        ]
        techniques[local] = {
            "id": d3_id,
            "name": _lit(node.get("rdfs:label")) or local,
            "definition": _lit(node.get("d3f:definition")).strip(),
            "synonyms": _lit_list(node.get("d3f:synonym")),
            "parents": parents,
        }
    return techniques


def _bval(row: dict, key: str) -> str:
    """Safely read a SPARQL-JSON binding value (rows may omit variables)."""
    cell = row.get(key)
    if isinstance(cell, dict):
        return str(cell.get("value", ""))
    return ""


def _parse_mappings(doc: dict) -> dict[str, dict]:
    """local_name -> {tactic, top_level, attack_ids:set}."""
    bindings = doc.get("results", {}).get("bindings", []) or []
    by_local: dict[str, dict] = defaultdict(lambda: {"tactic": "", "top_level": "", "attack_ids": set()})
    for row in bindings:
        def_uri = _bval(row, "def_tech")
        if not def_uri:
            continue
        rec = by_local[_local_name(def_uri)]
        rec["tactic"] = rec["tactic"] or _bval(row, "def_tactic_label")
        rec["top_level"] = rec["top_level"] or _bval(row, "top_def_tech_label")
        off_id = _bval(row, "off_tech_id")
        if off_id:
            rec["attack_ids"].add(off_id)
    return by_local


def normalize_d3fend(jsonld: dict, mappings: dict) -> tuple[list[NormalizedTechnique], list[dict], dict]:
    techniques_meta = _parse_jsonld(jsonld)
    mapping_by_local = _parse_mappings(mappings)

    attack_to_defense: dict[str, set[str]] = defaultdict(set)
    techniques: list[NormalizedTechnique] = []
    tactics_seen: dict[str, None] = {}

    for local, meta in techniques_meta.items():
        mapped = mapping_by_local.get(local, {})
        tactic = mapped.get("tactic", "")
        attack_ids = sorted(mapped.get("attack_ids", set()))
        for aid in attack_ids:
            attack_to_defense[aid].add(meta["id"])
        if tactic:
            tactics_seen[tactic] = None

        techniques.append(
            NormalizedTechnique(
                framework=common.FRAMEWORK_D3FEND,
                id=meta["id"],
                name=meta["name"],
                description=meta["definition"],
                tactics=[common.slugify(tactic)] if tactic else [],
                tactic_names=[tactic] if tactic else [],
                is_subtechnique=False,
                parent_id=None,
                detection="",
                data_components=[],
                mitigations=[],
                platforms=[],
                url=D3FEND_TECH_URL.format(local=local),
                stix_id=None,
                references=[],
                attack_mappings=attack_ids,
                domain="d3fend",
                extra={
                    "synonyms": meta["synonyms"],
                    "parents": meta["parents"],
                    "top_level": mapped.get("top_level", ""),
                },
            )
        )
    techniques.sort(key=lambda t: t.id)

    tactic_records = [{"shortname": common.slugify(t), "id": None, "name": t, "url": ""} for t in sorted(tactics_seen)]
    attack_to_defense_out = {aid: sorted(ids) for aid, ids in sorted(attack_to_defense.items())}
    return techniques, tactic_records, attack_to_defense_out


def fetch_d3fend(*, refresh: bool = False) -> dict:
    jsonld_path = config.RAW_DIR / "d3fend.json"
    mappings_path = config.RAW_DIR / "d3fend_mappings.json"

    if refresh or not jsonld_path.exists():
        common.write_json(jsonld_path, common.http_get_json(config.D3FEND_JSONLD_URL))
        log(f"downloaded D3FEND ontology -> {jsonld_path.name}")
    if refresh or not mappings_path.exists():
        common.write_json(mappings_path, common.http_get_json(config.D3FEND_MAPPINGS_URL))
        log(f"downloaded D3FEND mappings -> {mappings_path.name}")

    jsonld = common.read_json(jsonld_path)
    mappings = common.read_json(mappings_path)
    techniques, tactic_records, attack_to_defense = normalize_d3fend(jsonld, mappings)

    out_path = config.NORMALIZED_DIR / "d3fend.json"
    common.dump_framework(
        out_path,
        framework=common.FRAMEWORK_D3FEND,
        source=config.D3FEND_JSONLD_URL,
        source_version="d3fend.mitre.org ontology + full-mappings API",
        techniques=techniques,
        tactics=tactic_records,
        mitigations=[],
        extra={"attack_to_defense": attack_to_defense, "mapped_attack_techniques": len(attack_to_defense)},
    )
    return {"techniques": len(techniques), "mapped_attack_techniques": len(attack_to_defense), "normalized": str(out_path)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch + normalize MITRE D3FEND defensive countermeasures.")
    parser.add_argument("--refresh", action="store_true", help="Re-download D3FEND sources even if cached.")
    args = parser.parse_args()
    summary = fetch_d3fend(refresh=args.refresh)
    log(f"D3FEND done: {summary}")


if __name__ == "__main__":
    main()
