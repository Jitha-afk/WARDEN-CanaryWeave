"""Fetch and normalize MITRE ATT&CK via the official ``mitreattack-python`` package.

Downloads the STIX 2.1 bundle for each requested ATT&CK domain (enterprise /
mobile / ics), loads it with ``MitreAttackData``, and emits both the raw bundle
and a normalized ``NormalizedTechnique`` dump that the WARDEN transform consumes.

Run directly:
    python fetch_attack.py                 # all domains
    python fetch_attack.py --domain enterprise-attack --refresh
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mitreattack.stix20 import MitreAttackData

import common
import config
from common import NormalizedTechnique, log


def _ref_id_url(obj: Any, source_names: set[str]) -> tuple[str | None, str]:
    """Pull the (external_id, url) from an object's primary MITRE reference."""
    for ref in getattr(obj, "external_references", None) or []:
        if ref.get("source_name") in source_names:
            return ref.get("external_id"), ref.get("url", "")
    return None, ""


def _all_references(obj: Any) -> list[dict]:
    out: list[dict] = []
    for ref in getattr(obj, "external_references", None) or []:
        out.append(
            {
                "source": ref.get("source_name", ""),
                "id": ref.get("external_id"),
                "url": ref.get("url", ""),
            }
        )
    return out


def _build_tactic_index(mad: MitreAttackData) -> dict[str, dict]:
    """shortname -> {id, name, url} for every x-mitre-tactic in the bundle."""
    index: dict[str, dict] = {}
    for tactic in mad.get_tactics(remove_revoked_deprecated=True):
        shortname = getattr(tactic, "x_mitre_shortname", None)
        if not shortname:
            continue
        ta_id, url = _ref_id_url(tactic, {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"})
        index[shortname] = {"id": ta_id, "name": tactic.name, "url": url}
    return index


def _entries(bulk: dict, stix_id: str) -> list[Any]:
    raw = bulk.get(stix_id, []) if bulk else []
    return [e.get("object") if isinstance(e, dict) else e for e in raw]


def _detection_for(
    stix_id: str,
    ds_bulk: dict,
    analytic_index: dict,
    dc_index: dict,
) -> tuple[str, list[str], list[str]]:
    """Build (detection_text, data_component_names, log_source_channels).

    ATT&CK v17+ expresses detection as detection-strategy objects that reference
    analytics; each analytic references log sources backed by data components.
    """
    strategy_names: list[str] = []
    data_components: set[str] = set()
    log_sources: set[str] = set()
    for ds in _entries(ds_bulk, stix_id):
        name = getattr(ds, "name", None)
        if name:
            strategy_names.append(name)
        for aref in getattr(ds, "x_mitre_analytic_refs", None) or []:
            analytic = analytic_index.get(aref)
            if analytic is None:
                continue
            for ls in getattr(analytic, "x_mitre_log_source_references", None) or []:
                channel = ls.get("name")
                if channel:
                    log_sources.add(channel)
                dc_name = dc_index.get(ls.get("x_mitre_data_component_ref"))
                if dc_name:
                    data_components.add(dc_name)
    return "; ".join(strategy_names), sorted(data_components), sorted(log_sources)


def normalize_domain(mad: MitreAttackData, domain: str) -> list[NormalizedTechnique]:
    source_names = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
    kc_name = config.ATTACK_KILL_CHAIN_NAMES.get(domain, "mitre-attack")
    tactic_index = _build_tactic_index(mad)

    # One bulk relationship pass each, keyed by technique STIX id.
    mit_bulk = mad.get_all_mitigations_mitigating_all_techniques()
    ds_bulk = mad.get_all_detection_strategies_detecting_all_techniques()
    analytic_index = {a.id: a for a in mad.get_analytics()}
    dc_index = {dc.id: dc.name for dc in mad.get_datacomponents()}

    techniques: list[NormalizedTechnique] = []
    for tech in mad.get_techniques(include_subtechniques=True, remove_revoked_deprecated=True):
        attack_id, url = _ref_id_url(tech, source_names)
        if not attack_id:
            attack_id = mad.get_attack_id(tech.id)
        if not attack_id:
            continue

        tactic_shortnames: list[str] = []
        tactic_names: list[str] = []
        for phase in getattr(tech, "kill_chain_phases", None) or []:
            if phase.get("kill_chain_name") != kc_name:
                continue
            sn = phase.get("phase_name")
            tactic_shortnames.append(sn)
            tactic_names.append(tactic_index.get(sn, {}).get("name") or common.title_from_shortname(sn))

        is_sub = bool(getattr(tech, "x_mitre_is_subtechnique", False))
        parent_id = attack_id.split(".")[0] if is_sub and "." in attack_id else None

        mitigations = []
        for mit in _entries(mit_bulk, tech.id):
            mit_id, _ = _ref_id_url(mit, source_names)
            mitigations.append({"id": mit_id or mad.get_attack_id(mit.id), "name": mit.name})

        detection, data_components, log_sources = _detection_for(tech.id, ds_bulk, analytic_index, dc_index)
        if not detection:
            detection = (getattr(tech, "x_mitre_detection", "") or "").strip()
        if not detection and data_components:
            detection = "Data sources: " + ", ".join(data_components)

        techniques.append(
            NormalizedTechnique(
                framework=common.FRAMEWORK_ATTACK,
                id=attack_id,
                name=tech.name,
                description=(getattr(tech, "description", "") or "").strip(),
                tactics=tactic_shortnames,
                tactic_names=tactic_names,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                detection=detection,
                data_components=data_components,
                mitigations=mitigations,
                platforms=list(getattr(tech, "x_mitre_platforms", []) or []),
                url=url,
                stix_id=tech.id,
                references=_all_references(tech),
                domain=domain,
                extra={
                    "is_revoked": bool(getattr(tech, "revoked", False)),
                    "version": getattr(tech, "x_mitre_version", None),
                    "log_sources": log_sources,
                },
            )
        )
    techniques.sort(key=lambda t: t.id)
    return techniques


def _tactic_records(mad: MitreAttackData) -> list[dict]:
    records = []
    for sn, meta in sorted(_build_tactic_index(mad).items()):
        records.append({"shortname": sn, "id": meta["id"], "name": meta["name"], "url": meta["url"]})
    return records


def _mitigation_records(mad: MitreAttackData) -> list[dict]:
    source_names = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
    out = []
    for mit in mad.get_mitigations(remove_revoked_deprecated=True):
        mid, url = _ref_id_url(mit, source_names)
        out.append(
            {
                "id": mid or mad.get_attack_id(mit.id),
                "name": mit.name,
                "description": common.first_line(getattr(mit, "description", "")),
                "url": url,
            }
        )
    out.sort(key=lambda m: (m["id"] or ""))
    return out


def fetch_attack(domains: list[str] | None = None, *, refresh: bool = False) -> dict:
    domains = domains or list(config.ATTACK_DOMAINS)
    results = {}
    for domain in domains:
        url = config.ATTACK_DOMAINS[domain]
        raw_path = config.RAW_DIR / f"{domain}.json"
        if refresh or not raw_path.exists():
            common.download_to(url, raw_path)
        else:
            log(f"using cached raw bundle {raw_path.name} (use --refresh to re-download)")

        log(f"loading {domain} into MitreAttackData ...")
        mad = MitreAttackData(stix_filepath=str(raw_path))
        techniques = normalize_domain(mad, domain)
        out_path = config.NORMALIZED_DIR / f"attack_{domain.replace('-attack', '')}.json"
        common.dump_framework(
            out_path,
            framework=common.FRAMEWORK_ATTACK,
            source=url,
            source_version=f"attack-stix-data/master ({domain})",
            techniques=techniques,
            tactics=_tactic_records(mad),
            mitigations=_mitigation_records(mad),
            extra={"domain": domain},
        )
        results[domain] = {"techniques": len(techniques), "normalized": str(out_path)}
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch + normalize MITRE ATT&CK via mitreattack-python.")
    parser.add_argument(
        "--domain",
        action="append",
        choices=list(config.ATTACK_DOMAINS),
        help="ATT&CK domain(s) to process; repeatable. Default: all.",
    )
    parser.add_argument("--refresh", action="store_true", help="Re-download STIX bundles even if cached.")
    args = parser.parse_args()
    summary = fetch_attack(args.domain, refresh=args.refresh)
    log(f"ATT&CK done: {summary}")


if __name__ == "__main__":
    main()
