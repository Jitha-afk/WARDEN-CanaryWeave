"""Transform normalized MITRE dumps into WARDEN / MCP-oriented artifacts.

This is the "fit and transform" step. It consumes the framework-neutral dumps
produced by the fetchers (``data/normalized/*.json``) plus the OWASP MCP Top 10
index, then emits four things under ``data/warden/``:

* ``technique_catalog.json`` - every ATT&CK + ATLAS technique enriched with its
  ``.war`` anchor, suggested severity, mapped D3FEND defenses, and the OWASP MCP
  risks it relates to. This is the raw material an author (or an LLM) reads to
  write or improve a rule.
* ``mcp_focus.json`` - the MCP-relevant subset, grouped by OWASP risk and by
  tactic, plus the full ATLAS catalogue (always in scope for an LLM/agent).
* ``rule_scaffolds/*.war`` - minimal, **schema-valid** ``.war`` rule skeletons,
  one file per OWASP risk, ready to be fleshed out with patterns. Every scaffold
  is validated with the repository's own rule loader before it is written, so a
  generated file is guaranteed to parse.
* ``coverage_report.md`` - a gap analysis of the MCP-focus techniques against the
  anchors already present in the hand-authored ``rules/*.war``.

The cross-reference from OWASP risk to MITRE technique starts from the curated
seeds in :data:`config.OWASP_MCP_RISK_MAP` (validated against the freshly
downloaded data) and is widened by a tactic-and-keyword heuristic.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import config
from common import (
    FRAMEWORK_ATLAS,
    FRAMEWORK_ATTACK,
    first_line,
    log,
    now_iso,
    read_json,
    write_json,
    write_text,
)

# --------------------------------------------------------------------------- #
# Optional: the repository's own rule loader, used to validate scaffolds.
# Importing it keeps generated .war files honest - if it cannot parse what we
# emit, we do not write the file.
# --------------------------------------------------------------------------- #
sys.path.insert(0, str(config.REPO_ROOT / "src"))
try:
    from canaryweave_fides.rule_loader import parse_ruleset  # type: ignore
    from canaryweave_fides.rule_schema import RuleValidationError  # type: ignore

    _HAVE_LOADER = True
except Exception as exc:  # noqa: BLE001 - validation is best-effort
    parse_ruleset = None  # type: ignore
    RuleValidationError = Exception  # type: ignore
    _HAVE_LOADER = False
    _LOADER_ERR = exc


# --------------------------------------------------------------------------- #
# Heuristics
# --------------------------------------------------------------------------- #
# Tactics (shortnames) and tactic-name hints that warrant a high severity.
_HIGH_TACTICS = {
    "initial-access",
    "execution",
    "privilege-escalation",
    "credential-access",
    "command-and-control",
    "exfiltration",
    "impact",
}
_HIGH_NAME_HINTS = (
    "execution",
    "escalation",
    "credential",
    "exfiltration",
    "impact",
    "command and control",
    "initial access",
    "ml attack staging",
    "ml supply chain",
)
_ACTION_FOR_SEVERITY = {
    "critical": "block_and_audit",
    "high": "block_and_audit",
    "medium": "quarantine",
    "low": "audit",
}

# Per-risk primary built-in fact wired into each scaffold's condition, plus
# additional facts offered as inline suggestions. Names must exist in the engine
# fact registry (canaryweave_fides.fact_registry.FACT_NAMES).
_RISK_PRIMARY_FACT = {
    "MCP01": "from_untrusted_origin",
    "MCP02": "capability_denied",
    "MCP03": "tool_call_shape",
    "MCP04": "tool_call_shape",
    "MCP05": "capability_denied",
    "MCP06": "instruction_shape",
    "MCP07": "from_untrusted_origin",
    "MCP08": "from_untrusted_origin",
    "MCP09": "tool_call_shape",
    "MCP10": "from_untrusted_origin",
}
_RISK_EXTRA_FACTS = {
    "MCP01": ["canary_outside_sink"],
    "MCP02": ["from_untrusted_origin", "tool_call_shape"],
    "MCP03": ["from_untrusted_origin", "instruction_shape"],
    "MCP04": ["from_untrusted_origin"],
    "MCP05": ["from_untrusted_origin", "tool_call_shape"],
    "MCP06": ["from_untrusted_origin", "hidden_unicode"],
    "MCP07": ["tool_call_shape"],
    "MCP08": [],
    "MCP09": ["from_untrusted_origin"],
    "MCP10": ["canary_outside_sink", "hidden_unicode"],
}

# Cap how many techniques become scaffolds per risk; the full set still lives in
# the catalog and the MCP focus file.
_SCAFFOLDS_PER_RISK = 12


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _load_normalized() -> dict[str, Any]:
    """Read every normalized dump that exists under ``data/normalized``."""
    nd = config.NORMALIZED_DIR
    if not nd.exists():
        raise FileNotFoundError(f"normalized data dir missing: {nd} (run the fetchers first)")

    attack: list[dict] = []
    attack_versions: list[str] = []
    for path in sorted(nd.glob("attack_*.json")):
        doc = read_json(path)
        attack.extend(doc.get("techniques", []))
        attack_versions.append(doc.get("source_version", path.stem))

    atlas_doc = read_json(nd / "atlas.json") if (nd / "atlas.json").exists() else {}
    d3fend_doc = read_json(nd / "d3fend.json") if (nd / "d3fend.json").exists() else {}

    atlas = atlas_doc.get("techniques", [])
    d3fend = d3fend_doc.get("techniques", [])

    owasp_index_path = config.OWASP_MCP10_DIR / "index.json"
    owasp_index = read_json(owasp_index_path) if owasp_index_path.exists() else {}

    if not attack and not atlas:
        raise RuntimeError("no ATT&CK or ATLAS techniques found - run the fetchers first")

    log(
        f"loaded {len(attack)} ATT&CK + {len(atlas)} ATLAS + {len(d3fend)} D3FEND techniques"
    )
    return {
        "attack": attack,
        "attack_versions": attack_versions,
        "atlas": atlas,
        "atlas_version": atlas_doc.get("source_version", ""),
        "d3fend": d3fend,
        "d3fend_version": d3fend_doc.get("source_version", ""),
        "attack_to_defense": d3fend_doc.get("attack_to_defense", {}),
        "owasp_index": owasp_index,
    }


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def _severity_for(rec: dict) -> str:
    short = set(rec.get("tactics") or [])
    names = " ".join(rec.get("tactic_names") or []).lower()
    if short & _HIGH_TACTICS or any(hint in names for hint in _HIGH_NAME_HINTS):
        return "high"
    return "medium"


def _attack_mcp_relevant(rec: dict, seed_ids: set[str]) -> bool:
    rid = rec.get("id", "")
    parent = rec.get("parent_id")
    if rid in seed_ids or (parent and parent in seed_ids):
        return True
    if not (set(rec.get("tactics") or []) & config.MCP_RELEVANT_ATTACK_TACTICS):
        return False
    hay = (rec.get("name", "") + " " + (rec.get("description") or "")).lower()
    return any(kw.strip() in hay for kw in config.MCP_RELEVANCE_KEYWORDS)


def _validate_seeds(by_id: dict[str, dict]) -> list[str]:
    warnings: list[str] = []
    for risk in config.OWASP_MCP_RISK_MAP:
        for key in ("attack_seed", "atlas_seed"):
            for sid in risk.get(key, []):
                if sid not in by_id:
                    warnings.append(f"{risk['id']} ({risk['title']}): seed {sid} not present in current data")
    if warnings:
        for w in warnings:
            log(f"WARN seed validation: {w}")
    return warnings


def _build_risk_assoc(
    attack: list[dict], atlas: list[dict], by_id: dict[str, dict]
) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
    """Associate each OWASP risk with MITRE technique ids.

    Members = validated curated seeds (and their sub-techniques) widened by a
    tactic-and-keyword match. Returns ``risk -> [ids]`` and ``id -> {risks}``.
    """
    children: dict[str, list[str]] = defaultdict(list)
    for rec in (*attack, *atlas):
        if rec.get("parent_id"):
            children[rec["parent_id"]].append(rec["id"])

    risk_to_tech: dict[str, list[str]] = {}
    tech_to_risk: dict[str, set[str]] = defaultdict(set)

    for risk in config.OWASP_MCP_RISK_MAP:
        rid = risk["id"]
        seeds = [s for s in (*risk.get("attack_seed", []), *risk.get("atlas_seed", [])) if s in by_id]
        members: set[str] = set(seeds)
        for seed in seeds:
            members.update(children.get(seed, []))

        keywords = [k.lower() for k in risk.get("keywords", [])]
        tactics = set(risk.get("tactics", []))

        for rec in attack:
            if set(rec.get("tactics") or []) & tactics:
                hay = (rec.get("name", "") + " " + (rec.get("description") or "")).lower()
                if any(kw in hay for kw in keywords):
                    members.add(rec["id"])
        for rec in atlas:
            hay = (rec.get("name", "") + " " + (rec.get("description") or "")).lower()
            if any(kw in hay for kw in keywords):
                members.add(rec["id"])

        members = {m for m in members if m in by_id}
        seed_set = set(seeds)
        risk_to_tech[rid] = sorted(members, key=_risk_sort_key(by_id, seed_set))
        for m in members:
            tech_to_risk[m].add(rid)

    return risk_to_tech, tech_to_risk


def _risk_sort_key(by_id: dict[str, dict], seed_set: set[str]):
    """Curated seeds first, then ATLAS, then parents before subs, then id."""

    def key(tid: str):
        rec = by_id.get(tid, {})
        seed_rank = 0 if tid in seed_set else 1
        fw_rank = 0 if rec.get("framework") == FRAMEWORK_ATLAS else 1
        sub_rank = 1 if rec.get("is_subtechnique") else 0
        return (seed_rank, fw_rank, sub_rank, tid)

    return key


def _defenses_for(
    rec: dict, attack_to_defense: dict[str, list[str]], d3fend_by_id: dict[str, dict]
) -> list[dict]:
    ids: list[str] = []
    if rec.get("framework") == FRAMEWORK_ATTACK:
        ids = list(attack_to_defense.get(rec["id"], []))
        if not ids and rec.get("parent_id"):
            ids = list(attack_to_defense.get(rec["parent_id"], []))
    elif rec.get("framework") == FRAMEWORK_ATLAS:
        for mapped in rec.get("attack_mappings") or []:
            ids.extend(attack_to_defense.get(mapped, []))

    out: list[dict] = []
    seen: set[str] = set()
    for did in ids:
        if did in seen:
            continue
        seen.add(did)
        d3 = d3fend_by_id.get(did, {})
        name = (d3.get("name") or "").replace(",", " ").strip()
        out.append(
            {
                "id": did,
                "name": name,
                "anchor": f"{did} ({name})" if name else did,
                "tactic": (d3.get("tactic_names") or [None])[0],
            }
        )
    return out


# --------------------------------------------------------------------------- #
# .war scaffold rendering
# --------------------------------------------------------------------------- #
def _war_text(value: str, limit: int = 220) -> str:
    """Make free text safe for a quoted .war string / scored term."""
    text = re.sub(r"\s+", " ", (value or "")).strip()
    text = text.replace("\\", "/").replace('"', "'")
    text = text.rstrip("(").strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text


def _rule_name(prefix: str, name: str, used: set[str]) -> str:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", name) if p]
    camel = "".join(p[:1].upper() + p[1:].lower() for p in parts)
    base = f"{prefix}{camel}"[:60]
    if not base or not (base[0].isalpha() or base[0] == "_"):
        base = "Rule" + base
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _anchor_with_strength(rec: dict, strength: str = "analogical") -> str:
    label = (rec.get("tactic_names") or [""])[0].replace(",", " ").strip()
    if label:
        return f"{rec['id']} ({label}, {strength})"
    return rec["id"]


def _render_rule(
    *,
    rule_id: str,
    rule_name: str,
    rec: dict,
    risk: dict,
    severity: str,
    defenses: list[dict],
) -> str:
    """Render one schema-valid .war rule scaffold for a technique."""
    fw = "ATLAS" if rec.get("framework") == FRAMEWORK_ATLAS else "ATT&CK"
    # ATLAS techniques are first-class LLM/agent threats -> map directly; ATT&CK
    # techniques are mapped by analogy onto the MCP surface.
    strength = "direct" if rec.get("framework") == FRAMEWORK_ATLAS else "analogical"
    technique_anchor = _anchor_with_strength(rec, strength)

    primary_fact = _RISK_PRIMARY_FACT.get(risk["id"], "from_untrusted_origin")
    extra_facts = [f for f in _RISK_EXTRA_FACTS.get(risk["id"], []) if f != primary_fact]
    action = _ACTION_FOR_SEVERITY.get(severity, "audit")

    desc = _war_text(
        f"{rec.get('name', '')} ({rec['id']}) reachable through an MCP tool, resource, "
        f"or agent surface; relates to OWASP {risk['id']} {risk['title']}."
    )
    sem_text = _war_text(
        f"Content or tool activity is consistent with {rec.get('name', '')} "
        f"[{rec['id']}] against an MCP/agent surface."
    )
    judge_text = _war_text(
        f"Assess whether public-safe facts indicate {rec.get('name', '')} [{rec['id']}] "
        f"is being attempted via the MCP/agent surface described by OWASP "
        f"{risk['id']}: {risk['title']}."
    )

    lines: list[str] = []
    lines.append(f"rule {rule_name} {{")
    lines.append("    meta:")
    lines.append(f"        id          = {rule_id}")
    lines.append("        version     = 0.1.0")
    lines.append(f"        severity    = {severity}")
    lines.append("        scope       = event_window")
    lines.append(f"        action      = {action}")
    lines.append(f"        technique   = {technique_anchor}")
    if defenses:
        lines.append(f"        defense     = {defenses[0]['anchor']}")
    lines.append(f'        description = "{desc}"')
    lines.append(f"        owasp_mcp   = {risk['id']}")
    lines.append("        status      = scaffold")
    lines.append('        safety      = "Generic technique indicators only; no memorized payload strings."')
    # Authoring hints (full-line comments are ignored by the parser).
    lines.append(f"    // framework: {fw}  |  source technique: {rec.get('name', '')}")
    if rec.get("tactic_names"):
        lines.append(f"    // tactics: {', '.join(rec['tactic_names'])}")
    if rec.get("url"):
        lines.append(f"    // reference: {rec['url']}")
    if extra_facts:
        lines.append(f"    // suggested extra facts: {', '.join('$' + f for f in extra_facts)}")
    if len(defenses) > 1:
        more = ", ".join(d["anchor"] for d in defenses[1:6])
        lines.append(f"    // related D3FEND defenses: {more}")
    lines.append("    // TODO add deterministic patterns, then tighten the condition to:")
    lines.append(f"    //   (($p1 or $p2) and ${primary_fact}) or $intent or $judge")
    lines.append("    semantics:")
    lines.append(f'        $intent = "{sem_text}" (0.65)')
    lines.append("    judge:")
    lines.append(f'        $judge = "{judge_text}" (0.60)')
    lines.append("    condition:")
    lines.append(f"        (${primary_fact} and $intent) or $judge")
    lines.append("}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Existing-rule coverage
# --------------------------------------------------------------------------- #
_ANCHOR_ID_RE = re.compile(r"\b(AML\.T\d{4}(?:\.\d{3})?|T\d{4}(?:\.\d{3})?|D3-[A-Za-z]+)\b")


def _existing_anchor_coverage() -> dict[str, list[str]]:
    """Map every MITRE id referenced by ``rules/*.war`` to the files using it."""
    coverage: dict[str, list[str]] = defaultdict(list)
    if not config.RULES_DIR.exists():
        return coverage
    for path in sorted(config.RULES_DIR.rglob("*.war")):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("technique") or stripped.startswith("defense"):
                for match in _ANCHOR_ID_RE.findall(stripped):
                    if path.name not in coverage[match]:
                        coverage[match].append(path.name)
    return coverage


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def transform() -> dict[str, Any]:
    data = _load_normalized()
    attack: list[dict] = data["attack"]
    atlas: list[dict] = data["atlas"]
    d3fend: list[dict] = data["d3fend"]
    attack_to_defense: dict[str, list[str]] = data["attack_to_defense"]

    by_id: dict[str, dict] = {}
    for rec in (*attack, *atlas):
        by_id.setdefault(rec["id"], rec)
    d3fend_by_id = {rec["id"]: rec for rec in d3fend}

    seed_ids = {
        sid
        for risk in config.OWASP_MCP_RISK_MAP
        for sid in (*risk.get("attack_seed", []), *risk.get("atlas_seed", []))
    }
    seed_warnings = _validate_seeds(by_id)
    risk_to_tech, tech_to_risk = _build_risk_assoc(attack, atlas, by_id)
    risk_titles = {r["id"]: r["title"] for r in config.OWASP_MCP_RISK_MAP}

    # ---- enrich every technique ----
    catalog: list[dict] = []
    for rec in (*attack, *atlas):
        relevant = (
            True if rec.get("framework") == FRAMEWORK_ATLAS else _attack_mcp_relevant(rec, seed_ids)
        )
        risks = sorted(tech_to_risk.get(rec["id"], set()))
        defenses = _defenses_for(rec, attack_to_defense, d3fend_by_id)
        severity = _severity_for(rec)
        catalog.append(
            {
                "framework": rec["framework"],
                "id": rec["id"],
                "name": rec.get("name", ""),
                "anchor": rec.get("anchor", ""),
                "meta_key": rec.get("meta_key", "technique"),
                "is_subtechnique": rec.get("is_subtechnique", False),
                "parent_id": rec.get("parent_id"),
                "tactics": rec.get("tactics", []),
                "tactic_names": rec.get("tactic_names", []),
                "platforms": rec.get("platforms", []),
                "severity_suggestion": severity,
                "mcp_relevant": relevant or bool(risks),
                "mcp_risks": risks,
                "defenses": defenses,
                "data_components": rec.get("data_components", []),
                "mitigations": rec.get("mitigations", []),
                "url": rec.get("url", ""),
                "summary": first_line(rec.get("description") or "", 400),
                "description": rec.get("description", ""),
            }
        )
    catalog_by_id = {c["id"]: c for c in catalog}

    catalog_payload = {
        "generated": now_iso(),
        "generator": "automation/mitre/transform_warden.py",
        "sources": {
            "attack": data["attack_versions"],
            "atlas": data["atlas_version"],
            "d3fend": data["d3fend_version"],
        },
        "counts": {
            "attack": len(attack),
            "atlas": len(atlas),
            "d3fend": len(d3fend),
            "mcp_relevant": sum(1 for c in catalog if c["mcp_relevant"]),
        },
        "owasp_risks": [{"id": r["id"], "title": r["title"]} for r in config.OWASP_MCP_RISK_MAP],
        "techniques": catalog,
    }
    catalog_path = config.WARDEN_DIR / "technique_catalog.json"
    write_json(catalog_path, catalog_payload)
    log(f"wrote {catalog_path.name}: {len(catalog)} techniques")

    # ---- MCP focus subset ----
    def _focus_view(tid: str) -> dict:
        c = catalog_by_id[tid]
        return {
            "id": c["id"],
            "name": c["name"],
            "framework": c["framework"],
            "anchor": c["anchor"],
            "is_subtechnique": c["is_subtechnique"],
            "tactic_names": c["tactic_names"],
            "severity_suggestion": c["severity_suggestion"],
            "defenses": [d["anchor"] for d in c["defenses"]],
            "summary": c["summary"],
        }

    by_risk = {}
    for risk in config.OWASP_MCP_RISK_MAP:
        tids = risk_to_tech.get(risk["id"], [])
        by_risk[risk["id"]] = {
            "title": risk["title"],
            "tactics": risk["tactics"],
            "technique_count": len(tids),
            "techniques": [_focus_view(t) for t in tids],
        }

    by_tactic: dict[str, list[str]] = defaultdict(list)
    for c in catalog:
        if c["mcp_relevant"]:
            for tn in c["tactic_names"] or ["Unspecified"]:
                by_tactic[tn].append(c["id"])

    focus_payload = {
        "generated": now_iso(),
        "generator": "automation/mitre/transform_warden.py",
        "seed_validation_warnings": seed_warnings,
        "by_risk": by_risk,
        "by_tactic": {k: sorted(v) for k, v in sorted(by_tactic.items())},
        "atlas": [_focus_view(rec["id"]) for rec in atlas if rec["id"] in catalog_by_id],
    }
    focus_path = config.WARDEN_DIR / "mcp_focus.json"
    write_json(focus_path, focus_payload)
    log(f"wrote {focus_path.name}: {sum(len(v['techniques']) for v in by_risk.values())} risk-technique links")

    # ---- .war scaffolds ----
    scaffold_summary = _emit_scaffolds(risk_to_tech, catalog_by_id, by_id)

    # ---- coverage report ----
    coverage_path = _emit_coverage_report(risk_to_tech, catalog_by_id, seed_warnings)

    summary = {
        "generated": now_iso(),
        "technique_catalog": str(catalog_path.relative_to(config.REPO_ROOT)),
        "mcp_focus": str(focus_path.relative_to(config.REPO_ROOT)),
        "coverage_report": str(coverage_path.relative_to(config.REPO_ROOT)),
        "scaffolds": scaffold_summary,
        "seed_validation_warnings": seed_warnings,
        "counts": catalog_payload["counts"],
    }
    write_json(config.WARDEN_DIR / "summary.json", summary)
    log("transform complete")
    return summary


def _emit_scaffolds(
    risk_to_tech: dict[str, list[str]],
    catalog_by_id: dict[str, dict],
    by_id: dict[str, dict],
) -> dict[str, Any]:
    config.SCAFFOLD_DIR.mkdir(parents=True, exist_ok=True)
    # Clear stale scaffolds so re-runs are deterministic.
    for old in config.SCAFFOLD_DIR.glob("*.war"):
        old.unlink()

    used_names: set[str] = set()
    counter = 0
    total_rules = 0
    files: list[dict] = []
    validation_errors: list[str] = []

    for risk in config.OWASP_MCP_RISK_MAP:
        rid = risk["id"]
        tids = risk_to_tech.get(rid, [])[:_SCAFFOLDS_PER_RISK]
        if not tids:
            continue

        header = [
            f"// CanaryWeave WARDEN scaffold ruleset: OWASP {rid} - {risk['title']}.",
            "//",
            "// Auto-generated by automation/mitre/transform_warden.py from MITRE",
            "// ATT&CK / ATLAS data cross-referenced with the OWASP MCP Top 10.",
            "// These are STARTING POINTS: add deterministic patterns and review",
            "// thresholds before promoting any rule into rules/.",
            "",
        ]
        blocks: list[str] = []
        rules_in_file = 0
        for tid in tids:
            rec = by_id.get(tid)
            cat = catalog_by_id.get(tid)
            if not rec or not cat:
                continue
            counter += 1
            rule_id = f"cwfr-mcp-{counter:04d}"
            prefix = f"{rid.replace('MCP', 'Mcp')}"
            rule_name = _rule_name(prefix, rec.get("name", tid), used_names)
            block = _render_rule(
                rule_id=rule_id,
                rule_name=rule_name,
                rec=rec,
                risk=risk,
                severity=cat["severity_suggestion"],
                defenses=cat["defenses"],
            )
            blocks.append(block)
            rules_in_file += 1

        if not blocks:
            continue
        content = "\n".join(header) + "\n\n".join(blocks) + "\n"

        # Validate with the repo's own loader before writing.
        ok = True
        if _HAVE_LOADER:
            try:
                parsed = parse_ruleset(content, source=f"{rid}.war")  # type: ignore
                rules_in_file = len(parsed)
            except RuleValidationError as exc:  # type: ignore
                ok = False
                validation_errors.append(f"{rid}: {exc}")
                log(f"ERROR scaffold {rid} failed validation: {exc}")

        if not ok:
            continue
        fname = f"{rid.lower()}_{_slug(risk['title'])}.war"
        path = config.SCAFFOLD_DIR / fname
        write_text(path, content)
        total_rules += rules_in_file
        files.append({"risk": rid, "file": fname, "rules": rules_in_file})
        log(f"scaffold {fname}: {rules_in_file} rules")

    return {
        "validated_with_repo_loader": _HAVE_LOADER,
        "loader_error": None if _HAVE_LOADER else repr(_LOADER_ERR),
        "files": files,
        "total_rules": total_rules,
        "validation_errors": validation_errors,
    }


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", value.lower())
    return value.strip("_")[:48]


def _emit_coverage_report(
    risk_to_tech: dict[str, list[str]],
    catalog_by_id: dict[str, dict],
    seed_warnings: list[str],
) -> Path:
    coverage = _existing_anchor_coverage()
    covered_ids = set(coverage)

    lines: list[str] = []
    lines.append("# MCP coverage report")
    lines.append("")
    lines.append(f"_Generated {now_iso()} by automation/mitre/transform_warden.py_")
    lines.append("")
    lines.append(
        "Gap analysis of MCP-relevant MITRE techniques (per OWASP MCP Top 10) "
        "against anchors already referenced by hand-authored `rules/*.war`."
    )
    lines.append("")

    if covered_ids:
        lines.append("## Anchors already used by rules/")
        lines.append("")
        for anchor in sorted(covered_ids):
            files = ", ".join(sorted(coverage[anchor]))
            lines.append(f"- `{anchor}` - {files}")
        lines.append("")

    total_focus = 0
    total_covered = 0
    lines.append("## Per-risk coverage")
    lines.append("")
    for risk in config.OWASP_MCP_RISK_MAP:
        rid = risk["id"]
        tids = risk_to_tech.get(rid, [])
        total_focus += len(tids)
        covered = [t for t in tids if t in covered_ids or (catalog_by_id.get(t, {}).get("parent_id") in covered_ids)]
        gaps = [t for t in tids if t not in covered]
        total_covered += len(covered)
        pct = (len(covered) / len(tids) * 100) if tids else 0.0
        lines.append(f"### {rid} - {risk['title']}")
        lines.append("")
        lines.append(f"{len(covered)}/{len(tids)} techniques covered ({pct:.0f}%).")
        lines.append("")
        if gaps:
            lines.append("Uncovered techniques (candidates for new/updated rules):")
            lines.append("")
            lines.append("| id | name | framework | tactics | suggested severity |")
            lines.append("| --- | --- | --- | --- | --- |")
            for tid in gaps:
                c = catalog_by_id.get(tid, {})
                tactics = ", ".join(c.get("tactic_names", []))
                lines.append(
                    f"| `{tid}` | {c.get('name', '')} | {c.get('framework', '')} "
                    f"| {tactics} | {c.get('severity_suggestion', '')} |"
                )
            lines.append("")
        else:
            lines.append("All focus techniques for this risk are anchored by an existing rule.")
            lines.append("")

    overall = (total_covered / total_focus * 100) if total_focus else 0.0
    summary_block = [
        "## Summary",
        "",
        f"- MCP-focus techniques: **{total_focus}**",
        f"- Covered by existing rules: **{total_covered}** ({overall:.0f}%)",
        f"- Gaps: **{total_focus - total_covered}**",
    ]
    if seed_warnings:
        summary_block.append(f"- Seed validation warnings: **{len(seed_warnings)}** (see mcp_focus.json)")
    # Surface the summary near the top, after the intro paragraph.
    lines = lines[:5] + summary_block + [""] + lines[5:]

    path = config.WARDEN_DIR / "coverage_report.md"
    write_text(path, "\n".join(lines) + "\n")
    log(f"wrote {path.name}: {total_covered}/{total_focus} covered")
    return path


def main() -> int:
    if not _HAVE_LOADER:
        log(f"NOTE: repo rule loader unavailable ({_LOADER_ERR!r}); scaffolds will be emitted unvalidated")
    transform()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
