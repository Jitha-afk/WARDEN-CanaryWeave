"""Fetch the OWASP MCP Top 10 (2025) into ``OWASP/mcp10/``.

Walks the GitHub Contents API for the project's ``2025/`` folder (which avoids
the en-dash filename pitfall by handing back correctly encoded download URLs),
mirrors every file locally, and writes an ``index.json`` + ``README.md`` that
links each MCP risk to its curated MITRE ATT&CK / ATLAS cross-reference.

Run directly:
    python fetch_owasp_mcp.py [--refresh]
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import common
import config
from common import log


def _walk_contents(api_url: str) -> list[dict]:
    """Recursively list files under a GitHub Contents API directory URL."""
    files: list[dict] = []
    entries = common.http_get_json(api_url)
    for entry in entries:
        if entry["type"] == "file":
            files.append(entry)
        elif entry["type"] == "dir":
            files.extend(_walk_contents(entry["url"]))
    return files


def _title_of(markdown: str, fallback: str) -> str:
    fm = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', markdown, re.MULTILINE)
    if fm:
        return fm.group(1).strip()
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return fallback


def _risk_id(filename: str) -> str | None:
    match = re.match(r"(MCP\d{2})", filename)
    return match.group(1) if match else None


def fetch_owasp_mcp(*, refresh: bool = False) -> dict:
    dest_root = config.OWASP_MCP10_DIR
    dest_root.mkdir(parents=True, exist_ok=True)

    log(f"listing OWASP MCP Top 10 contents from {config.OWASP_MCP10_API}")
    files = _walk_contents(config.OWASP_MCP10_API)
    log(f"found {len(files)} files")

    # Curated MITRE cross-reference keyed by MCP id.
    risk_map = {risk["id"]: risk for risk in config.OWASP_MCP_RISK_MAP}

    risks: list[dict] = []
    for entry in sorted(files, key=lambda e: e["path"]):
        rel = entry["path"].removeprefix("2025/")
        dest = dest_root / rel
        if refresh or not dest.exists():
            text = common.http_get_text(entry["download_url"])
            common.write_text(dest, text)
        else:
            text = dest.read_text(encoding="utf-8")
        log(f"  {rel}")

        if not rel.lower().endswith(".md") or "/" in rel:
            continue  # only top-level risk docs feed the index
        rid = _risk_id(entry["name"])
        if not rid:
            continue
        crossref = risk_map.get(rid, {})
        risks.append(
            {
                "id": rid,
                "title": _title_of(text, crossref.get("title", entry["name"])),
                "file": rel,
                "source_url": entry["html_url"],
                "raw_url": entry["download_url"],
                "mitre_crossref": {
                    "attack_seed": crossref.get("attack_seed", []),
                    "atlas_seed": crossref.get("atlas_seed", []),
                    "tactics": crossref.get("tactics", []),
                    "keywords": crossref.get("keywords", []),
                },
            }
        )
    risks.sort(key=lambda r: r["id"])

    index = {
        "project": "OWASP MCP Top 10 (2025)",
        "source": "https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025",
        "generated": common.now_iso(),
        "risk_count": len(risks),
        "risks": risks,
    }
    common.write_json(dest_root / "index.json", index)
    common.write_text(dest_root / "README.md", _render_readme(index))
    return {"files": len(files), "risks": len(risks), "dest": str(dest_root)}


def _render_readme(index: dict) -> str:
    lines = [
        "# OWASP MCP Top 10 (2025) — local mirror",
        "",
        f"Mirrored from <{index['source']}> on {index['generated']}.",
        "",
        "Each risk links to the curated MITRE ATT&CK / ATLAS seed anchors used by",
        "`automation/mitre/transform_warden.py` to focus technique selection on the",
        "MCP threat surface. Seeds are validated against live MITRE data at transform time.",
        "",
        "| ID | Risk | ATT&CK seeds | ATLAS seeds | Tactics |",
        "|----|------|--------------|-------------|---------|",
    ]
    for risk in index["risks"]:
        cr = risk["mitre_crossref"]
        lines.append(
            f"| {risk['id']} | [{risk['title']}]({risk['file']}) "
            f"| {', '.join(cr['attack_seed']) or '—'} "
            f"| {', '.join(cr['atlas_seed']) or '—'} "
            f"| {', '.join(cr['tactics']) or '—'} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mirror the OWASP MCP Top 10 (2025) into OWASP/mcp10/.")
    parser.add_argument("--refresh", action="store_true", help="Re-download files even if present.")
    args = parser.parse_args()
    summary = fetch_owasp_mcp(refresh=args.refresh)
    log(f"OWASP MCP Top 10 done: {summary}")


if __name__ == "__main__":
    main()
