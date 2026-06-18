"""Shared utilities for the MITRE -> WARDEN automation.

Provides HTTP download, JSON/YAML IO, a slug helper, and the framework-neutral
``NormalizedTechnique`` record that every fetcher emits and the transform step
consumes. Keeping one record shape lets ATT&CK, ATLAS, and D3FEND techniques be
merged and turned into ``.war`` rule anchors uniformly.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

import config


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def log(message: str) -> None:
    """Print a timestamped progress line."""
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[mitre {stamp}] {message}", flush=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _session() -> requests.Session:
    sess = requests.Session()
    sess.headers.update({"User-Agent": config.USER_AGENT, "Accept": "application/json, text/plain, */*"})
    return sess


def http_get(url: str, *, timeout: int | None = None, retries: int | None = None) -> requests.Response:
    """GET with simple exponential backoff. Raises on the final failure."""
    timeout = timeout or config.HTTP_TIMEOUT
    retries = retries or config.HTTP_RETRIES
    last_exc: Exception | None = None
    with _session() as sess:
        for attempt in range(1, retries + 1):
            try:
                resp = sess.get(url, timeout=timeout)
                resp.raise_for_status()
                return resp
            except Exception as exc:  # noqa: BLE001 - re-raised after retries
                last_exc = exc
                wait = 2 ** attempt
                log(f"GET failed (attempt {attempt}/{retries}) {url}: {exc} - retrying in {wait}s")
                time.sleep(wait)
    raise RuntimeError(f"GET failed after {retries} attempts: {url}") from last_exc


def http_get_json(url: str, **kwargs: Any) -> Any:
    return http_get(url, **kwargs).json()


def http_get_text(url: str, **kwargs: Any) -> str:
    return http_get(url, **kwargs).text


def fetch_text_follow_symlink(url: str, *, max_hops: int = 6) -> tuple[str, str]:
    """Fetch text, transparently following git-symlink blobs.

    On raw.githubusercontent.com a symlinked file (e.g. ATLAS-latest.yaml)
    returns its relative target path as plain text rather than the content.
    Returns ``(text, resolved_url)``.
    """
    current = url
    text = ""
    for _ in range(max_hops):
        text = http_get_text(current)
        stripped = text.strip()
        looks_like_link = (
            "\n" not in stripped
            and 0 < len(stripped) < 200
            and stripped.lower().endswith((".yaml", ".yml", ".json"))
        )
        if not looks_like_link:
            return text, current
        nxt = urljoin(current, stripped)
        if nxt == current:
            break
        log(f"following symlink {current.rsplit('/', 1)[-1]} -> {stripped}")
        current = nxt
    return text, current


def download_to(url: str, dest: Path, **kwargs: Any) -> Path:
    """Stream a (possibly large) resource to disk."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    resp = http_get(url, **kwargs)
    dest.write_bytes(resp.content)
    log(f"downloaded {url} -> {dest.name} ({len(resp.content):,} bytes)")
    return dest


# --------------------------------------------------------------------------- #
# IO helpers
# --------------------------------------------------------------------------- #
def write_json(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False), encoding="utf-8")
    return path


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #
def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower())
    return value.strip("_")


def title_from_shortname(shortname: str) -> str:
    """``defense-evasion`` -> ``Defense Evasion`` (fallback when no name is known)."""
    return " ".join(part.capitalize() for part in re.split(r"[-_]", shortname) if part)


def first_line(text: str, limit: int = 280) -> str:
    text = (text or "").strip().replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


# --------------------------------------------------------------------------- #
# Normalized record
# --------------------------------------------------------------------------- #
FRAMEWORK_ATTACK = "attack"
FRAMEWORK_ATLAS = "atlas"
FRAMEWORK_D3FEND = "d3fend"


@dataclass
class NormalizedTechnique:
    """Framework-neutral technique/countermeasure record.

    ``framework`` is one of ``attack`` / ``atlas`` / ``d3fend``. The ``anchor``
    property renders the exact ``meta`` string a ``.war`` rule expects, and
    ``meta_key`` says whether it belongs under ``technique`` (ATT&CK/ATLAS) or
    ``defense`` (D3FEND).
    """

    framework: str
    id: str
    name: str
    description: str = ""
    tactics: list[str] = field(default_factory=list)        # machine shortnames
    tactic_names: list[str] = field(default_factory=list)   # human-readable
    is_subtechnique: bool = False
    parent_id: str | None = None
    detection: str = ""
    data_components: list[str] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    url: str = ""
    stix_id: str | None = None
    references: list[dict] = field(default_factory=list)
    attack_mappings: list[str] = field(default_factory=list)  # D3FEND -> ATT&CK ids
    domain: str = ""
    deprecated: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def meta_key(self) -> str:
        return "defense" if self.framework == FRAMEWORK_D3FEND else "technique"

    @property
    def anchor(self) -> str:
        """Render the ``.war`` anchor string.

        ATT&CK/ATLAS anchors carry the primary tactic name; D3FEND ``defense``
        anchors carry the countermeasure's own name, matching repo convention
        (e.g. ``T1059 (Execution)`` and ``D3-EI (Execution Isolation)``).
        """
        if self.framework == FRAMEWORK_D3FEND:
            label = self.name
        else:
            label = self.tactic_names[0] if self.tactic_names else ""
        label = label.replace(",", " ").strip()
        return f"{self.id} ({label})" if label else self.id

    def to_dict(self) -> dict:
        data = asdict(self)
        data["anchor"] = self.anchor
        data["meta_key"] = self.meta_key
        return data


def dump_framework(
    path: Path,
    *,
    framework: str,
    source: str,
    source_version: str,
    techniques: list[NormalizedTechnique],
    tactics: list[dict] | None = None,
    mitigations: list[dict] | None = None,
    extra: dict | None = None,
) -> Path:
    """Write a normalized per-framework bundle."""
    payload = {
        "framework": framework,
        "source": source,
        "source_version": source_version,
        "generated": now_iso(),
        "technique_count": len(techniques),
        "tactics": tactics or [],
        "mitigations": mitigations or [],
        "techniques": [t.to_dict() for t in techniques],
    }
    if extra:
        payload.update(extra)
    write_json(path, payload)
    log(f"normalized {framework}: {len(techniques)} techniques -> {path.name}")
    return path
