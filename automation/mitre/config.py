"""Central configuration for the MITRE -> WARDEN automation.

Holds source URLs, output paths, and the LLM/MCP relevance heuristics the
transform step uses to fit raw MITRE techniques onto the MCP threat surface.

All MITRE/OWASP sources used here are public, machine-readable knowledge bases.
"""
from __future__ import annotations

from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

DATA_DIR = HERE / "data"
RAW_DIR = DATA_DIR / "raw"
NORMALIZED_DIR = DATA_DIR / "normalized"
WARDEN_DIR = DATA_DIR / "warden"
SCAFFOLD_DIR = WARDEN_DIR / "rule_scaffolds"

# OWASP MCP Top 10 lands at the repo-root OWASP/mcp10 folder (per task spec).
OWASP_DIR = REPO_ROOT / "OWASP"
OWASP_MCP10_DIR = OWASP_DIR / "mcp10"

# Existing hand-authored rules, used to compute an anchor-coverage report.
RULES_DIR = REPO_ROOT / "rules"

# --------------------------------------------------------------------------- #
# MITRE ATT&CK (STIX 2.1 bundles from the official attack-stix-data repo)
# `master` always points at the latest released version.
# --------------------------------------------------------------------------- #
ATTACK_STIX_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
ATTACK_DOMAINS: dict[str, str] = {
    "enterprise-attack": f"{ATTACK_STIX_BASE}/enterprise-attack/enterprise-attack.json",
    "mobile-attack": f"{ATTACK_STIX_BASE}/mobile-attack/mobile-attack.json",
    "ics-attack": f"{ATTACK_STIX_BASE}/ics-attack/ics-attack.json",
}
# kill_chain_name used inside each domain's STIX technique objects.
ATTACK_KILL_CHAIN_NAMES = {
    "enterprise-attack": "mitre-attack",
    "mobile-attack": "mitre-mobile-attack",
    "ics-attack": "mitre-ics-attack",
}

# --------------------------------------------------------------------------- #
# MITRE ATLAS (adversarial ML). ATLAS does not host a STIX bundle, so we read
# the official, hosted YAML export directly.
# --------------------------------------------------------------------------- #
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"

# --------------------------------------------------------------------------- #
# MITRE D3FEND (defensive countermeasures). Not part of mitreattack-python and
# not published as STIX; we read the JSON-LD ontology plus the inferred
# D3FEND<->ATT&CK mapping API.
# --------------------------------------------------------------------------- #
D3FEND_JSONLD_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
D3FEND_MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"

# --------------------------------------------------------------------------- #
# OWASP MCP Top 10 (2025). The Contents API gives correctly URL-encoded
# download links, which matters because 9 of 10 filenames use an en/em dash.
# --------------------------------------------------------------------------- #
OWASP_MCP10_API = "https://api.github.com/repos/OWASP/www-project-mcp-top-10/contents/2025"

# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
USER_AGENT = "WARDEN-CanaryWeave-mitre-automation/0.1 (+https://github.com/Jitha-afk/WARDEN-CanaryWeave)"
HTTP_TIMEOUT = 180
HTTP_RETRIES = 3

# --------------------------------------------------------------------------- #
# LLM / MCP relevance heuristics (used by transform_warden.py)
# --------------------------------------------------------------------------- #
# ATT&CK tactics most relevant to MCP / agentic / tool-abuse threat surface.
# NOTE: ATT&CK v19 split the former "defense-evasion" tactic into "stealth" and
# "defense-impairment"; both are kept here (plus the legacy name, still used by
# the mobile/ics domains) so the heuristic tracks whichever the live data ships.
MCP_RELEVANT_ATTACK_TACTICS: set[str] = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

# Keyword heuristics over technique name + description that flag an ATT&CK
# technique as plausibly reachable through an MCP/LLM/agent surface.
MCP_RELEVANCE_KEYWORDS: tuple[str, ...] = (
    "prompt", "llm", "model", " agent", "tool", "api ", "token", "secret",
    "credential", "command", "script", "interpreter", "exfiltrat", "injection",
    "supply chain", "dependency", "plugin", "extension", "serializ", "deserializ",
    "ssrf", "web service", "web shell", "context", "session", "oauth", "scope",
)

# Curated cross-reference: each OWASP MCP Top 10 risk -> seed MITRE anchors and
# the keyword tags used to auto-attach further techniques. Seed IDs are
# validated against the freshly downloaded data at transform time; unknown IDs
# are reported rather than silently emitted.
OWASP_MCP_RISK_MAP: list[dict] = [
    {
        "id": "MCP01",
        "title": "Token Mismanagement and Secret Exposure",
        "attack_seed": ["T1552", "T1528", "T1550.001"],
        "atlas_seed": [],
        "tactics": ["credential-access", "collection"],
        "keywords": ["token", "secret", "credential", "api key", "oauth"],
    },
    {
        "id": "MCP02",
        "title": "Privilege Escalation via Scope Creep",
        "attack_seed": ["T1548", "T1068", "T1078"],
        "atlas_seed": [],
        "tactics": ["privilege-escalation"],
        "keywords": ["privilege", "scope", "escalat", "permission", "elevation"],
    },
    {
        "id": "MCP03",
        "title": "Tool Poisoning",
        "attack_seed": ["T1195", "T1554"],
        "atlas_seed": ["AML.T0051", "AML.T0010"],
        "tactics": ["initial-access", "execution"],
        "keywords": ["tool", "poison", "prompt injection", "description", "manifest"],
    },
    {
        "id": "MCP04",
        "title": "Software Supply Chain Attacks & Dependency Tampering",
        "attack_seed": ["T1195", "T1195.001", "T1195.002", "T1199"],
        "atlas_seed": ["AML.T0010"],
        "tactics": ["initial-access"],
        "keywords": ["supply chain", "dependency", "package", "tamper", "compromise"],
    },
    {
        "id": "MCP05",
        "title": "Command Injection & Execution",
        "attack_seed": ["T1059", "T1505.003"],
        "atlas_seed": [],
        "tactics": ["execution"],
        "keywords": ["command", "inject", "execut", "shell", "script", "interpreter"],
    },
    {
        "id": "MCP06",
        "title": "Intent Flow Subversion",
        "attack_seed": [],
        "atlas_seed": ["AML.T0051", "AML.T0054"],
        "tactics": ["initial-access", "execution"],
        "keywords": ["prompt injection", "jailbreak", "intent", "instruction", "hijack"],
    },
    {
        "id": "MCP07",
        "title": "Insufficient Authentication & Authorization",
        "attack_seed": ["T1078", "T1550"],
        "atlas_seed": [],
        "tactics": ["credential-access", "stealth", "defense-impairment", "defense-evasion"],
        "keywords": ["authentication", "authorization", "session", "valid account"],
    },
    {
        "id": "MCP08",
        "title": "Lack of Audit and Telemetry",
        # T1685 "Disable or Modify Tools" + T1685.002 "Disable or Modify Cloud Log"
        # are the ATT&CK v19 successors to the revoked T1562 / T1562.008.
        "attack_seed": ["T1070", "T1685", "T1685.002"],
        "atlas_seed": [],
        "tactics": ["stealth", "defense-impairment", "defense-evasion"],
        "keywords": ["audit", "log", "telemetry", "indicator removal", "evasion"],
    },
    {
        "id": "MCP09",
        "title": "Shadow MCP Servers",
        "attack_seed": ["T1133", "T1219", "T1071"],
        "atlas_seed": [],
        "tactics": ["command-and-control", "persistence"],
        "keywords": ["shadow", "rogue", "unauthorized server", "remote", "external"],
    },
    {
        "id": "MCP10",
        "title": "Context Injection & Oversharing",
        "attack_seed": ["T1567", "T1213"],
        "atlas_seed": ["AML.T0051", "AML.T0057"],
        "tactics": ["collection", "exfiltration"],
        "keywords": ["context", "oversharing", "exfiltrat", "disclosure", "leak"],
    },
]
