# MITRE → WARDEN automation

Python automation that downloads **all** of MITRE **ATT&CK**, **ATLAS**, and
**D3FEND**, normalizes them to one schema, and *fits and transforms* the result
onto the **OWASP MCP Top 10** threat surface so the output can drive new or
improved CanaryWeave WARDEN `.war` rules.

It also mirrors the OWASP MCP Top 10 (2025) into `OWASP/mcp10/`.

> **Everything under `data/` and `OWASP/mcp10/` is generated and git-ignored.**
> Only the scripts in this folder are version-controlled. Clone the repo, then
> run the pipeline to (re)build the data locally — see [Quick start](#quick-start).

---

## Why this exists

A WARDEN `.war` rule anchors its detection to MITRE identifiers in `meta:`
(`technique = T1059 (Execution, analogical)`, `defense = D3-EI (Execution
Isolation)`). Authoring good rules means knowing, for a given threat:

- which ATT&CK / ATLAS techniques describe the **attack**,
- which D3FEND countermeasures describe the **defense**, and
- how those map onto the **MCP / LLM / agent** surface CanaryWeave guards.

Doing that by hand against thousands of techniques across three frameworks is
slow and goes stale every MITRE release. This pipeline produces a continuously
regenerable, MCP-prioritized **catalog**, **focus list**, **coverage gap
report**, and a set of **schema-valid `.war` scaffolds** to start from.

---

## Quick start

**Prerequisites:** Python **3.11–3.13** (`mitreattack-python` requires it; the
repo's default 3.14 venv will *not* work) and network access to GitHub +
`d3fend.mitre.org`.

```powershell
cd automation/mitre

# 1) Create an isolated venv with a supported interpreter (3.12 shown).
py -3.12 -m venv .venv            # or: <path-to-python3.12> -m venv .venv

# 2) Install dependencies.
.venv\Scripts\python.exe -m pip install -r requirements.txt

# 3) Run the whole pipeline (downloads sources, then transforms).
.venv\Scripts\python.exe run_all.py
```

On success you'll have `data/normalized/`, `data/warden/`, and `OWASP/mcp10/`
populated. Re-running reuses cached downloads; add `--refresh` to re-fetch.

---

## How it works

### Data flow

```
            fetch_attack.py ─┐
            fetch_atlas.py  ─┤   normalize to one
            fetch_d3fend.py ─┤   NormalizedTechnique  ──►  data/normalized/*.json
            fetch_owasp_mcp ─┘   schema                      (+ OWASP/mcp10/)
                                                                   │
                                                  transform_warden.py
                                                                   │
                                                                   ▼
                                                          data/warden/
                                                   ├─ technique_catalog.json
                                                   ├─ mcp_focus.json
                                                   ├─ rule_scaffolds/*.war
                                                   ├─ coverage_report.md
                                                   └─ summary.json
```

`run_all.py` runs the stages in order: `attack → atlas → d3fend → owasp →
transform`.

### Stage 1 — Fetch & normalize

Each fetcher downloads a public, machine-readable source and emits a
`NormalizedTechnique` dump. Keeping one record shape lets the three frameworks be
merged and turned into `.war` anchors uniformly.

| Source | Script | Upstream | Output |
|---|---|---|---|
| **ATT&CK** (enterprise + mobile + ics) | `fetch_attack.py` | STIX 2.1 bundles via `mitreattack-python` | `data/normalized/attack_*.json` |
| **ATLAS** (adversarial ML) | `fetch_atlas.py` | official `ATLAS-latest.yaml` | `data/normalized/atlas.json` |
| **D3FEND** (countermeasures) | `fetch_d3fend.py` | JSON-LD ontology + ATT&CK-mapping API | `data/normalized/d3fend.json` |
| **OWASP MCP Top 10** | `fetch_owasp_mcp.py` | `OWASP/www-project-mcp-top-10` (2025) | `OWASP/mcp10/` |

The normalized record (`common.py → NormalizedTechnique`):

| field | meaning |
|---|---|
| `framework` | `attack` / `atlas` / `d3fend` |
| `id`, `name`, `description` | MITRE id, title, full prose |
| `tactics`, `tactic_names` | machine shortnames + human names |
| `is_subtechnique`, `parent_id` | sub-technique linkage |
| `detection`, `data_components` | ATT&CK detection strategy / data sources |
| `mitigations` | ATT&CK / ATLAS mitigations |
| `attack_mappings` | D3FEND → ATT&CK technique ids |
| `anchor`, `meta_key` | rendered `.war` anchor + whether it's a `technique` or `defense` |

D3FEND also emits an `attack_to_defense` reverse map (`ATT&CK id → [D3FEND
ids]`), which the transform uses to attach defenses to attacks.

### Stage 2 — Transform onto the MCP surface

`transform_warden.py` cross-references every ATT&CK/ATLAS technique against the
OWASP MCP Top 10 and produces four artifacts (below). The cross-reference works
in two layers:

1. **Curated seeds** — `config.OWASP_MCP_RISK_MAP` hand-maps each MCP risk to a
   few high-confidence MITRE ids. These seeds are **validated against the freshly
   downloaded data**; any id that no longer exists is reported (see
   `seed_validation_warnings`) rather than silently emitted.
2. **Heuristic widening** — additional techniques are attached when their
   tactic intersects the risk's tactics **and** their name/description matches
   the risk's keywords. ATLAS techniques are always treated as MCP-relevant
   (they *are* the adversarial-ML/LLM surface).

---

## Outputs

All under `data/warden/`.

### `technique_catalog.json`
Every ATT&CK + ATLAS technique, enriched. This is the raw material for rule
authoring. Example entry (trimmed):

```json
{
  "framework": "attack",
  "id": "T1059",
  "name": "Command and Scripting Interpreter",
  "anchor": "T1059 (Execution)",
  "severity_suggestion": "high",
  "mcp_relevant": true,
  "mcp_risks": ["MCP05"],
  "tactic_names": ["Execution"],
  "defenses": ["D3-CF (Content Filtering)", "D3-CM (Content Modification)", "..."],
  "summary": "Adversaries may abuse command and script interpreters to execute commands..."
}
```

### `mcp_focus.json`
The MCP-relevant subset, organized three ways: `by_risk` (MCP01–MCP10, each with
its techniques), `by_tactic`, and the full `atlas` list. Start here when you want
"what should we detect for *Tool Poisoning*?"

### `rule_scaffolds/*.war`
One file per OWASP risk, each containing schema-valid draft rules
(`cwfr-mcp-NNNN`). **Every scaffold is validated with the repository's own
`rule_loader` before it is written**, so a generated file is guaranteed to parse.
They are *starting points*: semantics + judge + one built-in fact, with inline
`// TODO` hints for the deterministic patterns an author still needs to add.

```
rule Mcp05CommandAndScriptingInterpreter {
    meta:
        id          = cwfr-mcp-0049
        severity    = high
        action      = block_and_audit
        technique   = T1059 (Execution, analogical)
        defense     = D3-CF (Content Filtering)
        owasp_mcp   = MCP05
        status      = scaffold
        ...
    // TODO add deterministic patterns, then tighten the condition to:
    //   (($p1 or $p2) and $capability_denied) or $intent or $judge
    semantics:
        $intent = "Content or tool activity is consistent with ..." (0.65)
    judge:
        $judge = "Assess whether public-safe facts indicate ..." (0.60)
    condition:
        ($capability_denied and $intent) or $judge
}
```

### `coverage_report.md`
Gap analysis: for each MCP risk, how many focus techniques are already anchored
by a hand-authored `rules/*.war`, and a table of the **uncovered** ones (your
backlog of new/updated rules).

### `summary.json`
Machine-readable run summary: output paths, counts, scaffold tally, and any seed
warnings.

---

## Usage reference

```powershell
# Full pipeline (cached downloads).
.venv\Scripts\python.exe run_all.py

# Re-download every source, then transform.
.venv\Scripts\python.exe run_all.py --refresh

# Only specific stages (order is normalized to the pipeline order).
.venv\Scripts\python.exe run_all.py --only attack atlas

# Everything except one stage.
.venv\Scripts\python.exe run_all.py --skip d3fend

# Re-run just the transform over existing dumps (fast; no network).
.venv\Scripts\python.exe run_all.py --transform-only

# Continue past a failing stage instead of aborting.
.venv\Scripts\python.exe run_all.py --keep-going
```

Each fetcher is also runnable on its own (e.g. `python fetch_attack.py --domain
enterprise-attack --refresh`). Run scripts **directly** (not with `-m`); they put
this folder on `sys.path` so the sibling imports resolve.

---

## From artifacts to a `.war` rule

A practical loop for closing a coverage gap:

1. Open `coverage_report.md`, pick an uncovered technique under a risk you care
   about (say `T1552` under **MCP01**).
2. Look it up in `technique_catalog.json` for its `summary`, `tactic_names`,
   suggested `severity`, and mapped `defenses`.
3. Open the matching `rule_scaffolds/mcp01_*.war` and find the draft rule for
   that technique (or copy the closest one).
4. Replace the `$intent`/`$judge` placeholder text with sharper wording, add
   deterministic `patterns:` (generic, public-safe indicators — no memorized
   payloads), and tighten the `condition:` per the inline `// TODO`.
5. Give it a real id in the appropriate namespace, move it into `rules/`, and let
   the repo's loader/tests validate it.

### `.war` anchor convention (recap)

- `technique` anchors are **ATT&CK** (`T1059`) or **ATLAS** (`AML.T0051`) ids and
  carry the **tactic** name: `T1059 (Execution, analogical)`.
- `defense` anchors are **D3FEND** (`D3-*`) ids and carry the **technique** name:
  `D3-EI (Execution Isolation)`.
- The second parenthetical item is the mapping strength: `direct` or
  `analogical`. Scaffolds use `direct` for ATLAS (first-class LLM threats) and
  `analogical` for ATT&CK (mapped onto MCP by analogy).
- A rule needs **at least one** ATT&CK/ATLAS `technique` anchor.

---

## Tuning the cross-reference

The MCP mapping lives entirely in `config.py`:

- `OWASP_MCP_RISK_MAP` — per-risk curated `attack_seed` / `atlas_seed` ids,
  `tactics`, and `keywords`. Edit this to sharpen which techniques attach to
  which risk.
- `MCP_RELEVANT_ATTACK_TACTICS` / `MCP_RELEVANCE_KEYWORDS` — the global
  ATT&CK relevance heuristic.

Severity, action, the per-risk built-in fact wired into scaffold conditions, and
the per-risk scaffold cap live near the top of `transform_warden.py`
(`_HIGH_TACTICS`, `_ACTION_FOR_SEVERITY`, `_RISK_PRIMARY_FACT`,
`_SCAFFOLDS_PER_RISK`).

---

## Notes & gotchas

- **Python version.** `mitreattack-python` (6.x) needs CPython 3.11–3.13. Create
  the `.venv` here with a supported interpreter; do not reuse the repo's 3.14
  venv.
- **MITRE versions drift.** The pipeline always pulls the latest released data
  (ATT&CK `attack-stix-data/master`, `ATLAS-latest.yaml`, live D3FEND). When a
  new version restructures things — e.g. **ATT&CK v19 split "Defense Evasion"
  into "Stealth" + "Defense Impairment"** and revoked `T1562` → `T1685` — the
  seed validator flags any curated id that disappeared so you can update
  `config.py`. Revoked/deprecated techniques are dropped automatically.
- **Network.** All sources are public. `download_*` uses retries with backoff;
  raw bundles are cached under `data/raw/` so only `--refresh` re-downloads.
- **Determinism.** Re-running the transform clears and rewrites
  `rule_scaffolds/` so output is stable.

---

## File map

| File | Responsibility |
|---|---|
| `config.py` | Source URLs, paths, MCP heuristics, `OWASP_MCP_RISK_MAP` |
| `common.py` | HTTP/IO helpers, `NormalizedTechnique`, `dump_framework` |
| `fetch_attack.py` | ATT&CK fetch + normalize (enterprise/mobile/ics) |
| `fetch_atlas.py` | ATLAS fetch + normalize |
| `fetch_d3fend.py` | D3FEND fetch + normalize + `attack_to_defense` map |
| `fetch_owasp_mcp.py` | OWASP MCP Top 10 mirror → `OWASP/mcp10/` |
| `transform_warden.py` | Cross-reference + emit WARDEN/MCP artifacts |
| `run_all.py` | Stage orchestrator (CLI) |
| `requirements.txt` | Python dependencies |
