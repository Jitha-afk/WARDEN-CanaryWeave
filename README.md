# CanaryWeave FIDES

Controlled research POC for comparing a traditional regex/signature guard, a defender-authored structured WARDEN rule layer, and an optional FIDES/IFC layer around quarantined `query_llm` calls.

## Thesis

The research claim is intentionally narrow:

Within controlled MCP security benchmarks, a human-reviewable structured rule layer can improve over ordinary regex pattern matching because it evaluates policy-relevant context, not only text substrings. Adding FIDES/IFC can then reduce remaining policy-relevant ASR by tracking whether low-integrity or restricted data caused consequential actions or crossed permitted sinks.

This mirrors the OPA/Rego philosophy: decouple policy decision-making from enforcement, feed the policy engine structured data, and let defenders author declarative, reviewable policies. Here, the structured input is a NormalizedTrace, the policy artifacts are `.war` rules, and enforcement happens inside a quarantined `query_llm` gate.

## What this POC demonstrates

- Baseline regex guard: fast but shallow pattern matching over visible text.
- Structured rule guard: YAML rules with metadata, named signals, boolean conditions, categories, and synthetic fixtures.
- FIDES/IFC layer: optional information-flow checks for trusted-action and permitted-flow policies.
- `query_llm`: deterministic preflight, quarantined model stub, postflight, optional FIDES/IFC, and structured result.
- Smoke metrics: `no_guard`, `regex_guard`, `structured_rule_guard`, and `rules_plus_fides_ifc` compared on the same synthetic cases.

## Why structured rules over regex

Regex answers: does this string contain a known pattern?

The structured rule layer answers: did a server-originated sampling result propose a tool-plan-shaped action that was not granted by the host policy? Did a canary appear outside an allowed sink? Did an untrusted field contain instruction-shaped structure? Did hidden text structure appear in an MCP-visible field?

That lets defenders write higher-quality detections against origin, surface, capability, sink, labels, and event shape rather than only matching words.

## NormalizedTrace

A NormalizedTrace is the neutral audit record all guard stacks consume. It records event order, MCP surface, origin, role, action/tool/sink labels, capability labels, canary movement, integrity/confidentiality labels, and safe structural text features.

Public/default NormalizedTrace exports do not contain raw adversarial payload text. They keep redactions, feature flags, lengths, hashes, categories, and opaque IDs so regex, rules, and FIDES can be compared apples-to-apples while raw payloads remain in controlled custody.

## FIDES/IFC framing

FIDES is treated as Flow Integrity Deterministic Enforcement System from the IFC line of work, not merely a generic LLM judge. In this POC it checks two policy shapes:

- Trusted action: consequential actions must not be caused by low-integrity or untrusted-origin data.
- Permitted flow: restricted data may only flow to permitted sinks/readers.

The quarantined LLM path is represented by `query_llm` and a deterministic model stub. Real providers are not called by default.

## Safety boundaries

- No raw exploit payloads in docs, tests, rules, reports, PR text, or chat.
- No outbound network sinks or real credentials.
- Public fixtures are synthetic and structural.
- Controlled future real-dataset evaluation should use manifests, hashes/HMAC IDs, and redacted NormalizedTrace exports.
- Provider calls are disabled in this MVP.

## Quickstart

Prerequisites on a fresh machine:

- Python 3.10+ for the core source-tree harness.
- `uv` for reproducible local execution.
- Python 3.11+ if you install the optional GitHub Copilot SDK FIDES provider.

From this directory:

```bash
uv run --with pytest --with PyYAML pytest -q
uv run python -m canaryweave_fides.cli --fixture-set smoke --output artifacts/smoke_report.json
uv run python scripts/check_markdown_fences.py
uv run python scripts/check_public_artifacts.py
```

The smoke report is written to `artifacts/smoke_report.json`.
Optional controlled datasets are not committed. If absent, ASB and
AgentDefenseBench adapters report `skipped_missing_local_path`.

```bash
export CANARYWEAVE_ASB_ROOT=/path/to/controlled/ASB
export CANARYWEAVE_AGENTDEFENSEBENCH_ROOT=/path/to/controlled/AgentDefenseBench
```

Private reviewer CSVs and raw reverse-engineering data must stay under ignored
controlled paths such as `reverse-engineering/` and must not be committed.

## Modular harness CLI

Single prompt WARDEN scan:

```bash
uv run python -m canaryweave_fides.cli warden check \
  --prompt-file /path/to/public-safe-prompt.txt \
  --origin tool_output \
  --trust untrusted \
  --output /tmp/warden_check.json
```

Single prompt WARDEN plus deterministic FIDES test double:

```bash
uv run python -m canaryweave_fides.cli judge one \
  --prompt "ordinary public-safe task request" \
  --fides-mode test_double \
  --test-verdict unsafe \
  --output /tmp/judge_one.json
```

Prompt-file scan over JSONL/CSV/TXT without echoing raw prompts into the report:

```bash
uv run python -m canaryweave_fides.cli bench scan \
  --input /path/to/prompts.jsonl \
  --input-format jsonl \
  --text-field prompt \
  --id-field id \
  --output /tmp/bench_scan.json
```

Optional FIDES provider inspection is provider-free by default:

```bash
uv run python -m canaryweave_fides.cli provider status --provider copilot_sdk --json
uv run python -m canaryweave_fides.cli provider models --provider copilot_sdk --json
uv run python -m canaryweave_fides.cli provider doctor --provider copilot_sdk --model MODEL --json
```

Live Copilot SDK FIDES calls are disabled unless both `--fides-mode copilot_sdk`
and `--provider-calls-enabled` are supplied with an explicit `--model`. Provider
prompts are built from redacted normalized facts only; public outputs omit raw
prompts, provider responses, and judge transcripts.

## Structure

```text
canaryweave-fides/
├── conf/                  # Vigil-style harness defaults, datasets, stacks
├── data/
│   ├── datasets/          # public-safe dataset adapter specs
│   ├── evals/             # smoke and multi-dataset eval configs
│   ├── prompts/           # FIDES judge contract, provider disabled by default
│   └── yara/              # regex baseline and YARA-style rule manifests
├── docs/                  # thesis, rules, datasets, judge, eval guidance
├── rules/                 # .war structured rules
├── src/canaryweave_fides/ # rule engine, FIDES/IFC, query_llm, metrics
├── tests/                 # pytest suite
├── research/              # source-grounded research notes
├── design/                # design docs, including evaluation methodology
├── scripts/               # local verification helpers
└── artifacts/             # generated smoke reports
```

WARDEN is the deterministic rule stack: regex baseline, YARA-style manifests,
current `.war` rules, and future policy engines. FIDES is the separate
judge layer for deterministic misses. Public configs and reports must remain
free of raw dataset payloads, raw prompts, and judge transcripts.
