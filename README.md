# CanaryWeave FIDES

Controlled research POC for comparing a traditional regex guard, a defender-authored WARDEN rule layer, and an optional FIDES/IFC layer around quarantined `query_llm` calls.

## Documentation

- **[Documentation home](docs/README.md)** — full table of contents.
- **[Architecture](docs/architecture/README.md)** — [HLD](docs/architecture/hld.md), [LLD](docs/architecture/lld.md), [DFD](docs/architecture/dfd.md), and the [known post-refactor gaps](docs/architecture/README.md#known-gaps).
- **[`CONTEXT.md`](CONTEXT.md)** — the canonical glossary.
- **[Developer guide](docs/developer.md)** · **[Rule authoring](docs/rule_authoring.md)** · **[Running evaluations](docs/running_evals.md)**

## Thesis

The research claim is intentionally narrow:

Within controlled MCP security benchmarks, a human-reviewable structured rule layer can improve over ordinary regex pattern matching because it evaluates policy-relevant context, not only text substrings. Adding FIDES/IFC can then reduce remaining policy-relevant ASR by tracking whether low-integrity or restricted data caused consequential actions or crossed permitted sinks.

This mirrors the OPA/Rego philosophy: decouple policy decision-making from enforcement, feed the policy engine a flat evaluation record, and let defenders author declarative, reviewable policies. Here, the record is raw `text` plus framework-computed facts, the policy artifacts are `.war` rules, and enforcement happens inside a quarantined `query_llm` gate.

## What this POC demonstrates

- Baseline regex guard: fast but shallow pattern matching over visible text.
- WARDEN structured rules: YARA-style `.war` rulesets with `rule Name { ... }` blocks, `meta` technique anchors, named `patterns:`, `semantics:`, and `judge:` layers, plus boolean conditions over raw text and facts.
- One rule shape: a patterns-only rule is a brittle signature; a rule that reasons over facts, semantics, or judge checks is a structured policy.
- Six framework-owned facts: `$from_untrusted_origin`, `$capability_denied`, `$canary_outside_sink`, `$tool_call_shape`, `$hidden_unicode`, and `$instruction_shape`.
- FIDES/IFC layer: optional information-flow checks for trusted-action and permitted-flow policies, including per-rule judge questions.
- `query_llm`: deterministic preflight, quarantined model stub, postflight, optional FIDES/IFC, and structured result.
- Smoke metrics: the same `.cases` corpus run with `warden test` across `no_guard`, `regex_baseline`, `yara_rules`, and `rules_plus_fides`.

## Why structured rules over regex

Regex answers: does this string contain a known pattern?

The structured rule layer answers: did content from an untrusted origin propose a tool-plan-shaped action that was not granted by the host policy? Did a canary appear outside an allowed sink? Did hidden text structure appear in an MCP-visible field? Does the raw text express an intent family a plain regex is likely to miss?

Defenders write these detections as `.war` rulesets: one or more `rule <Name> {` blocks with `meta:`, `patterns:`, `semantics:`, `judge:`, and `condition:` sections. Conditions compose declared `$terms` and built-in facts with boolean operators. Every declared `$term` must be used in the condition, and every non-built-in condition reference must be declared, so rules stay reviewable and free of dead evidence.

That lets defenders write higher-quality detections against origin, capability, sink, canary flow, message shape, semantic intent, and judge checks rather than only matching words.

## NormalizedTrace

A NormalizedTrace is the framework-internal audit record that populates the flat evaluation record. It carries event order, MCP surface, origin, role, action/tool/sink labels, capability labels, canary movement, integrity/confidentiality labels, and structural text features.

Rules, cases, exports, and reports operate on raw prompt/tool text plus normalized facts so reviewers can see exactly what led to an outcome. Synthetic public corpora should still use generic indicators and benign examples rather than real credentials, live sinks, or benchmark string memorisation.

## FIDES/IFC framing

FIDES is treated as Flow Integrity Deterministic Enforcement System from the IFC line of work, not merely a generic LLM judge. In this POC it checks two policy shapes:

- Trusted action: consequential actions must not be caused by low-integrity or untrusted-origin data.
- Permitted flow: restricted data may only flow to permitted sinks/readers.

The quarantined LLM path is represented by `query_llm` and a deterministic model stub. Real providers are not called by default.

## Safety boundaries

- Public docs, tests, rules, and reports use synthetic prompt/tool text.
- No outbound network sinks or real credentials.
- Public fixtures are synthetic and structural.
- Controlled future real-dataset evaluation should use manifests, hashes/HMAC IDs, and normalized fact exports appropriate for review.
- Provider calls are disabled in this MVP.

## Quickstart

Prerequisites on a fresh machine:

- Python 3.10+ for the core source-tree harness.
- `uv` for reproducible local execution.
- Python 3.11+ if you install the optional GitHub Copilot SDK FIDES provider.

From this directory:

```bash
uv run --with pytest pytest -q
uv run python -m canaryweave_fides.cli --fixture-set smoke --output artifacts/smoke_report.json
uv run python -m canaryweave_fides.cli warden test --input data/cases/smoke.cases
uv run python scripts/check_markdown_fences.py
uv run python scripts/check_public_artifacts.py
```

The smoke report is written to `artifacts/smoke_report.json`. `warden test` renders per-case pass/fail rows and per-stack attack-success-rate / false-positive-rate metrics from the `.cases` corpus.
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
  --output artifacts/warden_check.json
```

Single prompt WARDEN plus deterministic FIDES test double:

```bash
uv run python -m canaryweave_fides.cli judge one \
  --prompt "ordinary public-safe task request" \
  --fides-mode test_double \
  --test-verdict unsafe \
  --output artifacts/judge_one.json
```

Prompt-file scan over JSONL/CSV/TXT:

```bash
uv run python -m canaryweave_fides.cli bench scan \
  --input /path/to/prompts.jsonl \
  --input-format jsonl \
  --text-field prompt \
  --id-field id \
  --output artifacts/bench_scan.json
```

Optional FIDES provider inspection is provider-free by default:

```bash
uv run python -m canaryweave_fides.cli provider status --provider copilot_sdk --json
uv run python -m canaryweave_fides.cli provider models --provider copilot_sdk --json
uv run python -m canaryweave_fides.cli provider doctor --provider copilot_sdk --model MODEL --json
```

Live Copilot SDK FIDES calls are disabled unless both `--fides-mode copilot_sdk`
and `--provider-calls-enabled` are supplied with an explicit `--model`. Provider
judge prompts are built from the raw text, normalized facts, and the rule's own
`judge:` question; public outputs should be treated as synthetic benchmark
artifacts.

## Structure

```text
canaryweave-fides/
├── conf/                  # Harness defaults, datasets, stacks
├── data/
│   ├── cases/             # .cases corpora for stack-level evals
│   ├── datasets/          # public-safe dataset adapter specs
│   ├── evals/             # smoke and multi-dataset eval configs
│   ├── prompts/           # FIDES judge contract, provider disabled by default
│   └── yara/              # regex baseline and YARA-style rule manifests
├── docs/                  # thesis, rules, datasets, judge, eval guidance
├── rules/                 # .war YARA-style rulesets
├── src/canaryweave_fides/ # rule engine, FIDES/IFC, query_llm, metrics
├── tests/                 # pytest suite
├── research/              # source-grounded research notes
├── design/                # design docs, including evaluation methodology
├── scripts/               # local verification helpers
└── artifacts/             # generated smoke reports
```

WARDEN is the deterministic rule stack: regex baseline, YARA-style manifests,
flat `.war` rules, and future policy engines. FIDES is the separate IFC and judge
layer; its per-rule questions come from `judge:` entries. The `.cases` corpus and
`warden test` command are the stack-level evaluation path.
