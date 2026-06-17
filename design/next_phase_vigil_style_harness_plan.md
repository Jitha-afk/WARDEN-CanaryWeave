# Next Phase Plan: Vigil-Style Multi-Dataset Gate Harness

> **For Hermes:** Do not execute this plan until the user approves. After approval, use subagent-driven-development. Auto-commit after each major implementation milestone and run verification before every commit.

**Goal:** Prove that defender-maintainable YARA-style deterministic rules plus FIDES LLM-as-judge improve agent security posture across multiple attack datasets before unsafe content reaches an agent context window.

**Core thesis:** Security defenders should focus on writing high-quality, portable rule samples and policy detections. The engine should stay stable, simple, and transferable to an OPA/Rego-like policy engine model: structured facts in, declarative policy decision out, enforcement separate.

**Architecture:** Build a simple Vigil-inspired toolkit layout around the existing `canaryweave_fides` package: `data/` for rule/eval artifacts and dataset specs, `docs/` for user-facing guidance, `scripts/` for smoke/eval commands, and `src/` for the reusable engine. Use adapters for ASB, AgentDefenseBench, and synthetic fixtures. Run a pre-context gate loop where deterministic rules fire first and FIDES judges only deterministic misses.

**Tech Stack:** Python 3.11+, pytest, PyYAML, stdlib dataclasses, existing `.war` rules, optional MCP simulation later, provider calls disabled by default.

---

## 1. What changed from the previous plan

The previous ASB plan was too dataset-centric and too methodology-heavy. The new direction is simpler and closer to the research thesis:

1. We are not building an ASB-only evaluator.
2. We are building a reusable multi-dataset gate harness.
3. ASB is one dataset source; AgentDefenseBench and future folders are peer sources.
4. The main proof point is the decision ladder:
   - no guard;
   - regex baseline;
   - YARA-style deterministic rules;
   - YARA-style rules plus FIDES LLM-as-judge.
5. The harness evaluates attacks before they reach the target model context window.
6. A full sandboxed Hermes/MCP runtime is optional. The first proof can be a deterministic pre-context gate loop over normalized attack cases.
7. Maintainability and transferability are first-class metrics: rules should express stable policy shapes, not dataset-specific payload strings.

## 2. Vigil-inspired target structure

Current POC root: `poc/canaryweave-fides/`

Target shape:

```text
poc/canaryweave-fides/
├── conf/
│   ├── default.yaml
│   ├── datasets.yaml
│   └── stacks.yaml
├── data/
│   ├── datasets/
│   │   ├── README.md
│   │   ├── asb.yaml
│   │   ├── agentdefensebench.yaml
│   │   └── synthetic.yaml
│   ├── evals/
│   │   ├── smoke.yaml
│   │   └── multi_dataset_gate.yaml
│   ├── prompts/
│   │   └── fides_judge.yaml
│   └── yara/
│       ├── baseline_regex.yaml
│       └── canaryweave_rules.yaml
├── docs/
│   ├── thesis.md
│   ├── rule_authoring.md
│   ├── datasets.md
│   ├── fides_judge.md
│   └── running_evals.md
├── scripts/
│   ├── run_smoke.sh
│   ├── run_multi_dataset_eval.sh
│   └── check_public_artifacts.py
├── rules/
│   └── existing .war rules
├── src/canaryweave_fides/
│   └── reusable engine implementation
├── tests/
└── artifacts/
    └── generated reports, public-safe by default
```

This mirrors Vigil’s good parts:

- implementation in the package;
- scanner/rule data as first-class artifacts;
- config-driven scanner/eval selection;
- docs by capability;
- scripts for smoke runs;
- API/CLI kept thin over the same core engine.

## 3. Core concepts

### 3.1 AttackCase

Dataset-neutral envelope produced by adapters.

Fields:

- `case_id`: opaque stable ID.
- `dataset_id`: `synthetic`, `asb`, `agentdefensebench`, or future source.
- `split`: `ci`, `dev`, `test`, `holdout`, or dataset-native split.
- `case_kind`: `attack` or `benign`.
- `attack_category`: shared taxonomy label.
- `surface`: `prompt`, `tool_result`, `mcp_resource`, `mcp_tool`, `api_message`, `server_sampling`, etc.
- `raw_ref`: private pointer to raw local data; never exported publicly.
- `safe_features`: lengths, hashes/HMACs, structural booleans, origin labels, role/source labels, canary flags.
- `policy_context`: allowed tools, allowed sinks, trusted origins, protected labels, canary policy.
- `expected_behavior`: expected allow/block/quarantine or attack-success criterion.

### 3.2 NormalizedFacts

OPA-like decision input for regex, YARA-style rules, and FIDES.

It should include only policy-relevant structured facts:

- origin/trust labels;
- surface and role labels;
- instruction-shaped/tool-plan-shaped/obfuscated/canary-bearing feature flags;
- requested or implied tool/action/sink;
- capability grants/denials;
- protected-data flow indicators;
- redacted text features only where needed for regex baseline.

### 3.3 GateDecision

Single result schema for every defense stack:

- `stack`: `no_guard`, `regex_baseline`, `yara_rules`, `rules_plus_fides`.
- `decision`: `allow`, `quarantine`, or `block`.
- `blocked_by`: `regex`, `yara_rule`, `fides_judge`, or `none`.
- `rule_ids`: deterministic rule IDs that fired.
- `fides_verdict`: `safe`, `unsafe`, `uncertain`, or `not_called`.
- `reason_codes`: short non-sensitive codes.
- `latency_ms`.
- `provider_calls`: normally 0 unless judge mode is explicitly enabled.

## 4. Defense ladder

Run every case through the same ladder.

### 4.1 `no_guard`

Baseline. Nothing blocks before context.

Purpose:
- establish vulnerability baseline;
- compare ASR reduction.

### 4.2 `regex_baseline`

Traditional regex/string/pattern matching.

Purpose:
- show what conventional pattern matching catches;
- establish baseline false negatives.

### 4.3 `yara_rules`

Main deterministic contribution.

Rules are defender-maintainable and YARA-style:

- metadata;
- strings/signals;
- structured facts;
- boolean conditions;
- severity and tags;
- safe fixtures;
- expected action.

The current `.war` format can evolve toward an OPA-transferable representation. The point is that defenders write rules, not engine code.

### 4.4 `rules_plus_fides`

FIDES LLM-as-judge runs only for deterministic misses.

Flow:

```text
AttackCase
  -> NormalizedFacts
  -> regex baseline
  -> YARA-style deterministic rules
  -> if allowed, FIDES judge over redacted policy view
  -> final allow/quarantine/block
```

FIDES is the LLM judge layer for this research. It should receive only redacted policy facts, not raw payload dumps. It produces structured verdicts and reason codes.

## 5. Simple evaluation loop

First implementation should avoid unnecessary complexity.

For each enabled dataset:

1. Adapter loads cases from configured local path.
2. Adapter emits `AttackCase` objects.
3. Runner samples or selects configured cases.
4. Runner repeats each case 50 times with fixed seeds or deterministic perturbations.
5. For each iteration:
   - build `NormalizedFacts`;
   - run `regex_baseline`;
   - run `yara_rules`;
   - call FIDES only if deterministic rules allow;
   - record final decision and metrics.
6. Optional simulator runs only for cases that pass the pre-context gate.
7. Public-safe aggregate report is generated.

A full attacker MCP server is optional, not required for the first proof. The simpler first proof is a pre-context gate benchmark. If needed later, add an attacker MCP server that emits tool/resource/sampling messages from AttackCase records into the same gate.

## 6. Dataset strategy

### 6.1 Synthetic

Always available. CI-safe. No raw attack data.

Purpose:
- rule regression tests;
- smoke report;
- docs examples.

### 6.2 ASB

Official target:
- `agiresearch/ASB`.

Use as one real attack dataset source. Raw payload-bearing fields remain local/private.

### 6.3 AgentDefenseBench

Treat as a peer source, not a second-class add-on.

Current local search did not find the folder under `/home/sealjitha`; ask user for the path or support configuration via `conf/datasets.yaml`.

Adapter should auto-skip if absent and report:

```text
agentdefensebench: skipped_missing_local_path
```

### 6.4 Future datasets

The adapter interface should make it easy to add:

- MCPGuard-like corpora;
- MCPSecBench-like corpora;
- OASB or other artifact scanners;
- internal local benchmark folders.

## 7. Metrics

Keep metrics focused on proving the thesis.

Primary:

- ASR for `no_guard`, `regex_baseline`, `yara_rules`, `rules_plus_fides`.
- ASR reduction vs no guard and vs regex baseline.
- Deterministic catch rate.
- FIDES incremental catch rate.
- Remaining miss rate.
- Benign refusal/overblock rate.
- Safe pass-through rate.

Maintainability/transferability:

- Rule count.
- Rule coverage by category and dataset.
- Cross-dataset rule reuse rate.
- Dataset-specific rule count vs generic policy-shape rule count.
- Regex miss / YARA catch count.
- YARA miss / FIDES catch count.

Operational:

- FIDES judge call count.
- FIDES latency and cost if provider mode is enabled.
- Cost per incremental catch.
- Public artifact safety status.

## 8. Raw payload and judge-output safety

The harness can evaluate real attack data, but public/default artifacts must stay clean.

Rules:

- Do not commit raw dataset payloads.
- Do not print raw payloads in CLI default output.
- Do not include raw payloads in docs, tests, PRs, chat, or reports.
- Keep raw-to-case mapping private.
- Keep real FIDES judge transcripts private by default.
- Public reports contain aggregate metrics, opaque IDs, rule IDs, reason codes, and synthetic examples only.

## 9. Implementation milestones

### Milestone 1: Reorganize into Vigil-style structure

Files:

- Create `conf/default.yaml`.
- Create `conf/datasets.yaml`.
- Create `conf/stacks.yaml`.
- Create `data/datasets/README.md`.
- Create `data/datasets/synthetic.yaml`.
- Create `data/datasets/asb.yaml`.
- Create `data/datasets/agentdefensebench.yaml`.
- Create `data/evals/smoke.yaml`.
- Create `data/evals/multi_dataset_gate.yaml`.
- Create `data/prompts/fides_judge.yaml`.
- Create `docs/thesis.md`.
- Create `docs/rule_authoring.md`.
- Create `docs/running_evals.md`.
- Create `scripts/run_smoke.sh`.
- Create `scripts/check_public_artifacts.py`.

Acceptance:

- Existing tests still pass.
- Existing CLI smoke still works.
- Markdown fence check passes.
- Commit after verification.

### Milestone 2: Core schemas

Files:

- Create `src/canaryweave_fides/cases.py`.
- Create `src/canaryweave_fides/facts.py`.
- Create `src/canaryweave_fides/decisions.py`.
- Add tests:
  - `tests/test_cases.py`.
  - `tests/test_facts.py`.
  - `tests/test_decisions.py`.

Acceptance:

- `AttackCase`, `NormalizedFacts`, and `GateDecision` serialize to public-safe JSON.
- Raw fields are excluded from public export.
- Commit after verification.

### Milestone 3: Dataset adapter registry

Files:

- Create `src/canaryweave_fides/adapters/base.py`.
- Create `src/canaryweave_fides/adapters/synthetic.py`.
- Create `src/canaryweave_fides/adapters/asb.py`.
- Create `src/canaryweave_fides/adapters/agentdefensebench.py`.
- Add adapter tests.

Acceptance:

- Synthetic adapter returns CI-safe cases.
- ASB adapter can inspect a configured local path but exports only safe features.
- AgentDefenseBench adapter auto-skips if path missing.
- No raw payload output in tests or CLI.
- Commit after verification.

### Milestone 4: Gate runner

Files:

- Create `src/canaryweave_fides/gate.py`.
- Create `src/canaryweave_fides/runner.py`.
- Extend CLI with `eval` subcommand.
- Add `tests/test_gate.py` and `tests/test_runner.py`.

Acceptance:

- Runner executes `no_guard`, `regex_baseline`, `yara_rules`, and `rules_plus_fides`.
- FIDES is called only for deterministic misses.
- Runner supports `--iterations 50`.
- Provider mode is disabled by default.
- Commit after verification.

### Milestone 5: Multi-dataset reports

Files:

- Create `src/canaryweave_fides/reporting.py`.
- Add `tests/test_reporting.py`.
- Generate public-safe JSON report under `artifacts/evals/`.

Acceptance:

- Report includes ASR, ASR reduction, deterministic catch, FIDES incremental catch, benign overblock, rule coverage, and cross-dataset reuse.
- Report excludes raw payloads and judge transcripts.
- Public artifact scanner passes.
- Commit after verification.

### Milestone 6: Optional attacker MCP/API simulator

Only after the gate runner works.

Files:

- Create `src/canaryweave_fides/simulators/api.py`.
- Create `src/canaryweave_fides/simulators/mcp.py`.
- Add tests and docs.

Acceptance:

- Simulator consumes AttackCase records.
- Simulator does not execute real attacks, real network calls, or real filesystem side effects.
- Gate still runs before any simulated context injection.
- Commit after verification.

## 10. Approval questions

Before implementation, confirm:

1. Where is the local AgentDefenseBench folder?
2. Should I clone official ASB into a controlled path, or do you already have a local ASB copy?
3. Should FIDES initially use a deterministic stub judge, or should we wire an opt-in real LLM judge after the gate runner is working?
4. Do you want the optional attacker MCP simulator in this phase, or only after the pre-context gate benchmark is producing results?

Recommended default:

- Implement Milestones 1 through 5 first.
- Use synthetic + ASB first, AgentDefenseBench as optional if the path is provided.
- Keep FIDES stubbed until the runner and reports are stable.
- Add attacker MCP simulator only after we have baseline multi-dataset metrics.
