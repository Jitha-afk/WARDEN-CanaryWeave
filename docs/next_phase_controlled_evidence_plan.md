# Next Phase: Controlled Dataset Evidence Plan

Date: 2026-06-03
Branch: `poc/canaryweave-asr`
Scope: `poc/canaryweave-fides`

Terminology:

- **WARDEN**: deterministic `.war` rule engine.
- **FIDES**: opt-in LLM-as-judge layer for WARDEN misses.

## Current state after reviewer-callout fixes

The latest implementation fixes the highest-priority peer review blockers at the harness layer:

- Public eval now executes declared `.war` rules through `RuleEngine` instead of only hard-coded WARDEN heuristics.
- WARDEN public reports now include `cwfr-*` rule IDs such as `cwfr-0001`.
- Dataset adapter configuration is loaded from eval/dataset YAML specs.
- Optional ASB / AgentDefenseBench datasets explicitly skip when local paths are missing.
- ASB adapter public IDs and content hashes use HMAC-style public identifiers instead of raw SHA-256 exports.
- Ground truth labels are separated from detector facts in `AttackCase`.
- FIDES modes are explicit: disabled, test double, and provider placeholder.
- `QueryResult.to_dict()` is public-safe; private model output requires private serialization.
- ASR denominator and incremental catch key collisions were fixed.

Validation at this point:

- `python3 scripts/check_markdown_fences.py` passed.
- `python3 scripts/check_public_artifacts.py` passed.
- `uv run --with pytest --with PyYAML pytest -q` passed with 66 tests.

## Current controlled ASB smoke result

A local ASB run was executed with:

```bash
CANARYWEAVE_ASB_ROOT=/home/sealjitha/projects/ProjectOpenHandMonk/reverse-engineering/ASB scripts/run_multi_dataset_eval.sh
```

The public-safe aggregate report shows:

- Total cases: 882
- Total iterations: 44,100
- Synthetic loaded: 4 cases
- ASB loaded: 878 cases
- AgentDefenseBench: skipped missing local path
- Provider calls: 0

Current stack metrics:

| Stack | ASR | Recall | F1 |
|---|---:|---:|---:|
| no_guard | 1.0 | 0.0 | 0.0 |
| regex_baseline | 0.9977 | 0.0023 | 0.0045 |
| yara_rules / WARDEN | 0.9966 | 0.0034 | 0.0068 |
| rules_plus_fides | 0.9966 | 0.0034 | 0.0068 |

Interpretation:

- WARDEN now runs real `*.war` rules, but current rules only cover the synthetic fixture families.
- ASB contributes 43,900 attack iterations and has essentially zero current WARDEN coverage.
- FIDES is disabled, so `rules_plus_fides` equals WARDEN.
- This is useful gap evidence, not thesis evidence yet.

## ASB coverage gap analysis

The current ASB adapter normalizes 878 ASB cases into public-safe facts, but most rule prerequisites are absent:

- All ASB cases are currently `attack` ground truth.
- All ASB cases normalize to surface `api_message`.
- All ASB cases normalize to attack category `dataset_native`.
- All ASB cases normalize to origin label `api_message`.
- All ASB cases normalize to trust label `dataset_local`.
- Requested tool/capability present: 0 / 878.
- Requested sink present: 0 / 878.
- Redacted text present: 0 / 878.
- Canary/hidden-unicode/obfuscation/exfiltration features present: 0 / 878.
- Instruction-shape feature present in only 15 / 878.

Rule prerequisites currently fail for ASB:

- `cwfr-0001` requires server-sampling origin, tool-plan shape, and denied capability.
- `cwfr-0002` requires canary/protected-flow and sink facts.
- `cwfr-0003` requires untrusted origin and instruction shape.
- `cwfr-0004` requires hidden Unicode / suspicious text structure.

Therefore, the next phase must improve dataset-to-fact mapping before adding many new rules.

## Next-phase objective

Move from “scaffold with controlled ASB gap evidence” to “thesis-supporting controlled benchmark evidence.”

The next phase is complete when we have:

1. WARDEN `*.war` rules executing over richer ASB/AgentDefenseBench redacted facts.
2. A shared attack taxonomy and explicit attack-to-rule mapping schema.
3. Benign near-miss controls for each important category.
4. Public-safe reports showing regex vs WARDEN vs WARDEN+FIDES on the same cases.
5. FIDES opt-in judge path ready to produce incremental catch metrics without exposing transcripts.

## Implementation plan

### Commit 1: Enrich ASB / dataset fact extraction

Goal: stop collapsing ASB into only `dataset_native` / `api_message`.

Tasks:

- Add a shared taxonomy mapper.
- Add ASB-safe structural extraction for these public-safe features:
  - instruction hierarchy / policy override shape;
  - tool or capability request shape;
  - requested sink / data-flow shape;
  - credential or protected-data exposure shape;
  - command/code execution intent shape;
  - file/path/resource-boundary shape;
  - network/API request shape;
  - memory/RAG/context poisoning shape;
  - approval/consent bypass shape;
  - obfuscation/encoding shape.
- Keep all extraction as booleans/enums/counts/HMAC IDs only.
- Never expose raw payload text in artifacts or docs.

Primary files:

- `src/canaryweave_fides/adapters/asb.py`
- `src/canaryweave_fides/adapters/agentdefensebench.py`
- `src/canaryweave_fides/facts.py`
- `src/canaryweave_fides/cases.py`
- `tests/test_adapters.py`
- `tests/test_facts.py`

Verification:

- ASB adapter fixture tests show feature extraction without raw payload exposure.
- ASB controlled run shows category distribution beyond `dataset_native`.
- Public artifact safety scan passes.

Commit message:

`[Turing] poc/canaryweave-fides: Enrich controlled dataset fact extraction`

### Commit 2: Add attack-to-rule mapping schema

Goal: make rule correctness reviewable.

Add mapping fields:

- `mapping_id`
- `case_ref.case_id`
- `dataset_id`
- `source_tier`
- `policy_violation_id`
- `surface`
- `origin_class`
- `impact_class`
- `evasion_class`
- `expected_behavior`
- `expected_rule_ids`
- `expected_fides_checks`
- `should_not_fire_rule_ids`
- `required_fields`
- `required_correlation`
- optional external mapping metadata
- benign near-miss controls

Primary files:

- `src/canaryweave_fides/mappings.py`
- `data/evals/*mapping*.yaml` or `data/datasets/*mapping*.yaml`
- `docs/rule_authoring.md`
- `docs/datasets.md`
- `tests/test_mappings.py`

Verification:

- Mapping parser rejects unknown rule IDs.
- Mapping parser rejects missing required telemetry definitions.
- Mapping public export excludes raw fields.
- Every existing synthetic attack has expected rule IDs.
- Every existing rule has at least one benign near-miss control.

Commit message:

`[Turing] poc/canaryweave-fides: Add attack-to-rule mapping schema`

### Commit 3: Add next WARDEN rule families

Goal: cover ASB-shaped attack facts, not just synthetic MCP sampling facts.

Priority rule families:

1. `mcp_prompt_boundary/instruction_hierarchy_violation`
2. `mcp_tool_authority/unauthorized_capability_request`
3. `mcp_tool_authority/approval_or_consent_bypass`
4. `mcp_data_flow/protected_data_unapproved_sink`
5. `mcp_data_flow/credential_or_secret_exposure`
6. `mcp_resource_boundary/path_or_uri_boundary_escape`
7. `mcp_execution/command_or_code_execution_request`
8. `mcp_network/unapproved_network_request`
9. `mcp_context_integrity/memory_or_rag_poisoning`
10. `mcp_server_supply_chain/untrusted_tool_manifest_or_schema`

Each rule must include:

- rich metadata;
- taxonomy block;
- required telemetry;
- false-positive guidance;
- at least one positive synthetic structural fixture;
- at least two benign near-miss negative fixtures;
- optional external mapping metadata with caveat notes.

Primary files:

- `rules/**/*.war`
- `tests/test_rule_schema.py`
- `tests/test_rule_engine.py`
- `tests/test_warden_rule_style.py`
- `docs/rule_authoring.md`

Verification:

- WARDEN hits expected rules on synthetic positives.
- Benign near-misses do not fire high/critical rules.
- Public docs/rules remain payload-free.
- Public reports show improved ASB coverage.

Commit message:

`[Turing] poc/canaryweave-fides: Add ASB-oriented WARDEN rule families`

### Commit 4: Add evidence-grade reporting

Goal: make reports useful for thesis evidence.

Add metrics:

- ASR and ASR reduction vs no guard and regex.
- Deterministic catch rate.
- FIDES incremental catch rate.
- Remaining miss rate.
- Benign refusal / overblock rate.
- Safe pass-through rate.
- Rule coverage by dataset/category/surface.
- Rule reuse across datasets.
- Rules with no coverage.
- Missing prerequisite counts by dataset/category.
- Disagreement matrix for regex vs WARDEN vs WARDEN+FIDES.
- FIDES call count, latency, and cost aggregates.

Primary files:

- `src/canaryweave_fides/reporting.py`
- `src/canaryweave_fides/metrics.py`
- `src/canaryweave_fides/runner.py`
- `tests/test_reporting.py`
- `tests/test_metrics_cli.py`

Verification:

- Public report includes denominators for every rate.
- Incremental catches use internal case IDs for computation but do not expose case-level details unless explicitly enabled for synthetic/private runs.
- Artifact safety scan passes.

Commit message:

`[Turing] poc/canaryweave-fides: Add evidence-grade reporting`

### Commit 5: FIDES opt-in judge boundary

Goal: make FIDES a real, explicit judge layer without default provider calls.

Modes:

- `disabled`: default, no provider calls.
- `test_double`: deterministic fixture judge for CI.
- `provider`: requires explicit opt-in env/flag and private transcript policy.

Requirements:

- FIDES receives redacted policy facts only.
- Strict JSON verdict parser:
  - verdict: safe / unsafe / uncertain
  - confidence
  - reason_codes
  - recommended_decision
- Malformed provider output fails closed to quarantine/block depending config.
- Public report never includes transcripts.
- Private transcript paths are local/ignored only.

Primary files:

- `src/canaryweave_fides/gate.py`
- `src/canaryweave_fides/fides_judge.py` if split out
- `src/canaryweave_fides/cli.py`
- `data/prompts/fides_judge.yaml`
- `docs/fides_judge.md`
- `tests/test_gate.py`
- `tests/test_query_llm_gate.py`

Verification:

- WARDEN block short-circuits FIDES.
- WARDEN miss invokes test-double FIDES.
- Unsafe verdict blocks.
- Uncertain verdict quarantines.
- Provider mode refuses to run unless explicitly enabled.
- Public report omits transcript/output text.

Commit message:

`[Turing] poc/canaryweave-fides: Add explicit FIDES judge boundary`

### Commit 6: Controlled evidence packet

Goal: generate first public-safe benchmark packet.

Runs:

```bash
uv run --with pytest --with PyYAML pytest -q
PYTHONPATH=src python3 -m canaryweave_fides.cli eval --config data/evals/smoke.yaml --iterations 50 --public-report --output artifacts/evals/public_gate_eval_report_50.json
CANARYWEAVE_ASB_ROOT=/home/sealjitha/projects/ProjectOpenHandMonk/reverse-engineering/ASB PYTHONPATH=src python3 -m canaryweave_fides.cli eval --config data/evals/multi_dataset_gate.yaml --dataset asb --iterations 50 --public-report --output artifacts/evals/asb_public_controlled.json
python3 scripts/check_markdown_fences.py
python3 scripts/check_public_artifacts.py
```

If AgentDefenseBench path is provided later:

```bash
CANARYWEAVE_AGENTDEFENSEBENCH_ROOT=/path/to/agentdefensebench PYTHONPATH=src python3 -m canaryweave_fides.cli eval --config data/evals/multi_dataset_gate.yaml --dataset agentdefensebench --iterations 50 --public-report --output artifacts/evals/agentdefensebench_public_controlled.json
```

Public packet should include:

- synthetic CI report;
- ASB controlled public report;
- optional AgentDefenseBench public report if path exists;
- docs explaining limitations;
- no raw payloads;
- no transcripts;
- no private mappings.

Commit message:

`[Hermes] poc/canaryweave-fides: Publish public-safe controlled evidence packet`

## Current limitations to keep in final docs

Until the next phase is complete, say:

- Current ASB results are coverage-gap diagnostics.
- WARDEN executes real `*.war` rules, but the starter rule families are still synthetic/MCP-sampling oriented.
- FIDES is explicit but disabled by default; provider-backed judge results require a later opt-in run.
- AgentDefenseBench is supported as an optional adapter but local path is not currently configured.
- No raw ASB or private dataset payloads are committed or exposed.
