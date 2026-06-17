# Peer Review Report: CanaryWeave FIDES / WARDEN Harness

Date: 2026-06-03
Status: updated after WARDEN rule-file execution, ASB evidence closure, private reviewer CSV support, and `.war` rule migration
Branch: `poc/canaryweave-asr`
Scope: `poc/canaryweave-fides`

## Terminology

- **WARDEN**: deterministic YARA/OPA/Vigil-style rule engine that executes defender-authored `.war` YAML policy files and reports stable public `cwfr-*` rule IDs.
- **FIDES**: separate LLM-as-judge boundary for WARDEN misses. Current checked-in evidence uses disabled or test-double modes only; no provider-backed FIDES claim is made.

## Current reviewer verdict

Verdict: **engineering milestone acceptable; not yet final detection-effectiveness evidence**.

The earlier review blockers around hard-coded WARDEN-like checks, synthetic-only public evaluation, public/private serializer separation, HMAC-based public identifiers, and expected-rule evidence have been addressed in the current source tree. The harness now:

1. Executes declared `.war` WARDEN rule files through `RuleEngine(load_rules(...))`.
2. Reports public `cwfr-*` rule IDs from loaded rules.
3. Loads synthetic fixtures and optional controlled-local ASB/AgentDefenseBench adapters through config.
4. Produces public-safe aggregate reports without raw source material, model output, or judge transcripts.
5. Produces private reviewer CSVs for controlled human signature-improvement loops under git-ignored custody paths.
6. Reports expected-rule evidence, safe-fact completeness, rule coverage, disagreement matrices, and false-positive diagnostics.

The current evidence supports a bounded claim: WARDEN is connected end-to-end, executes real rule files, and improves over the regex baseline on the current synthetic and controlled-local ASB artifacts while preserving zero measured ASB benign false positives in the current small ASB benign set.

It does **not** yet support a broad claim of production readiness, comprehensive dataset coverage, real-provider FIDES effectiveness, or statistically stable ASB/AgentDefenseBench robustness.

## Current artifacts reviewed

| Artifact | Scope | Current interpretation |
|---|---|---|
| `artifacts/evals/public_gate_eval_report_50.json` | Public synthetic CI smoke | Confirms rule execution, reporting, and public safety on hand-authored fixtures. |
| `artifacts/evals/fides_test_double_public.json` | Public FIDES test-double smoke | Confirms WARDEN-miss / FIDES-catch accounting with zero provider calls. |
| `artifacts/evals/asb_controlled_public_report_1.json` | Controlled-local ASB aggregate | Shows WARDEN improvement over regex and current ASB gap profile without publishing raw ASB source. |
| `reverse-engineering/review/asb_gate_review.csv` | Private controlled reviewer CSV | Contains raw input/output and labels for human signature review; intentionally git-ignored and not public. |

## Current code review findings

### Resolved or substantially improved

1. **Authored rule-file execution**
   - Public gate evaluation now executes real WARDEN rule files through `RuleEngine`.
   - Tests verify that an empty `RuleEngine` changes output, preventing a silent fallback to hard-coded heuristics.

2. **Rule extension migration**
   - WARDEN rule files now use `.war` extension.
   - The loader discovers `*.war` files.
   - Rule IDs remain stable `cwfr-*` identifiers for public reporting and expected-rule evidence.

3. **Config-driven adapters**
   - CLI/config paths instantiate dataset adapters from eval specs.
   - Optional controlled datasets report explicit skipped status when local roots are absent.

4. **Public/private boundary**
   - Public reports omit case-level rows, raw source, model output, judge transcripts, private reviewer CSV rows, `raw_ref`, and `private_data`.
   - Private reviewer CSV output is explicitly opt-in and guarded from public roots.

5. **Evidence-grade reporting**
   - Reports include rule coverage, expected-rule evidence, missing prerequisites, false-positive diagnostics, FIDES call/catch accounting, and safe-fact completeness.

### Remaining engineering risks

1. **Boolean condition evaluator**
   - `RuleEngine` still uses a constrained boolean expression evaluation path. It is guarded, but a small explicit AST/boolean parser would be cleaner before broader use.

2. **Packaging / distribution**
   - The source-tree runner loads rules relative to the repository layout. If this project is distributed as a wheel, verify `.war` rule files are included and discoverable.

3. **FIDES provider path**
   - Provider-backed FIDES is still intentionally not implemented in public artifacts. This is safe, but no empirical LLM-judge claim should be made yet.

## Current thesis / accuracy findings

### Defensible claims

- A public-safe WARDEN/FIDES evaluation harness exists.
- WARDEN executes declared `.war` rule files and reports stable `cwfr-*` rule IDs.
- Synthetic CI artifacts show WARDEN improves over regex on hand-authored structural fixtures.
- Controlled-local ASB artifacts show WARDEN improves over regex on mapped ASB structural facts.
- Private reviewer CSVs enable human inspection of raw inputs/outputs under controlled custody.
- FIDES test-double artifacts validate accounting for WARDEN-miss/FIDES-catch behavior with zero provider calls.

### Claims not yet supported

- Real-provider FIDES improves security outcomes.
- WARDEN comprehensively covers ASB, AgentDefenseBench, or broader agent-security distributions.
- The current benign refusal rate is statistically stable; ASB has only 20 benign cases in the current artifact.
- Gate-level allow/block decisions equal real downstream attack success in a full agent runtime.

## Current security detection findings

### Strengths

1. **Rule-to-case evidence is explicit**
   - Expected-rule metadata and required fields are tracked as ground truth/reporting metadata, not detector facts.

2. **Benign disruption is now measurable**
   - False-positive diagnostics identify benign blocks by stack, dataset, category, and rule ID.

3. **Private review loop exists**
   - The reviewer CSV contains raw input/output and labels for controlled human signature improvement without leaking raw material into public artifacts.

4. **New WARDEN rules are structural**
   - New rules for protected context extraction, destructive action intent, and deceptive social-engineering tasking use safe feature flags and high-level ATLAS-style mappings rather than copied payload strings.

### Remaining detection gaps

1. **High ASB remaining ASR**
   - The latest ASB artifact improves over regex but still allows many attack-labeled cases.

2. **Limited benign denominator**
   - The current ASB benign set is small. More benign near-miss controls are needed before making stability claims.

3. **Event causality is still simplified**
   - `NormalizedFacts` is a compact pre-context fact envelope. Stronger causal claims need same-event/window/source-to-action correlation semantics.

4. **AgentDefenseBench needs a current artifact**
   - No current checked-in artifact should be used for AgentDefenseBench claims until regenerated and reviewed.

## Recommended next implementation order

1. Use `reverse-engineering/review/asb_gate_review.csv` to inspect ASB false negatives and identify additional safe structural signatures.
2. Add tests first for each new signature and each benign near-miss.
3. Preserve current zero measured ASB benign false positives while improving recall.
4. Add larger benign control sets for major WARDEN rule families.
5. Regenerate public ASB artifact and private reviewer CSV after every rule milestone.
6. Regenerate a separate AgentDefenseBench public-safe aggregate artifact before any current cross-dataset claim.
7. Only then plan transcript-private provider-backed FIDES experiments.

## Bottom line

The harness is now a credible engineering base for continuing WARDEN/FIDES research. The current work should be described as a controlled, leakage-safe evaluation harness with measurable ASB progress and remaining coverage gaps — not as final proof of comprehensive agent-security effectiveness.
