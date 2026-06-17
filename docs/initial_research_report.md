# Initial Research Report Draft: Controlled Multi-Dataset Evidence for CanaryWeave FIDES

Date: 2026-06-03
Status: initial academic-style draft outline and results narrative
Scope: `poc/canaryweave-fides`
Primary public artifacts: `artifacts/evals/public_gate_eval_report_50.json`, `artifacts/evals/fides_test_double_public.json`, and controlled-local `artifacts/evals/asb_controlled_public_report_1.json`

## Safety and claim boundary

This draft is intentionally public-safe. It does not include raw dataset examples, raw attack text, raw model outputs, judge transcripts, raw-to-case mappings, external links, or live sink details. All dataset discussion is limited to opaque case counts, adapter status, aggregate metrics, rule identifiers, and category-level summaries already present in the public-safe report.

The current evidence supports a narrow claim: within the present controlled harness, structured WARDEN rules can be evaluated against a common normalized case envelope across synthetic fixtures and local private dataset adapters, and the current WARDEN rule set improves over the simple regex baseline on the available mixed run. It does not yet support a broad claim of general agent security, comprehensive ASB or AgentDefenseBench coverage, production readiness, or real-provider FIDES effectiveness.

## Working title

Controlled Evaluation of Structured Policy Rules and Information-Flow Judging for Pre-Context Agent Defense

## Draft paper outline

### Abstract

Summarize the problem of evaluating pre-context defenses for agent and MCP-style inputs without publishing unsafe source material. State the proposed harness: dataset adapters normalize synthetic fixtures and controlled local datasets into public-safe facts; a regex baseline, the WARDEN structured rule layer, and WARDEN plus FIDES are compared on the same cases. Report the current mixed-run result conservatively: WARDEN improves aggregate ASR over regex in the available public report, while FIDES adds no measured incremental catches in the current provider-disabled run. Emphasize limitations: sparse benign controls, incomplete ASB coverage, local private dataset dependence, and no real-provider FIDES evaluation.

### 1. Introduction

Motivate the need for repeatable, leakage-safe security evaluation for agent inputs before those inputs enter an agent context or influence tool use. Explain why raw adversarial examples and provider transcripts should not appear in public artifacts. Introduce the central research question:

Can a structured, defender-reviewable policy layer reduce attack success relative to a regex baseline on redacted multi-dataset facts, and can a later FIDES layer add incremental coverage for policy-relevant misses without exposing raw source material?

### 2. Threat model and public-safety model

Define the evaluated boundary as a pre-context gate over untrusted or dataset-local content. The harness assumes that adapters may inspect local source material under controlled custody, but public artifacts expose only structural facts, labels, opaque identifiers, rule IDs, and aggregate metrics. The current public report excludes case-level rows, source material, judge transcripts, and model outputs.

### 3. System overview

Describe the current harness components:

- Dataset adapters: synthetic fixtures are always available; ASB and AgentDefenseBench are optional controlled local datasets that require local roots and export only redacted facts.
- Normalized case envelope: each case carries dataset ID, split, attack or benign label, surface, category, safe features, policy context, and expected behavior.
- Regex baseline: a simple deterministic baseline over safe visible markers and redacted structural indicators.
- WARDEN: deterministic `.war` structured rules over normalized facts and policy context.
- FIDES: a separate judge boundary with disabled, test-double, and provider-placeholder modes. Provider calls are disabled in the current public run.
- Public reporting: aggregate metrics only, with no raw source or transcript content.

### 4. Experimental setup

The checked-in public artifacts now represent three distinct evidence tiers and should not be merged into one claim:

| Artifact | Scope | Dataset status | Iterations | Public interpretation |
|---|---|---|---:|---|
| `artifacts/evals/public_gate_eval_report_50.json` | CI/public smoke | synthetic loaded; optional ASB and AgentDefenseBench skipped when local roots are absent | 50 | Public-safe regression artifact for schema, rule execution, aggregate reporting, and safety scanners. |
| `artifacts/evals/fides_test_double_public.json` | CI FIDES boundary test | synthetic loaded | 1 | Interface evidence for WARDEN-miss/FIDES-catch accounting with zero provider calls; not empirical LLM judge evidence. |
| `artifacts/evals/asb_controlled_public_report_1.json` | controlled-local ASB pass | ASB loaded from a private local root | 1 | Public-safe aggregate ASB evidence; raw ASB source remains private and uncommitted. |

All current checked-in artifacts report zero provider calls and exclude case-level rows, raw source material, model outputs, and judge transcripts. Earlier mixed ASB plus AgentDefenseBench runs should be treated as historical local experiments unless regenerated into a checked-in public-safe artifact.

### 5. Metrics

Use the public report definitions:

- Attack success rate, ASR: attack cases allowed divided by all attack cases.
- Recall: attack cases blocked or quarantined divided by all attack cases.
- Benign refusal rate: benign cases blocked or quarantined divided by all benign cases.
- Safe pass-through rate: benign cases allowed divided by all benign cases.
- Incremental WARDEN catches versus regex: attack case-iterations allowed by regex but blocked by WARDEN.
- Incremental FIDES catches versus WARDEN: attack case-iterations allowed by WARDEN but blocked by WARDEN plus FIDES.
- Expected-rule hit rate: mapped cases with public `cwfr-*` expected-rule metadata where the expected rule fired.
- False-positive diagnostics: aggregate benign blocking counts by stack, dataset, category, and rule ID, with no case-level rows.

### 6. Current checked-in aggregate results

The synthetic public smoke report gives the following aggregate security metrics:

| Stack | ASR | Recall | TP | FN | FP | TN | Benign refusal rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| no guard | 1.0000 | 0.0000 | 0 | 200 | 0 | 50 | 0.0000 |
| regex baseline | 0.5000 | 0.5000 | 100 | 100 | 0 | 50 | 0.0000 |
| WARDEN structured rules | 0.2500 | 0.7500 | 150 | 50 | 0 | 50 | 0.0000 |
| WARDEN plus FIDES | 0.2500 | 0.7500 | 150 | 50 | 0 | 50 | 0.0000 |

The FIDES test-double artifact separately demonstrates one deterministic FIDES incremental catch on a synthetic WARDEN miss, with zero provider calls. This is interface evidence only.

The controlled-local ASB artifact reports the current ASB research result:

| Stack | ASR | Recall | TP | FN | FP | TN | Benign refusal rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| no guard | 1.0000 | 0.0000 | 0 | 858 | 0 | 20 | 0.0000 |
| regex baseline | 0.9977 | 0.0023 | 2 | 856 | 0 | 20 | 0.0000 |
| WARDEN structured rules | 0.6923 | 0.3077 | 264 | 594 | 0 | 20 | 0.0000 |
| WARDEN plus FIDES | 0.6923 | 0.3077 | 264 | 594 | 0 | 20 | 0.0000 |

### 7. Results narrative

#### 7.1 Synthetic tier

The synthetic tier is the strongest current regression signal because it is hand-authored to exercise known structural policy shapes and contains no raw external dataset material. In the current public smoke run, synthetic contributes 250 case-iterations, with WARDEN blocking or quarantining 150 attack case-iterations and preserving all 50 benign case-iterations.

Allowed claim: the schema, adapters, WARDEN rule execution, public report generation, and safety boundaries work on deterministic public-safe fixtures.

Disallowed claim: synthetic results do not establish real-world effectiveness or coverage against ASB or AgentDefenseBench distributions.

#### 7.2 Controlled local ASB tier

The ASB-only artifact is the current controlled-local ASB evidence. ASB-native schema extraction now maps attack-tool and normal-tool record families into public-safe structural facts without exporting raw source. This produces measurable WARDEN coverage on ASB: 240 expected-rule cases, expected-rule hit rate 1.0000, eight covered WARDEN rule families, and 262 WARDEN incremental catches versus regex.

This is research progress, but it is not yet a complete security claim. WARDEN recall is 0.3077 and ASR remains 0.6923. The latest normal-tool hardening pass reduced the measured ASB benign false positives from 5/20 to 0/20 by treating ASB normal-tool descriptions as descriptive metadata rather than untrusted action requests, while preserving the current expected-rule hit rate.

Allowed claim: ASB-derived facts can be loaded through the controlled adapter and evaluated without exposing raw source material in public artifacts, and ASB-native schema extraction enables nonzero expected-rule evidence.

Disallowed claim: current ASB coverage is not sufficient to claim that WARDEN meaningfully secures ASB as a dataset. The result is best characterized as a controlled gap analysis with measurable progress and a clear false-positive hardening target.

#### 7.3 Controlled local AgentDefenseBench tier

No current checked-in public artifact loads AgentDefenseBench. The current public smoke report explicitly records AgentDefenseBench as skipped when its local root is absent. Any AgentDefenseBench results should be regenerated into a public-safe artifact before being used as current evidence.

#### 7.4 WARDEN interpretation

WARDEN is the deterministic structured rule layer. The current checked-in artifacts prove that WARDEN executes real `.war` rules and that public reports can summarize coverage, expected-rule hits, safe-fact completeness, and false-positive diagnostics without source leakage.

The more important scientific question is not raw block count alone, but whether WARDEN catches cases for defensible policy reasons that generalize across datasets while preserving benign near-misses. The ASB-only artifact shows progress on this question and now includes a private reviewer CSV path for human signature-improvement loops; the next blocker is improving recall and reducing remaining ASR without reintroducing benign disruption.

#### 7.5 FIDES interpretation

The current public smoke and ASB artifacts do not measure real FIDES effectiveness. Provider calls are zero, transcripts are absent, and WARDEN plus FIDES is WARDEN-equivalent in the provider-disabled reports. The separate FIDES test-double artifact validates accounting and report plumbing for a deterministic WARDEN-miss/FIDES-catch path, but it should not be described as empirical LLM judge performance.

### 8. Limitations

1. Dataset custody and reproducibility: ASB is a controlled local source. The public ASB report is reproducible only for users with equivalent local roots and configuration; raw source material is intentionally not committed.
2. Sparse benign evidence: the ASB artifact has only 20 benign cases. The current 0.0000 benign refusal rate after normal-tool hardening is encouraging, but it needs larger benign near-miss controls for stable estimates.
3. High remaining ASR: WARDEN improves over regex on ASB but still allows many attack-labeled cases.
4. AgentDefenseBench not current: no checked-in current artifact loads AgentDefenseBench after this refinement pass.
5. FIDES not empirically evaluated: disabled/test-double/provider-placeholder modes are useful for safety and interface testing, but they do not establish real judge performance.
6. No full agent runtime validation: the current gate evaluates normalized pre-context facts; it does not yet measure downstream agent task completion, tool execution, or recovery behavior in a full runtime.
7. No statistical uncertainty yet: the current deterministic reports lack confidence intervals, split variance, and holdout confirmation.

### 9. Next required experiments

1. Freeze evaluation splits before additional tuning, with separate synthetic CI, controlled local development, controlled local test, and holdout partitions.
2. Add larger benign near-miss controls for ASB-normal-tool records and each major WARDEN rule family.
3. Use the private reviewer CSV under `reverse-engineering/review/` to inspect remaining ASB false negatives and design additional signatures.
4. Preserve the current ASB expected-rule hit rate and zero measured ASB benign refusals while improving recall; treat any recall increase that reintroduces benign blocking as incomplete evidence.
5. Regenerate AgentDefenseBench as its own checked-in public-safe aggregate artifact before using it in current claims.
6. Run FIDES test-double experiments only as interface and reporting validation, clearly separated from empirical judge claims.
7. Add a transcript-private provider-enabled FIDES experiment after safety review, reporting only aggregate call counts, costs, latencies, verdict distributions, and incremental catches.
8. Add latency measurements for normalization, regex, WARDEN, and FIDES stages.
9. Add statistical summaries for frozen test and holdout runs, including confidence intervals or bootstrap intervals where appropriate.
10. Maintain public artifact scans and manual leakage review before any public report or paper draft is shared.

### 10. Candidate paper contribution statement

A defensible future contribution would be:

We present a leakage-safe controlled harness for comparing regex baselines, structured WARDEN rules, and a separately gated FIDES judge boundary on normalized agent-security cases. The current checked-in artifacts show that WARDEN is connected end-to-end, improves over a regex baseline on public synthetic fixtures, and produces measurable public-safe ASB evidence when a controlled local ASB root is available. The same evidence now shows zero measured benign refusals on the current small ASB benign set after normal-tool hardening, while still identifying the next research blocker: high remaining ASR. The method emphasizes explicit custody boundaries, public-safe aggregate reporting, expected-rule evidence, false-positive diagnostics, private reviewer CSVs, and attack-to-rule mappings as prerequisites for stronger future claims.

### 11. Current bottom line

The harness is ready for an initial report draft and follow-up ASB signature-improvement work, not a final paper claim. The current checked-in artifacts demonstrate engineering progress: real WARDEN rule execution, controlled ASB schema extraction, aggregate expected-rule evidence, aggregate false-positive diagnostics, FIDES test-double accounting, private reviewer CSV generation, and public reports that remain source-free. They also make the next research gap clear: use the private CSV to improve ASB recall and regenerate any AgentDefenseBench evidence as a current checked-in public-safe artifact before claiming cross-dataset coverage.
