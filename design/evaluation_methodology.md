# Evaluation Methodology: Regex Baseline vs Structured Rules vs Rules+FIDES on ASB

This document defines the evaluation plan for the next CanaryWeave FIDES phase. It is a methodology only; it does not specify implementation details or include raw ASB payloads.

## Goals

Compare three defense stacks on the same ASB-derived cases:

1. `regex_guard`: a text/signature baseline over visible, redacted text features.
2. `structured_rule_guard`: `.war` rules over `NormalizedTrace` records.
3. `rules_plus_fides_ifc`: structured rules plus FIDES/IFC checks for trusted-action and permitted-flow policy violations.

The evaluation should answer:

- How much does each stack reduce successful attacks?
- How many safe/benign cases does each stack allow without disruption?
- Which ASB categories are caught by structured context but missed by regex?
- Which remaining misses are caught only by FIDES/IFC flow reasoning?
- What is the disagreement pattern between stacks?
- What latency and cost overheads appear if real providers are enabled later?

## Safety boundary

Raw ASB material must stay in controlled local custody and must never appear in public artifacts.

Allowed in public or default exports:

- Opaque case IDs or keyed/HMAC identifiers.
- Dataset split names and category labels.
- Redacted `NormalizedTrace` fields.
- Structural feature flags, lengths, counts, hashes, and policy labels.
- Aggregate metrics and representative category-level summaries.
- Short rule IDs, check IDs, and non-sensitive rationales.

Not allowed in public artifacts, docs, rules, test fixtures, reports, PR text, or chat:

- Raw adversarial instructions or payload strings.
- Raw ASB prompts, completions, tool outputs, traces, transcripts, or secrets.
- Reconstructable snippets, long verbatim substrings, or payload templates.
- External sink details, credential-like material, or live provider request/response bodies.

All exported records should pass a leakage review before being committed or shared. Public reports should be reproducible from redacted manifests, but not sufficient to reconstruct ASB payloads.

## Evaluation tiers

Keep three evaluation tiers separate. Do not blend their artifacts or claims.

### Tier 1: Synthetic CI

Purpose: fast, deterministic regression checks that are safe to run in every PR.

Inputs:

- Synthetic structural fixtures only.
- No raw ASB payloads.
- No provider calls.
- Small hand-authored cases covering each rule and FIDES policy shape.

Outputs:

- CI-safe JSON summary.
- Per-stack aggregate metrics.
- Per-category counts using synthetic categories.
- Artifact-safety scan result.

Claims allowed:

- Rule schema, normalization, metrics, and FIDES policy logic behave as expected on synthetic fixtures.
- Structured rules and FIDES can be compared apples-to-apples on a fixed trace schema.

Claims not allowed:

- Real ASB effectiveness.
- General security effectiveness.
- Provider-model robustness.

### Tier 2: Controlled local ASB raw run

Purpose: measure the stacks on ASB-derived cases while keeping raw material private.

Inputs:

- Locally held ASB raw records.
- A private manifest mapping raw records to opaque case IDs.
- A redaction/normalization process that emits `NormalizedTrace` records without raw payload text.
- A locked evaluation configuration: stack versions, rule versions, FIDES policy version, random seeds if sampling is used, and provider-disabled or provider-enabled mode.

Custody rules:

- Raw ASB files remain outside committed project artifacts.
- Raw-to-case-ID mapping remains private.
- Only redacted traces and aggregate metrics can leave the controlled environment.
- Case-level exports must contain opaque IDs and feature summaries only.
- Manual reviewer notes must paraphrase at category level and avoid examples that reconstruct payloads.

Recommended flow:

1. Freeze the ASB case list and split before tuning.
2. Convert each raw case into a redacted `NormalizedTrace` plus labels.
3. Run all three stacks on the same normalized records.
4. Record allow/block/quarantine decisions, matched rule IDs, FIDES check IDs, and timing.
5. Compute metrics by split, category, surface, and overall.
6. Run leakage checks on every exported artifact.
7. Produce a private detailed report and a separate public-safe report.

Claims allowed:

- Controlled ASB effectiveness for the evaluated version, split, and configuration.
- Category-level incremental value of structured rules over regex and FIDES over rules.

Claims not allowed:

- Unqualified universal MCP security.
- Public disclosure of raw ASB content or exact exploit mechanics.

### Tier 3: Public-safe report

Purpose: communicate findings without leaking raw ASB material.

Inputs:

- Tier 2 aggregate metrics.
- Redacted category labels.
- Opaque case IDs only when necessary.
- Safe examples based on synthetic fixtures, not ASB raw content.

Outputs:

- Aggregate tables by stack and category.
- Confusion-matrix summaries.
- ASR/RR/block-rate plots or tables.
- Disagreement and incremental-catch summaries.
- Latency/cost summaries if provider mode was enabled.
- Safety statement describing what was redacted and what was withheld.

Public report language should say “ASB-derived redacted traces” or “controlled local ASB run,” not imply that raw records are published.

## Data model and labels

Each evaluated case should have:

- `case_id`: opaque stable ID.
- `split`: `synthetic_ci`, `asb_dev`, `asb_test`, or other frozen split name.
- `source_tier`: synthetic, local_asb_private, or public_safe_export.
- `surface`: MCP or agent surface category.
- `attack_category`: broad taxonomy label.
- `expected_attack`: true for malicious/unsafe cases, false for benign/safe cases.
- `expected_policy_violation`: optional finer label for rule/FIDES target.
- `expected_safe_completion`: true where benign task completion can be judged.
- `NormalizedTrace`: redacted trace consumed by every stack.
- `policy_context`: allowed capabilities, permitted sinks, trusted origins, and canary sink policy.

Ground truth should be assigned before model/guard evaluation where possible. If labels require adjudication, use at least two reviewers or one reviewer plus a written decision rubric. Track uncertain labels separately rather than forcing them into the main denominator.

## Defense stack definitions

### Regex baseline

The regex stack is intentionally limited:

- It may inspect visible redacted text fields and safe structural markers.
- It should not receive privileged raw payloads that the other stacks do not receive.
- It should not use ASB-specific memorized signatures from the test split.
- Its pattern set should be frozen before final test evaluation.

This gives a conservative but fair baseline: fast substring/signature matching without trace-aware policy reasoning.

### Structured rules

The structured-rule stack evaluates `.war` policies against the same `NormalizedTrace` records:

- Signals may use origin, surface, role, event order, capability, sink, schema shape, integrity/confidentiality labels, canary movement, and safe text-structure features.
- Rules should emit matched signal IDs, rule IDs, severity, and final action.
- Rules should be frozen before the final ASB test split.

### Rules+FIDES

The rules+FIDES stack is the union of structured-rule decisions and FIDES/IFC decisions:

- Structured rules still run first and retain their decision records.
- FIDES checks whether low-integrity or untrusted-origin data caused consequential actions.
- FIDES checks whether restricted or canary-bearing data flowed to non-permitted sinks.
- A block/quarantine by either layer counts as a block for this stack.
- FIDES should report check IDs and short non-sensitive rationales, not raw evidence.

## Metrics

Report metrics overall and by category/surface/split whenever denominators are large enough.

### Core classification counts

For each stack:

- TP: attack/unsafe case blocked or quarantined.
- FP: benign/safe case blocked or quarantined.
- TN: benign/safe case allowed.
- FN: attack/unsafe case allowed.

Use `block_or_quarantine` as the positive prediction unless a separate thresholding study is explicitly run.

### Required rates

- ASR, attack success rate: `FN / (TP + FN)`.
- RR, refusal or rejection rate on benign cases: `FP / (FP + TN)`.
- Block rate: `(TP + FP) / total_cases`.
- Precision: `TP / (TP + FP)`.
- Recall: `TP / (TP + FN)`.
- F1: harmonic mean of precision and recall.
- FPR: `FP / (FP + TN)`.
- FNR: `FN / (TP + FN)`; equivalent to ASR under block-as-defense framing.
- Safe pass-through rate: `TN / (TN + FP)`.
- TCR, task completion rate, where measurable: benign cases completed successfully and allowed divided by benign cases with a completion label.

If completion cannot be judged for a case, exclude it from TCR but keep it in safe pass-through and classification metrics.

### ASR reduction

Report absolute and relative ASR reduction against the regex baseline and, separately, against no guard if a no-guard reference exists:

- Absolute ASR reduction: `ASR_baseline - ASR_stack`.
- Relative ASR reduction: `(ASR_baseline - ASR_stack) / ASR_baseline`, when baseline ASR is non-zero.

Do not present ASR reduction without the corresponding RR/FPR and safe pass-through numbers; otherwise the result can hide excessive blocking.

### Incremental catch and disagreement

Required pairwise comparisons:

- Regex false negatives caught by structured rules: attack cases allowed by regex but blocked by structured rules.
- Structured-rule misses caught by FIDES: attack cases allowed by structured rules but blocked by rules+FIDES.
- FIDES-only blocks on benign cases: benign cases allowed by structured rules but blocked by rules+FIDES.
- Regex-only blocks: cases blocked by regex and allowed by structured rules.
- Rule-only blocks: cases blocked by structured rules and allowed by regex.
- Three-way disagreement matrix: decision tuple across regex, structured rules, and rules+FIDES.

Report incremental catch rate as:

- `incremental_catch(A -> B) = attacks_allowed_by_A_and_blocked_by_B / attacks_allowed_by_A`.

Also report incremental false-positive rate:

- `incremental_fp(A -> B) = benign_allowed_by_A_and_blocked_by_B / benign_allowed_by_A`.

### Latency and cost

For deterministic local mode:

- Measure per-case wall-clock latency for normalization, regex evaluation, structured-rule evaluation, FIDES evaluation, and total guard time.
- Report median, p90, p95, and p99 if sample size supports it.
- Report CPU-only local mode separately from any provider-enabled mode.

If providers are enabled later:

- Record provider mode, model alias, call count, input/output token counts if available, retries, timeouts, and estimated cost.
- Report cost per evaluated case and cost per additional attack caught.
- Keep provider transcripts private; public report includes only aggregates.
- Provider-enabled results are secondary unless the primary claim explicitly includes providers.

## Splits and anti-contamination

Use separate splits:

- Synthetic CI: safe public regression fixtures.
- ASB dev: private tuning and rule development.
- ASB test: private final evaluation; no tuning after test results are inspected.
- Optional ASB holdout: used only for final confirmation after methodology stabilizes.

Rules and regex patterns must be frozen before ASB test evaluation. If any rule is changed after reviewing test results, reset the test or move to a new holdout split.

## Statistical reporting

For ASB dev/test reports:

- Include denominators for every percentage.
- Provide confidence intervals or bootstrap intervals for key metrics when sample size supports it.
- Report category-level metrics only when denominators are sufficient; otherwise aggregate or mark as low-support.
- Include both macro averages by category and micro averages over cases when useful.
- Avoid overclaiming small differences without uncertainty estimates.

## Failure analysis without leakage

For private analysis, reviewers may inspect raw cases under local custody. Public-safe failure analysis should use only:

- Category and surface labels.
- Opaque case IDs.
- Matched/missed rule IDs.
- FIDES check IDs.
- Redacted structural reasons, such as “untrusted origin caused consequential action” or “restricted data reached non-permitted sink.”

Do not include payload excerpts. When a concrete example is needed publicly, create a synthetic structural analogue that demonstrates the same policy shape without copying ASB content.

## Reporting template

Each run should produce two report forms.

Private controlled report:

- Run ID, date, code revision, rule revision, FIDES policy revision.
- Dataset manifest ID and split ID.
- Safety/custody checklist result.
- Overall metrics table.
- Category/surface metrics table.
- Disagreement and incremental-catch tables.
- Latency/cost table.
- Private reviewer notes stored outside public artifacts.

Public-safe report:

- High-level methodology.
- Aggregate metrics with denominators.
- Category-level summaries with low-support caveats.
- Disagreement/incremental-catch counts.
- Latency/cost aggregates if applicable.
- Safety statement: raw payloads withheld; only redacted traces and aggregate metrics used.
- Limitations and claim boundary.

## Acceptance criteria for the next phase

The methodology is ready to use when:

- Synthetic CI can run without raw payloads or provider calls.
- The local ASB path keeps raw inputs outside committed artifacts.
- All stacks consume the same redacted `NormalizedTrace` view.
- Metrics include ASR, RR, block rate, precision, recall, F1, FPR, FNR, safe pass-through, and TCR where measurable.
- Disagreement and incremental-catch metrics are reported.
- Latency and cost fields exist, even when provider cost is zero in local mode.
- Public exports are checked for raw-payload leakage before sharing.
- Claims are clearly separated by tier: synthetic CI, controlled local ASB, and public-safe report.
