# Simplified Multi-Dataset Harness Architecture

This is a practical planning draft only. It does not define implementation code and must not include raw ASB, AgentDefenseBench, or other adversarial payload text.

## Thesis to prove

CanaryWeave FIDES should test a narrow, defensible claim:

YARA-style deterministic rules, followed by a FIDES LLM-as-judge layer for cases those rules miss, improve agent security posture across multiple attack datasets while remaining defender-maintainable, engine-stable, and transferable in an OPA-like policy model.

The evaluation should show incremental value, not just raw block rate:

1. A no-guard agent is vulnerable on attack cases.
2. Regex/YARA-style deterministic rules catch the obvious or structurally recognizable cases first.
3. FIDES LLM-as-judge catches policy-relevant misses that deterministic rules did not catch.
4. Benign task disruption remains measured and bounded.
5. The same rule engine and policy vocabulary work across ASB and at least one additional dataset when locally available.

## Design principles

- Multi-dataset by default: ASB must not be the only evidence source. Include local AgentDefenseBench when available, plus synthetic CI fixtures for safe regression.
- Dataset adapters, not dataset-specific defenses: each dataset is normalized into a common `AttackCase` record before evaluation.
- Pre-context gate first: evaluate the attack payload before it is inserted into the agent context or allowed to influence tool use.
- Deterministic rules before judge: regex/YARA-style rules run first and short-circuit obvious blocks.
- FIDES as second-stage judge: FIDES sees only the redacted, policy-relevant case view and decides whether a missed case should be blocked/quarantined.
- Defender maintainability: rules are declarative, reviewable, versioned, explainable, and stable across engines.
- OPA-like separation: policy decision-making is separate from enforcement; the harness passes structured facts to the rule/judge layers and records decisions.
- Raw payload safety: raw dataset payloads stay in local custody; committed artifacts contain only opaque IDs, metadata, hashes, redacted features, and aggregate metrics.

## High-level architecture

```text
local dataset roots
  ├─ ASB raw/private files
  ├─ AgentDefenseBench raw/private files, if present
  └─ synthetic safe fixtures
        |
        v
Dataset adapters
  - ASBAdapter
  - AgentDefenseBenchAdapter
  - SyntheticAdapter
        |
        v
AttackCase manifest
  - opaque case_id
  - dataset_id and split
  - attack/benign label
  - category/surface labels
  - allowed capabilities/sinks
  - raw payload pointer kept private
  - redacted payload features for public-safe export
        |
        v
Harness runner, 50 iterations per configured case/sample
        |
        v
Pre-context gate loop
  1. regex/YARA deterministic rules
  2. structured CanaryWeave rules over normalized facts
  3. FIDES LLM-as-judge on misses only
        |
        v
Optional attacker simulation
  - direct API injection simulation
  - MCP/tool-result injection simulation
        |
        v
Decision + metric recorder
  - allow/block/quarantine
  - rule IDs and judge check IDs
  - attack success/failure
  - benign pass-through/refusal
  - latency/cost
  - leakage-safe aggregate reports
```

## Core objects

### `DatasetAdapter`

Purpose: convert each dataset into the same harness input shape without leaking raw payloads.

Required adapter responsibilities:

- Discover local dataset files from configured paths.
- Refuse to run if the dataset is absent, unless marked optional.
- Map dataset-native examples into `AttackCase` records.
- Assign stable opaque IDs, preferably HMAC-derived with a private key.
- Preserve raw payload pointers privately for local execution.
- Emit only safe redacted features to public artifacts.
- Map dataset-specific categories into a shared taxonomy.

Initial adapters:

- `SyntheticAdapter`: safe CI fixtures, always available, no raw payload risk.
- `ASBAdapter`: controlled local ASB runs; raw data must remain outside committed artifacts.
- `AgentDefenseBenchAdapter`: optional local adapter; include if the local dataset exists, skip with an explicit report note if absent.

### `AttackCase`

A dataset-neutral case envelope.

Recommended fields:

- `case_id`: opaque stable ID.
- `dataset_id`: `synthetic`, `asb`, `agentdefensebench`, or future dataset name.
- `split`: `ci`, `dev`, `test`, `holdout`, or dataset-native split.
- `case_kind`: `attack` or `benign`.
- `attack_category`: shared taxonomy label.
- `surface`: `prompt`, `tool_result`, `mcp_resource`, `mcp_tool`, `api_message`, or dataset-specific mapped surface.
- `iteration_seed`: set by the runner for repeated trials.
- `raw_ref`: private local pointer, never exported publicly.
- `safe_features`: lengths, hashes, structural markers, origin labels, canary flags, role/source labels.
- `policy_context`: allowed tools, allowed sinks, trusted origins, protected data labels, canary handling policy.
- `expected_behavior`: expected allow/block/quarantine or attack-success criterion.

### `NormalizedFacts`

The OPA-like decision input for rules and FIDES.

It should contain structured facts, not dataset-specific records:

- Origin and trust labels.
- Role/surface labels.
- Whether content is instruction-shaped, tool-plan-shaped, exfiltration-shaped, obfuscated, or canary-bearing.
- Requested or implied tool/action/sink.
- Capability grants and denials.
- Whether protected data could flow to a non-permitted sink.
- Redacted text features only when required by regex/YARA baselines.

## Evaluation loop

Keep the loop simple and repeatable.

For each enabled dataset:

1. Load the dataset through its adapter.
2. Freeze a sample or split before tuning.
3. Convert examples to `AttackCase` records.
4. For each case, run 50 iterations using fixed seeds or deterministic perturbation settings.
5. For each iteration, build `NormalizedFacts` and run the pre-context gate.
6. If deterministic rules block, record a deterministic catch and do not call FIDES.
7. If deterministic rules allow, call FIDES LLM-as-judge with only the redacted/policy view.
8. If FIDES blocks or quarantines, record a FIDES catch.
9. If both layers allow, run the optional attacker simulation to determine whether the attack succeeds or the benign task completes.
10. Record metrics, disagreement rows, and leakage-safe evidence.

Recommended first evaluation configuration:

- 50 iterations per case or per fixed sampled case set.
- Provider calls disabled for CI and synthetic runs.
- For controlled local research, FIDES can use a configured judge model, but transcripts remain private.
- Temperature fixed low or zero for judge stability.
- Same case ordering, seeds, rule versions, and judge prompt version across defense stacks.

## Pre-context gate

The gate evaluates untrusted content before it reaches the agent's working context.

```text
incoming dataset payload or simulated attacker message
  -> normalize/redact into policy facts
  -> regex/YARA rule scan
  -> structured CanaryWeave rule evaluation
  -> if still allowed, FIDES LLM-as-judge
  -> allow, quarantine, or block
  -> only allowed cases continue to agent/MCP/API simulation
```

The deterministic stage should be intentionally simple:

- Regex rules for obvious lexical indicators and baseline comparison.
- YARA-style rules for composable strings, metadata, conditions, and tags.
- Structured CanaryWeave rules for origin, surface, capability, sink, canary, and tool-plan facts.

FIDES should focus on misses:

- Did untrusted content attempt to change the agent's policy or goal?
- Did untrusted content induce a consequential action?
- Did protected or canary-bearing information appear to flow toward an unapproved sink?
- Does the case violate the declared policy context even if no deterministic signature matched?

## Optional attacker simulation

The first harness should not need a full agent runtime. Use a minimal simulator only where useful for scoring.

Two modes are enough:

1. Direct API simulation:
   - Treat the attack case as an inbound API or chat message.
   - Apply the pre-context gate.
   - If allowed, ask whether the unsafe instruction would enter the agent context or cause a prohibited action in the simulator.

2. MCP/tool simulation:
   - Treat the attack case as a malicious tool result, resource, sampling output, or server-provided content.
   - Apply the pre-context gate before the content is joined into agent context.
   - If allowed, simulate whether the agent would call a prohibited tool, reveal protected data, or write to an unapproved sink.

Keep simulation deterministic where possible. If an LLM agent is used later, separate those results from the primary gate results.

## Defense stacks to compare

Run the same cases through these stacks:

1. `no_guard`
   - No pre-context blocking.
   - Establishes baseline vulnerability and benign completion.

2. `regex_baseline`
   - Plain regex/string matching over allowed redacted text features.
   - Useful baseline, not the proposed contribution.

3. `yara_rules`
   - Defender-maintainable deterministic rules with YARA-like metadata, strings/signals, conditions, tags, and stable semantics.
   - Can be represented in `.war` while borrowing YARA's mental model.

4. `rules_plus_fides`
   - Runs `yara_rules` first.
   - Sends only rule misses to FIDES LLM-as-judge.
   - Final decision is block/quarantine if either layer blocks.

Optional later stack:

5. `rules_plus_fides_plus_runtime_ifc`
   - Adds post-context flow checks if the project keeps the existing IFC framing.
   - Treat as an extension, not the core simplified thesis.

## Metrics

Report overall, per dataset, and per category where denominators are sufficient.

Primary security metrics:

- Attack success rate, ASR: attacks allowed and successful / total attacks.
- ASR reduction vs `no_guard` and vs `regex_baseline`.
- Deterministic catch rate: attacks blocked by regex/YARA before FIDES.
- FIDES incremental catch rate: attacks allowed by deterministic rules but blocked by FIDES.
- Remaining miss rate: attacks allowed by both rules and FIDES.

Benign-impact metrics:

- Refusal/rejection rate on benign cases.
- Safe pass-through rate.
- Task completion rate where the simulator can judge completion.
- FIDES incremental false-positive rate: benign cases allowed by deterministic rules but blocked by FIDES.

Operational metrics:

- Per-case latency by stage: adapter, normalization, regex, YARA/structured rules, FIDES, simulator.
- Judge call count and cost, if provider mode is enabled.
- Cost per additional attack caught by FIDES.
- Rule coverage by rule ID and category.

Required disagreement views:

- Regex missed, YARA caught.
- YARA missed, FIDES caught.
- FIDES blocked benign cases that YARA allowed.
- Dataset-specific categories where transfer fails.

## Raw payload safety

Safety requirements are part of the harness architecture, not a reporting afterthought.

Rules:

- Never commit raw dataset payloads, transcripts, completions, tool outputs, or exploit strings.
- Keep raw ASB and AgentDefenseBench files outside the repo or under ignored private directories.
- Public case IDs must be opaque and non-reconstructable.
- FIDES judge prompts and responses from real dataset runs are private artifacts.
- Public reports may include aggregate metrics, category labels, rule IDs, judge verdict IDs, and paraphrased policy reasons only.
- Synthetic examples used in docs must be hand-authored and must not copy dataset payloads.
- Every export should pass a leakage review before sharing.

Suggested artifact split:

- Private local artifacts:
  - raw dataset roots;
  - raw-to-case manifest;
  - judge transcripts;
  - detailed failure notes.
- Public-safe artifacts:
  - redacted manifest summary;
  - aggregate metrics;
  - rule coverage tables;
  - disagreement counts;
  - synthetic examples only.

## Transferability target

The deterministic rules should be judged not only by catch rate but by whether defenders can maintain and transfer them.

A good rule should:

- Describe a policy shape, not a dataset-specific payload string.
- Use stable facts such as origin, surface, capability, sink, protected-data label, canary flag, and action type.
- Include metadata, owner, severity, category, rationale, and test fixtures.
- Be reviewable in code review by a defender who does not know the harness internals.
- Avoid test-split memorization.
- Work across at least ASB and one additional dataset category when the same policy violation appears in both.

This gives the paper a stronger claim than “we matched ASB strings”: the system behaves like portable policy-as-code for agent security.

## Minimal milestone plan

### Milestone 1: Harness specification freeze

- Freeze `AttackCase` and `NormalizedFacts` schemas.
- Define shared taxonomy for ASB and AgentDefenseBench categories.
- Define public/private artifact boundaries.
- Define the 50-iteration runner contract.

### Milestone 2: Dataset adapters

- Add synthetic adapter for CI-safe fixtures.
- Add ASB local adapter with private raw custody.
- Add AgentDefenseBench local adapter that auto-skips when the dataset is absent.
- Ensure all adapters emit the same `AttackCase` shape.

### Milestone 3: Gate-only evaluation

- Implement `no_guard`, `regex_baseline`, `yara_rules`, and `rules_plus_fides` stack modes.
- Run pre-context gate results without a full agent runtime.
- Report deterministic catches first, then FIDES incremental catches.

### Milestone 4: Minimal simulation

- Add direct API simulation.
- Add MCP/tool-result simulation.
- Keep simulation deterministic and separate from primary gate metrics.

### Milestone 5: Controlled local report

- Run ASB plus AgentDefenseBench if available.
- Produce private detailed results and public-safe aggregate results.
- Include raw-payload safety statement, limitations, and transferability analysis.

## Acceptance criteria

The simplified architecture is ready for implementation when:

- ASB is not the only planned dataset.
- AgentDefenseBench is treated as an optional local dataset, not a required public dependency.
- Every dataset flows through a common `AttackCase` and `NormalizedFacts` interface.
- The pre-context gate is the primary evaluation point.
- Deterministic regex/YARA catches are measured before FIDES.
- FIDES incremental catches and false positives are measured separately.
- The runner supports 50 iterations with fixed seeds/configuration.
- Raw payloads, judge transcripts, and raw-to-case mappings remain private.
- Public results can support the thesis without leaking adversarial content.
