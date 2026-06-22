# ADR 0002: WARDEN `.war` rule DSL (YARA-style)

## Status

Accepted. Supersedes [ADR 0001](0001-warden-rule-grammar.md). Amended by
[ADR 0003](0003-collapse-to-facts-and-cases.md), which drops the `kind` split and
the `signals` layer, removes the custody/redaction model, and replaces the
case→rule mapping oracle with a `.cases` corpus.

## Context

`.war` rules were flat YAML documents: identity (`id`, `name`, `severity`,
`category`) sat outside `meta`, one rule per file, and the same feature was often
declared twice — once as a `keywords` entry of `type: feature` and again as a
`signals` `feature_flag` — with the condition referencing only one copy, leaving
the other dead. The `ppe` signature corpus was patterns-only over raw host
indicators and orphaned from every manifest, and rules reached the FIDES/IFC gate
carrying nothing rule-specific for the judge. Detection engineers found the format
hard to read and author.

We want a format that is familiar to detection engineers (YARA-shaped), lets one
ruleset hold many rules, anchors each rule to a standardised MITRE technique, and
carries exactly what each evaluation stage needs — while staying novel rather than
a copy of any single vendor's rule language.

## Decision

### File and rule model

A `.war` file is a **ruleset**: a sequence of bare `rule Name { ... }` blocks. The
folder and filename convey theme; the block conveys one detection. A hand-written
tokenizer/parser replaces `yaml.safe_load`; the `.war` extension stays. This is a
hard cut — there is no dual-format support.

```
rule CommandOrCodeExecutionRequest {
  meta:
    id          = cwfr-0106
    kind        = policy
    version     = 0.1.0
    severity    = high
    action      = block_and_audit
    scope       = event_window
    technique   = T1059 (Execution, analogical)
    defense     = D3-AM
    author      = "Project Open Hand Monk"
    status      = experimental
    description = "Untrusted or dataset-local content requesting command or code execution capability."
    safety      = "Structural feature-only rule; examples must not contain executable payload text."

  signals:
    $exec_shape  = feature(command_execution_shape)
    $not_granted = capability(not_in_allowed)

  semantics:
    $exec_intent = "Content requests command, code, script, shell, or interpreter-like execution." (0.70)

  judge:
    $unsafe_exec = "Do redacted facts indicate untrusted content is requesting command or code execution?" (0.65)

  condition:
    ($exec_shape and $not_granted) or $exec_intent or $unsafe_exec
}
```

### Identity lives in `meta:`

Only the rule **name** (the block header) and the **logic** (detection layers plus
`condition`) live outside `meta:`. Everything else is a `meta` field written as
`key = value`: controlled fields (`kind`, `severity`, `action`, `scope`) are bare
enums; free text (`description`, `safety`, `author`) is quoted.

- `id` — required, stable `cwfr-*` join key for the eval mapping/scoring harness.
- `kind` — `signature` or `policy` (see taxonomy below).
- `severity` — `low | medium | high | critical`.
- `action` — `allow | audit | quarantine | block_and_audit` (was `recommended_action`).
- `scope` — correlation scope, default `event_window`.
- `technique` — one or more MITRE anchors (required; see below).
- `defense` — optional D3FEND counter-mapping.
- `version`, `author`, `status`, `description`, `safety` (was `safety_notes`).

### Two kinds, separated by epistemic power

- **`signature`** may use **only** the `patterns` layer — deterministic text
  matching over custody-safe text using generic, publicly-known indicators
  (ATT&CK-documented paths, binaries, tropes). The deliberately-brittle baseline.
- **`policy`** must use **at least one** relational layer — `signals`,
  `semantics`, or `judge`. The structured detection tier and the project's core
  contribution.

The validator enforces this: a `signature` with any relational layer, or a
`policy` with only `patterns`, is rejected. The redacted-features-only purity
applies to `policy` rules; signatures may match generic text but must never
memorise dataset- or benchmark-specific payload strings.

### Four detection layers

- **`patterns`** — `$x = /regex/flags` or `$x = "exact"`, evaluated over
  custody-safe event text. Text only; no feature matching here.
- **`signals`** — the structured core. Named constructors over the
  NormalizedTrace and policy context: `feature(flag)`, `capability(not_in_allowed)`,
  `canary_flow(outside_allowed_sink)`, `origin(...)`, `sink_in(...)`,
  `schema_shape(...)`, `event_field_equals(field, value)`,
  `event_field_in(field, [..])`, `text_structure(hidden_unicode |
  untrusted_instruction_shape)`. **All** feature/structure matching lives here, so
  features are declared exactly once.
- **`semantics`** — `$z = "description" (threshold)`. Provider-free token-similarity
  score in `[0,1]`; satisfied when any in-scope event meets the threshold.
- **`judge`** — `$w = "natural-language question" (threshold)`. Routed to the
  FIDES/IFC judge when a policy rule's deterministic layers miss. The judge is a
  separate layer, never the quarantined model.

Every declared `$name` is unique within the rule and **must** be referenced by the
`condition` — no dead terms.

### Conditions use bare `$` refs

`condition` composes `$name` references (YARA-faithful — the layer is where a name
is *defined*, not how it is *referenced*) with `and`, `or`, `not`, parentheses, and
quantifier sugar: `any of <layer>` / `all of <layer>` (e.g. `any of patterns`,
`any of signals`), `any of them`, and `any of ($a, $b)`.

### Technique anchor (compact, prefix-inferred)

`technique = T1059 (Execution, analogical)`. The framework is inferred from the id
prefix — `T*` → ATT&CK, `AML.T*` → ATLAS, `D3-*` → D3FEND. The parenthesised part
is the MITRE **tactic** (the rule's classification axis, replacing the old bespoke
`category` slug) followed by an optional `mapping_strength` (`direct` |
`analogical`). A rule may declare several techniques; at least one offensive
technique is required. `mapping_strength` is retained deliberately: host ATT&CK
techniques map to LLM/MCP surfaces *analogically*, and saying so is part of the
research integrity. ATLAS `AML.T*` anchors are the novel, native taxonomy for the
agentic surface.

### Ground truth is the mapping layer, not per-rule fixtures

Rules carry **no** test vectors. The oracle — which rules should fire
(`expected_rule_ids`) and which must not (`should_not_fire_rule_ids`,
`benign_near_miss_controls`) — lives once per `AttackCase` in the central case→rule
mapping (`cases.py` / `mappings.py` / adapters), is public-safe, validated, and is
consumed by the runner and reporting. This mirrors MITRE: an analytic carries
detection logic plus a technique anchor; coverage is measured centrally, not via
per-analytic fixtures. The previous per-rule `fixtures:` field was write-only dead
metadata and is removed.

### FIDES wiring is a stack toggle

The existing guard `stacks` and `fides_mode` select the contract: `yara_rules`
runs the deterministic WARDEN layers only (benchmark mode, no judge escalation);
`rules_plus_fides` adds the always-on IFC invariants and carries each policy
rule's `judge:` checks. When a policy rule's deterministic layers miss, its
`judge:` checks are collected and threaded to the FIDES judge as miss-context;
the provider-backed judge includes them in its prompt so FIDES queries with the
rule's own questions. Deepening the deterministic test-double judge to adjudicate
each per-rule judge check individually is named future work.

### File organisation

Rules are split by kind: `rules/policy/*.war` and `rules/signature/*.war`, one
themed ruleset per file. The `signature` tier (re-authored from the former `ppe`
corpus) is wired into the baseline stack.

## Considered options

- **Extend the YAML format** (move identity into `meta`, keep YAML). Rejected: the
  verbosity and the keyword/signal duplication were intrinsic to the format; a
  YARA-shaped block DSL is what detection engineers expect.
- **Per-rule self-test fixtures** (each rule ships labelled positive/negative
  traces, run as a unit test). Rejected: it shifts the oracle burden onto every
  author and duplicates the live, central case→rule mapping layer.
- **Namespaced condition refs** (`signals.$x`, `judge.$y`). Rejected: real YARA
  conditions are bare `$a and $b`; the `$` sigil already disambiguates.
- **`tunables:` block now** (MITRE Mutable-Elements analog for per-environment
  overrides). Deferred: fixed inline thresholds keep ASR comparisons apples-to-apples
  across stacks; recorded as future work.

## Consequences

A hard cut: the YAML loader, the four detection sections (`keywords`/`fides`
become `patterns`/`judge`), and all 31 rules are rewritten; `docs/architecture/lld.md`,
`docs/guides/rule_authoring.md`, the `README`, the `data/yara/*` manifests, and the rule
and gate tests are updated to match. ADR 0001 is superseded. `tunables:`
remains open as named future work.
