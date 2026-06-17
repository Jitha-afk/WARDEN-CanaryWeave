# CanaryWeave FIDES

Controlled research POC comparing guard stacks — a regex/signature baseline, a defender-authored structured WARDEN rule layer, and an optional FIDES/IFC layer — around quarantined `query_llm` calls. This glossary fixes the language those guards share.

## Language

### Traces, guards, and gates

**NormalizedTrace**:
The neutral audit record every guard stack evaluates: a case-level envelope plus an ordered sequence of normalized events, each carrying structured fields (origin, surface, capability, sink, canary movement, integrity/confidentiality labels) and a safe-features map. Raw text stays in controlled custody; public exports are redacted and feature-only.
_Avoid_: NormalizedFacts, TraceEvent, trace record

**Safe feature**:
A structural boolean or label (e.g. `instruction_shape`, `hidden_unicode`, `command_execution_shape`) derived once from raw content at the custody boundary and carried on the NormalizedTrace. Guards read safe features; they never re-derive them from raw payloads.
_Avoid_: flag, text feature

**WARDEN**:
The deterministic rule stack — regex baseline, YARA-style manifests, and `.war` structured rules — that evaluates a NormalizedTrace into a decision.
_Avoid_: rule service, detector engine

**FIDES/IFC**:
The optional information-flow-control judge layer applied only after WARDEN allows. Checks trusted-action (consequential actions must not stem from low-integrity or untrusted-origin data) and permitted-flow (restricted data may only reach permitted sinks).
_Avoid_: LLM judge, guardrail

**Guard stack**:
A named evaluation configuration compared apples-to-apples on the same NormalizedTrace: `no_guard`, `regex_baseline`, `yara_rules`, `rules_plus_fides`.
_Avoid_: pipeline, guard layer; the README's `regex_guard` / `structured_rule_guard` / `rules_plus_fides_ifc` (use the StackName values)

**Gate**:
The quarantined `query_llm` enforcement point: runs a guard stack as preflight, calls the quarantined model, runs the stack again as postflight, then FIDES — composing one shared evaluation core rather than re-sequencing it.
_Avoid_: handler, middleware

**AttackCase**:
The public-safe case envelope (labels, safe features, policy context) a NormalizedTrace is derived from. Raw payloads live only in private custody and never appear in public exports.
_Avoid_: sample, example

**Canary**:
A marked token whose appearance outside an allowed sink signals exfiltration across a guard seam.
_Avoid_: honeytoken, marker

### Rule vocabulary

A `.war` ruleset is a file of `rule {}` blocks. Each rule declares its identity in `meta` (including a technique anchor), one or more detection layers, and a boolean `condition`. Two kinds exist, separated by epistemic power. A rule carries no test vectors of its own; ground truth lives in the case→rule mapping.

**Signature rule**:
A `kind: signature` rule that matches generic, publicly-known indicators in custody-safe text and does no trust- or flow-reasoning. The deliberately-brittle baseline that policy rules are measured against.
_Avoid_: regex rule, baseline rule, dumb rule

**Policy rule**:
A `kind: policy` rule that reasons over structured trust and flow facts, optionally escalating to the judge. The structured detection tier and the project's core contribution.
_Avoid_: smart rule, behavioral rule

**Pattern**:
A deterministic text matcher (exact or regex) in a rule's `patterns` layer, evaluated over custody-safe text. The only detection layer a signature rule may use.
_Avoid_: keyword, string

**Signal**:
A deterministic structured fact in a rule's `signals` layer — a safe-feature flag or a relational fact over the NormalizedTrace (origin, capability, sink, canary movement, text structure). The structured core that separates a policy rule from a signature.
_Avoid_: matcher, check, feature flag

**Semantic**:
An engine-local fuzzy-intent check in a rule's `semantics` layer, scored provider-free against a description threshold. Available to policy rules only.
_Avoid_: embedding match, similarity matcher

**Judge check**:
A natural-language question in a rule's `judge` layer, escalated to the FIDES/IFC judge when a policy rule's deterministic layers miss; its verdict feeds back into the rule's condition. The judge is a separate layer, never the quarantined model.
_Avoid_: llm check, fides check, prompt check

**Technique anchor**:
The external standardized identifier(s) a rule maps to in `meta` — ATT&CK (`T*`), ATLAS (`AML.T*`), or D3FEND (`D3-*`) — naming the adversary technique it detects or the defense it provides. Its MITRE **tactic** is the rule's classification/grouping axis (replacing the old bespoke `category` slug). A lookup, not author judgment; the rule's legible statement of intent.
_Avoid_: attack_refs, technique_id, tag, category

**Case→rule mapping**:
The central, public-safe ground-truth layer, authored once per AttackCase, recording which rules should fire (`expected_rule_ids`) and which must not (`should_not_fire_rule_ids`, `benign_near_miss_controls`). The single oracle the eval harness scores rules against — rules do not carry their own test vectors.
_Avoid_: fixtures, per-rule tests, golden cases
