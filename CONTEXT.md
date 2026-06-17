# CanaryWeave FIDES

Controlled research POC comparing guard stacks — a regex/signature baseline, a defender-authored structured WARDEN rule layer, and an optional FIDES/IFC layer — around quarantined `query_llm` calls. This glossary fixes the language those guards share.

## Language

**NormalizedTrace**:
The neutral audit record every guard stack evaluates: a case-level envelope plus an ordered sequence of normalized events, each carrying structured fields (origin, surface, capability, sink, canary movement, integrity/confidentiality labels) and a safe-features map. Raw text stays in controlled custody; public exports are redacted and feature-only.
_Avoid_: NormalizedFacts, TraceEvent, trace record

**Safe feature**:
A structural boolean or label (e.g. `instruction_shape`, `hidden_unicode`, `command_execution_shape`) derived once from raw content at the custody boundary and carried on the NormalizedTrace. Guards read safe features; they never re-derive them from raw payloads.
_Avoid_: flag, text feature

**Signal**:
The rule-side predicate a `.war` rule evaluates against a NormalizedTrace (e.g. `feature_flag`, `capability_policy`, `canary_flow`). A signal reads safe features and structured fields, not fabricated text.
_Avoid_: matcher, check

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
