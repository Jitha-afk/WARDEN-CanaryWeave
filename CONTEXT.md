# CanaryWeave FIDES

Controlled research POC comparing guard stacks — a regex/signature baseline, a defender-authored structured WARDEN rule layer, and an optional FIDES/IFC layer — around quarantined `query_llm` calls. This glossary fixes the language those guards share.

## Language

### Traces, guards, and gates

**NormalizedTrace**:
The framework-internal record that carries the raw text plus structured context (origin, surface, capability, sink, canary movement, integrity/confidentiality labels) and populates the evaluation record's facts. Built synthetically today, from MCP wire later. Rules and test cases never construct it.
_Avoid_: NormalizedFacts, TraceEvent, trace record

**Evaluation record**:
The flat `{text, facts}` a rule actually evaluates: the raw prompt/tool text plus the six framework-computed facts. The only surface rules and test cases touch.
_Avoid_: trace, event, normalized facts

**Feature**:
A precomputed structural boolean or label (e.g. `command_execution_shape`) derived from raw content and carried on the NormalizedTrace, consumed when the framework computes facts or runs the dumb regex baseline. Not author-facing.
_Avoid_: safe feature, flag, text feature

**WARDEN**:
The deterministic rule stack — regex baseline, YARA-style manifests, and `.war` structured rules — that evaluates a NormalizedTrace into a decision.
_Avoid_: rule service, detector engine

**FIDES/IFC**:
The optional layer applied only after WARDEN allows, in the `rules_plus_fides` stack, in two parts: (1) an always-on deterministic structural check — trusted-action (consequential actions must not stem from low-integrity or untrusted-origin data) and permitted-flow (restricted data may only reach permitted sinks); (2) the LLM judge, queried with the raw text, the facts, and the rule's `judge:` question. Separate from the quarantined model it helps guard.
_Avoid_: guardrail, LLM gate

**Guard stack**:
A named evaluation configuration compared apples-to-apples on the same NormalizedTrace: `no_guard`, `regex_baseline`, `yara_rules`, `rules_plus_fides`.
_Avoid_: pipeline, guard layer; the README's `regex_guard` / `structured_rule_guard` / `rules_plus_fides_ifc` (use the StackName values)

**Gate**:
The quarantined `query_llm` enforcement point: runs a guard stack as preflight, calls the quarantined model, runs the stack again as postflight, then FIDES — composing one shared evaluation core rather than re-sequencing it.
_Avoid_: handler, middleware

**AttackCase**:
The case envelope (attack type, raw detail, expected outcome, policy context) a NormalizedTrace is derived from. Carries the raw prompt/tool text so a reader can see exactly what led to what outcome.
_Avoid_: sample, example

**Canary**:
A marked token whose appearance outside an allowed sink signals exfiltration across a guard seam.
_Avoid_: honeytoken, marker

### Rule vocabulary

A `.war` ruleset is a file of `rule {}` blocks. Each rule declares its identity in `meta` (including a technique anchor), one or more detection layers, and a boolean `condition`. There is one rule shape; a rule's character is descriptive — a patterns-only rule is a brittle signature, a rule that reasons over facts/semantics/judge is a structured policy — never a declared kind. A rule carries no test vectors of its own; ground truth lives in the `.cases` corpus.

**Rule**:
A single `rule {}` block: `meta` identity plus one or more detection layers (`patterns`, `facts`, `semantics`, `judge`) combined by a boolean `condition`. There is no `signature`/`policy` kind — brittleness vs structure is read from which layers a rule uses. The brittle-vs-structured comparison lives at the guard-stack level, not on the rule.
_Avoid_: signature rule, policy rule, kind, smart rule, dumb rule

**Pattern**:
A deterministic text matcher (exact or regex) in a rule's `patterns` layer, evaluated over the raw text. A rule using only patterns is a brittle signature.
_Avoid_: keyword, string

**Fact**:
A framework-computed boolean exposed to a rule as a plain condition term, drawn from a small frozen, framework-owned vocabulary — currently `from_untrusted_origin`, `capability_denied`, `canary_outside_sink`, `tool_call_shape`, `hidden_unicode`, `instruction_shape`. Facts carry the structural trust/flow/message-shape reasoning a rule cannot derive from text alone. Authors reference facts but never define them; a new fact is a documented framework change grounded in the MCP specification, never an authoring task.
_Avoid_: signal, safe-feature flag, IFC signal

**Semantic**:
An engine-local fuzzy-intent check in a rule's `semantics` layer, scored provider-free against a description threshold. Carries the "does this text look like intent X?" classifications (command execution, path-boundary, social engineering, …) that authors write over text.
_Avoid_: embedding match, similarity matcher

**Judge check**:
A natural-language question in a rule's `judge` layer, escalated to the FIDES/IFC judge LLM when a rule's deterministic layers miss. The judge prompt carries the raw text, the facts, and the question itself; the verdict feeds back into the rule's condition. The judge LLM is separate from the quarantined model.
_Avoid_: llm check, fides check, prompt check

**Technique anchor**:
The external standardized identifier(s) a rule maps to in `meta` — ATT&CK (`T*`), ATLAS (`AML.T*`), or D3FEND (`D3-*`) — naming the adversary technique it detects or the defense it provides. Its MITRE **tactic** is the rule's classification/grouping axis (replacing the old bespoke `category` slug). A lookup, not author judgment; the rule's legible statement of intent.
_Avoid_: attack_refs, technique_id, tag, category

**Case**:
One `"detail" -> block | allow` line in a `.cases` file: a raw prompt/tool text plus its expected guard-stack outcome. The atomic test and benchmark unit. A rule carries no test vectors of its own.
_Avoid_: fixture, golden case, test vector

**Attack type**:
A `cases {}` block grouping cases that share a structural fact profile, declared in the block header (`[$from_untrusted_origin, $capability_denied]`, omitted = none). Sets the structural facts the framework applies to those cases; text-derived facts are computed per `detail`.
_Avoid_: category, scenario, label

**Benchmark**:
The full `.cases` corpus run across every guard stack (`no_guard → regex_baseline → yara_rules → rules_plus_fides`); the per-stack attack-success-rate / false-positive-rate table is the eval. The same corpus is both the unit tests and the benchmark. `expected` is the stack outcome; which rule fired is a diagnostic, not the oracle.
_Avoid_: eval set, test suite, golden set
