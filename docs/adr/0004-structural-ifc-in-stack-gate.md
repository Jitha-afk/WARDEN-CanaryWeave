# ADR 0004: Structural IFC as an in-stack deterministic gate, plus a `fides_only` stack

## Status

Accepted. Extends [ADR 0003](0003-collapse-to-facts-and-cases.md): the `.war`
rule shape, the six frozen facts, and the `.cases` corpus all carry over
unchanged. This ADR changes how the `rules_plus_fides` stack composes its layers,
adds a fifth guard stack, and fixes the FIDES escalation so the Semantic Judge
fires only on a real pending question.

## Context

Three facts about the code contradicted [CONTEXT.md](../../CONTEXT.md) and each
other:

1. **Structural IFC was dead in the stack.** `FidesIFCLayer` (`fides.py`) — the
   deterministic trusted-action / permitted-flow lattice — was only ever called
   by `query_llm.py` and the smoke-metrics path. `evaluate_stack(rules_plus_fides)`
   never invoked it, yet the glossary called it *"always-on within the stack."*
   The stack's only FIDES component at runtime was the Semantic Judge.

2. **FIDES short-circuited on a WARDEN block.** When a WARDEN rule blocked,
   `evaluate_stack` returned `fides_verdict=not_called` and computed no IFC
   verdict at all — so an operator could never see what IFC *independently*
   concluded about a blocked case, and a researcher could not isolate the IFC
   layer.

3. **The Semantic Judge was over-called.** `ProviderBackedFidesJudge` issued a
   provider call on **every** WARDEN allow, even when no rule had escalated a
   `judge:` question (`pending_checks` empty) — spending Quarantined-LLM calls on
   prompts no rule asked about.

Separately, the project is a showcase for a production deployment pattern (an MCP
proxy / gateway), which needs two **isolated** models kept distinct: the
**Quarantined LLM** (`query_llm`, constrained output, the helper) and the
**Planner LLM** (privileged, the protected target). Conflating them — as the old
"separate from the quarantined model it helps guard" prose did — undermines the
whole argument.

## Decision

### Layer verdicts are always computed; the gate decision is composed

Separate *evaluating a layer* from *deciding the gate*. WARDEN and Structural IFC
are both deterministic and cheap, so both are **always computed and recorded** as
layer verdicts — including when WARDEN already blocked. The gate decision is then
`most_restrictive(WARDEN, Structural IFC, Semantic Judge)` over the layers the
chosen stack includes. "Always-on" is redefined to mean *always evaluated and
recorded*, not *always decisive*.

### Structural IFC gates `rules_plus_fides`

In `rules_plus_fides`, Structural IFC now contributes to the decision: a
trusted-action or permitted-flow violation can block deterministically, recorded
as `blocked_by = fides_ifc`. This is wired into `evaluate_stack`, not recomputed
in the renderer.

### The Semantic Judge fires only on a pending question

The Semantic Judge (the Quarantined LLM in its boolean instance) runs only when
WARDEN allowed, Structural IFC allowed, **and** a rule left a `PendingFidesCheck`.
No pending question ⇒ no provider call ⇒ `fides_verdict = not_called`. This both
fixes the over-call and matches the rule: *"if a rule misses something, pass its
`judge:` question to the Quarantined LLM."*

### A fifth guard stack: `fides_only`

`fides_only` runs Structural IFC alone with WARDEN skipped. Because there are no
rules there are no pending `judge:` questions, so it is pure deterministic lattice
— the isolation a researcher needs to benchmark IFC's standalone
attack-success-rate / false-positive-rate, and the independent-IFC column in the
counterfactual ladder.

### Two isolated models, never conflated

The eval keeps the **Quarantined LLM** and **Planner LLM** as two parallel,
isolated, tool-free Copilot SDK functions. The Quarantined LLM produces the
constrained FIDES verdict; the Planner LLM appears only as a counterfactual
showcase ("had this prompt reached a real planner…"). Neither is given live tool
or side-effect access.

## Consequences

- **Benchmark numbers move.** Structural IFC can now block deterministically in
  `rules_plus_fides`, so per-stack ASR/FPR shifts; `.cases` expectations and the
  smoke baselines are re-pinned to the composed behaviour.
- **Schema additions.** `StackName.FIDES_ONLY`, `BlockedBy.FIDES_IFC`, and a
  recorded Structural-IFC sub-verdict distinct from the semantic `fides_verdict`.
- **Confidentiality stays inert on single prompts.** `judge one` carries no
  restricted-data label, so permitted-flow (P-F) renders `n/a` there; it is the
  axis that matters in an MCP proxy with labelled tool outputs.
- **Deferred.** Letting a rule's `judge:` variable declare a richer constrained
  output (boolean | enum | field-extraction) for the Quarantined LLM is a DSL +
  `JudgeCheck` schema change recorded in a later ADR, not this one.
