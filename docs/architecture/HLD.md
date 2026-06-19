# High-Level Design (HLD) — WARDEN-CanaryWeave FIDES

## 1. System Purpose

WARDEN-CanaryWeave is a deterministic security evaluation harness that implements the FIDES (Flow Integrity Deterministic Enforcement System) architecture for AI agents. It provides:

- **WARDEN**: A YARA-style structured rule engine for detecting prompt injection, data exfiltration, and agentic abuse
- **FIDES Structural IFC**: Formal information-flow control using lattice-based integrity/confidentiality labels
- **FIDES Semantic Judge**: LLM-as-judge escalation for attacks that bypass deterministic patterns
- **Benchmark Pipeline**: Stack-level comparison (no_guard → regex → WARDEN → WARDEN+FIDES)

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL INPUTS                                 │
│  User prompts, .cases corpus, dataset adapters (ASB, AgentDefenseBench)│
└──────────────────────────────┬────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     NORMALIZATION LAYER                                │
│                                                                       │
│  AttackCase → NormalizedFacts → TraceEvent + PolicyContext             │
│  (origin, trust, features, requested capabilities, policy)            │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     EVALUATION GATE                                    │
│                                                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │  no_guard   │  │regex_baseline│  │ yara_rules  │  │rules_plus_ │  │
│  │  (allow all)│  │(canary/obfusc│  │  (WARDEN)   │  │   fides    │  │
│  └─────────────┘  └─────────────┘  └──────┬──────┘  └─────┬──────┘  │
│                                            │               │          │
│                                            ▼               ▼          │
│                                    ┌──────────────┐ ┌────────────┐   │
│                                    │ Rule Engine  │ │FIDES Judge │   │
│                                    │ (deterministic)│(LLM on miss)│   │
│                                    └──────────────┘ └────────────┘   │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     QUARANTINED LLM PATH                              │
│                                                                       │
│  QueryRequest → Preflight → Model Call → Postflight → FIDES IFC      │
│  (Variable Memory hides untrusted data behind $VAR_n handles)         │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     OUTPUT LAYER                                       │
│                                                                       │
│  GateDecision → Runner → Metrics (ASR, F1, TCR@k) → Reports          │
└──────────────────────────────────────────────────────────────────────┘
```

## 3. Key Design Decisions

| Decision | Rationale |
|---|---|
| YARA-style `.war` DSL | Defenders author reviewable, declarative rules without code |
| 6 frozen facts (not extensible by authors) | Bounds the reasoning surface; new facts = framework change |
| FIDES judge only on WARDEN miss | Efficiency: LLM calls are expensive; deterministic rules catch most attacks |
| Variable Memory with $VAR_n handles | Prevents prompt injection by hiding untrusted content from planner |
| Formal lattice for IFC | Provable security properties: `leq`/`join`/`meet` operations |
| Dual LLM pattern | Planning LLM (trusted context) + Quarantined LLM (processes hidden variables) |
| 4-stack comparison | Measures incremental value of each defense layer |

## 4. Security Properties

1. **Trusted Action (P-T)**: Consequential actions require `integrity ⊑ T` (trusted context)
2. **Permitted Flow (P-F)**: Restricted data flows only to permitted sinks
3. **Deterministic Enforcement**: No probabilistic guessing — policy violations are provably blocked
4. **Conservative Default**: Unknown/uncertain → quarantine (ask human)

## 5. Component Boundaries

| Component | Responsibility | Interface |
|---|---|---|
| Rule Engine | Evaluate .war rules against EvaluationRecord | `evaluate_record(record) → RuleDecision` |
| FIDES IFC Layer | Lattice-based trusted-action + permitted-flow checks | `evaluate(trace, policy) → FidesVerdict` |
| FIDES Judge | LLM escalation for PendingFidesCheck | `judge(facts, rule_checks) → FidesJudgeResult` |
| Variable Store | Selective hiding behind opaque handles | `store(content, label) → $VAR_n` |
| Gate | Orchestrate stacks, route to FIDES on miss | `evaluate_stack(facts, stack) → GateDecision` |
| Runner | Iterate adapters × cases × stacks | `run(config) → report` |

## 6. External Dependencies

| Dependency | Purpose | Required |
|---|---|---|
| PyYAML | Config/eval YAML loading | Yes |
| Rich | Terminal rendering | Yes |
| github-copilot-sdk | Real quarantined LLM + FIDES judge | Optional (for `copilot_sdk` mode) |
| requests | REST fallback for GitHub Models API | Optional (fallback) |
