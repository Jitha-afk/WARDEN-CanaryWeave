# Low-Level Design (LLD) — WARDEN-CanaryWeave FIDES

## 1. Module Inventory

```
src/canaryweave_fides/
├── __init__.py              # Public API exports (59 lines)
├── lattice.py               # Formal IFC lattice: Lattice ABC, IntegrityLattice,
│                            #   ConfidentialityLattice, PowersetLattice, ProductLattice
├── variable_store.py        # Variable Memory: VariableStore, StoredVariable,
│                            #   store_if_untrusted()
├── autonomy_metrics.py      # PRUDENTIA metrics: TaskTrace, hitl_load(), tcr_at_k()
│
├── models.py                # Core data models: TraceEvent, PolicyContext,
│                            #   EvaluationRecord, RuleHit, PendingFidesCheck,
│                            #   RuleDecision, FidesVerdict, QueryResult
├── decisions.py             # Enums: StackName, Decision, BlockedBy, FidesVerdict,
│                            #   GateDecision
│
├── fact_registry.py         # 6 frozen facts: FactSpec, FROZEN_FACTS, is_fact()
├── normalization.py         # Text features: hidden_unicode, instruction_shape,
│                            #   high_entropy, normalize_text()
├── semantics.py             # Provider-free similarity: token cosine + SequenceMatcher
│
├── rule_schema.py           # DSL schema: RuleDefinition, PatternDef, SemanticPattern,
│                            #   JudgeCheck, TechniqueRef, validate_rule()
├── rule_loader.py           # .war parser: tokenize → validate → RuleDefinition[]
├── rule_engine.py           # Evaluation: build_evaluation_record(), RuleEngine,
│                            #   _compute_fact(), _eval_condition()
│
├── fides.py                 # FIDES Structural IFC: FidesIFCLayer.evaluate()
│                            #   using lattice leq() for P-T and P-F policies
├── fides_prompt.py          # Judge prompt builder: build_fides_judge_prompt(),
│                            #   parse_fides_judge_response()
├── gate.py                  # Gate orchestration: evaluate_stack(), FidesJudge protocol,
│                            #   StaticFidesJudge, ProviderBackedFidesJudge
├── query_llm.py             # Quarantined LLM: preflight → model → postflight → IFC
│
├── cases.py                 # AttackCase, CaseKind, ExpectedBehavior, GroundTruth
├── cases_dsl.py             # .cases parser: parse_cases() → CaseExample[]
├── facts.py                 # NormalizedFacts: from_attack_case(), to_dict()
├── fixtures.py              # Smoke cases for legacy report
│
├── config.py                # LoadedEvalConfig from YAML
├── runner.py                # EvaluationRunConfig, run orchestration, CSV output
├── reporting.py             # Public report: security metrics, coverage, disagreement
├── metrics.py               # Smoke metrics: ASR, F1, precision, recall per stack
├── rich_report.py           # Rich terminal rendering: render_warden_rule_check()
├── cli.py                   # CLI entry points: smoke, provider, warden, judge, bench, eval
├── resources.py             # Path resolution: rules_root(), conf_root(), data_root()
├── mappings.py              # Case→rule mapping validation
│
├── adapters/                # Dataset adapters
│   ├── base.py              #   AdapterConfig, DatasetAdapter ABC, AdapterResult
│   ├── synthetic.py         #   Hardcoded public-safe test cases
│   ├── asb.py               #   ASB dataset adapter
│   ├── agentdefensebench.py #   AgentDefenseBench thin subclass
│   └── identifiers.py       #   HMAC ID/hash helpers
│
├── providers/               # LLM provider backends
│   ├── base.py              #   JudgeProviderConfig, ProviderJudgeResponse, JudgeProvider
│   ├── copilot_sdk.py       #   CopilotSdkJudgeProvider: SDK + REST fallback, complete()
│   └── fake.py              #   Fixed-response fake for tests
│
└── simulators/              # API/MCP simulation helpers
    ├── base.py              #   SimulationResult, evaluate via rules_plus_fides
    ├── api.py               #   API/chat simulator
    └── mcp.py               #   MCP content simulator
```

## 2. Class Relationships

```
                    ┌─────────────────┐
                    │   Lattice (ABC)  │
                    └────────┬────────┘
            ┌───────────────┼────────────────┐
            ▼               ▼                ▼
  IntegrityLattice  ConfidentialityLattice  PowersetLattice
    {T ⊑ U}           {L ⊑ H}             {inverse subset}
            └───────────────┼────────────────┘
                            ▼
                    ProductLattice(left, right)
                            │
                            ▼
              ┌─────────────────────────────┐
              │     FidesIFCLayer            │
              │  evaluate(trace, policy)     │
              │  uses: leq(), join()         │
              └─────────────────────────────┘

  ┌──────────────────┐     ┌──────────────────────┐
  │  RuleDefinition  │     │  EvaluationRecord    │
  │  id, name, ...   │     │  text: str           │
  │  patterns[]      │     │  facts: {6 booleans} │
  │  semantics[]     │     └──────────┬───────────┘
  │  judge_checks[]  │                │
  │  condition: str  │                ▼
  └────────┬─────────┘     ┌──────────────────────┐
           │               │    RuleEngine         │
           └──────────────►│  evaluate_record()    │
                           │  → RuleDecision       │
                           │    hits[]             │
                           │    pending_fides[]    │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │     Gate (gate.py)    │
                           │  evaluate_stack()     │
                           │  → GateDecision       │
                           └──────────┬───────────┘
                                      │
                              ┌───────┴────────┐
                              ▼                ▼
                    ┌─────────────┐   ┌──────────────────┐
                    │FidesIFCLayer│   │  FidesJudge      │
                    │(structural) │   │  (LLM on miss)   │
                    └─────────────┘   └──────────────────┘

  ┌──────────────────┐
  │  VariableStore   │
  │  store() → $VAR_n│
  │  retrieve()      │
  │  redacted_view() │
  └──────────────────┘
```

## 3. Key Data Structures

### TraceEvent (models.py)
```python
@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    origin: str                           # "resource_content" | "tool_output" | "user" | ...
    surface: str                          # "resource" | "prompt" | "tool_result"
    text: str = ""                        # raw content
    schema_shape: str | None = None       # "tool_plan_like_json" | None
    capability: str | None = None         # requested tool/capability
    sink: str | None = None               # target sink for data flow
    canary_present: bool = False
    integrity: "high" | "low" = "high"
    confidentiality: "public" | "restricted" = "public"
    consequential_action: bool = False
```

### EvaluationRecord (models.py)
```python
@dataclass(frozen=True)
class EvaluationRecord:
    text: str = ""
    facts: Mapping[str, bool] = {}
    # facts = {
    #   "from_untrusted_origin": bool,
    #   "capability_denied": bool,
    #   "canary_outside_sink": bool,
    #   "tool_call_shape": bool,
    #   "hidden_unicode": bool,
    #   "instruction_shape": bool,
    # }
```

### RuleDefinition (rule_schema.py)
```python
@dataclass(frozen=True)
class RuleDefinition:
    id: str                              # "cwfr-0001"
    name: str                            # "ServerSamplingOriginBoundary"
    version: str
    severity: str                        # "low" | "medium" | "high" | "critical"
    scope: str                           # "event_window" | "text_field" | "trace"
    description: str
    action: str                          # "allow" | "audit" | "quarantine" | "block_and_audit"
    tactic: str                          # MITRE tactic from technique anchor
    technique: tuple[TechniqueRef, ...]  # ATT&CK / ATLAS / D3FEND
    defense: tuple[TechniqueRef, ...]
    condition: str                       # boolean expression over $terms
    patterns: tuple[PatternDef, ...]     # regex / exact substring
    facts: tuple[str, ...]               # referenced frozen facts
    semantics: tuple[SemanticPattern, ...]  # similarity checks
    judge_checks: tuple[JudgeCheck, ...]   # FIDES judge questions
```

### GateDecision (decisions.py)
```python
@dataclass(frozen=True)
class GateDecision:
    stack: StackName
    decision: Decision                   # ALLOW | QUARANTINE | BLOCK
    blocked_by: BlockedBy = NONE         # REGEX | YARA_RULE | FIDES_JUDGE | NONE
    rule_ids: tuple[str, ...] = ()
    fides_verdict: FidesVerdict = NOT_CALLED
    reason_codes: tuple[str, ...] = ()
    latency_ms: float | None = None
    provider_calls: int = 0
```

## 4. Rule Evaluation Algorithm

```
INPUT: EvaluationRecord{text, facts}
FOR each RuleDefinition in corpus:
    1. Evaluate patterns: regex/exact match against text → bool per pattern
    2. Resolve facts: lookup each referenced $fact from record.facts
    3. Evaluate semantics: token cosine similarity ≥ threshold → bool
    4. Set judge terms = False (deterministic pass)
    5. Expand quantifiers: "any of patterns" → OR over pattern terms
    6. Evaluate condition: boolean expression → hit or miss

    IF hit:
        Append RuleHit{rule_id, severity, action, signals, evidence}

    IF miss AND rule has judge terms:
        Hypothetically set judge terms = True
        IF condition would fire with judge = True:
            Emit PendingFidesCheck{rule_id, judge_questions}

OUTPUT: RuleDecision{hits[], final_action, pending_fides[]}
```

## 5. FIDES Judge Escalation Flow

```
INPUT: NormalizedFacts, PendingFidesCheck[]

1. Build judge prompt:
   - raw text from facts
   - 6 boolean facts
   - rule questions from each PendingFidesCheck

2. Send to provider:
   - CopilotSdkJudgeProvider.judge(prompt)
   - SDK path: CopilotClient → create_session → send_and_wait
   - REST fallback: POST models.github.ai/inference/chat/completions

3. Parse response:
   - Extract JSON {verdict, confidence, reason_codes, recommended_decision}
   - On parse failure: verdict = uncertain, decision = quarantine

4. Map to GateDecision:
   - unsafe → BLOCK
   - uncertain → QUARANTINE
   - safe → ALLOW
```

## 6. Condition Expression Grammar

```
condition   := expr
expr        := term | expr "and" expr | expr "or" expr | "not" expr | "(" expr ")"
term        := "$" identifier
quantifier  := ("any" | "all") "of" ("patterns" | "semantics" | "judge" | "them")
             | ("any" | "all") "of" "(" term_list ")"
term_list   := term ("," term)*
```

Built-in facts: `$from_untrusted_origin`, `$capability_denied`, `$canary_outside_sink`, `$tool_call_shape`, `$hidden_unicode`, `$instruction_shape`
