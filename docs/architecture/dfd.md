# Data Flow Diagrams (DFD)

> **Scope.** How data moves through CanaryWeave FIDES, from external input to
> decision and report. Read the [HLD](hld.md) for the component picture and the
> [LLD](lld.md) for the data structures named below. Terms follow
> [`CONTEXT.md`](../../CONTEXT.md).
>
> **Legend.** Rectangles are processes, cylinders are data stores, rounded nodes
> are external entities. A store tagged **(private)** never leaves the process
> boundary in cleartext; a store tagged **(public)** is safe to publish. The
> public/private split is the framework's core data-handling contract.

## 1. Level 0 — context

```mermaid
flowchart TB
    author(["Rule author"])
    operator(["Operator / CI"])
    datasets(["External corpora<br/>ASB, AgentDefenseBench"])
    provider(["Copilot SDK provider<br/>(optional, off by default)"])

    system["CanaryWeave FIDES"]

    reports[("Public reports<br/>& artifacts (public)")]
    raw[("Raw attack payloads<br/>(private)")]

    author -->|".war rules, .cases corpora"| system
    operator -->|"prompts, CLI invocations"| system
    datasets -->|"local files (env-gated)"| system
    system -->|"judge prompt (opt-in)"| provider
    provider -->|"verdict JSON"| system
    system -->|"decisions, metrics"| reports
    system -.->|"hashed, never published"| raw
```

The framework runs fully offline by default. The provider edge is dashed-in only
when `--fides-mode copilot_sdk --provider-calls-enabled --model …` are all set.

## 2. Level 1 — the two evaluation paths

```mermaid
flowchart TB
    subgraph inputs["Inputs"]
      prompt["Prompt / trace"]
      corpus[".cases corpus"]
      dsfiles["Dataset files"]
    end

    subgraph pathA["Path A — query_llm gate"]
      pre["Preflight RuleEngine"]
      stub["Quarantined model stub"]
      post["Postflight RuleEngine"]
      ifc["FidesIFCLayer<br/>(deterministic IFC)"]
      qr["QueryResult"]
      pre --> stub --> post --> ifc --> qr
    end

    subgraph pathB["Path B — stack gate"]
      norm["NormalizedFacts"]
      stacks["evaluate_stack<br/>(4 StackNames)"]
      gd["GateDecision"]
      norm --> stacks --> gd
    end

    subgraph shared["Shared core"]
      rec["EvaluationRecord{text, facts}"]
      engine["RuleEngine.evaluate_record"]
      rec --> engine
    end

    prompt --> pre
    corpus --> norm
    dsfiles --> norm
    pre -.projects.-> rec
    post -.projects.-> rec
    stacks -.projects.-> rec
    engine -.RuleDecision.-> pre
    engine -.RuleDecision.-> post
    engine -.RuleDecision.-> stacks
    gd --> runner["run_evaluation"]
    runner --> report["build_public_report"]
```

Both paths project their normalized window to the same `EvaluationRecord` and run
the same `RuleEngine`; they differ only in what wraps the core and what result
envelope they return (`QueryResult` vs `GateDecision`).

## 3. Level 2 — rule evaluation (the shared core)

```mermaid
flowchart TB
    rec["EvaluationRecord{text, facts}"]
    subgraph perRule["For each RuleDefinition"]
      pat["pattern terms<br/>(exact / regex over text)"]
      fact["fact terms<br/>(record.fact name)"]
      sem["semantic terms<br/>(best_score >= threshold)"]
      judge["judge terms = False"]
      cond["evaluate condition<br/>(quantifiers -> safe eval)"]
      base{"baseline hit?"}
      esc{"would fire if<br/>judge terms True?"}
    end
    hit["RuleHit"]
    pend["PendingFidesCheck"]
    dec["RuleDecision<br/>{hits, final_action, pending_fides}"]

    rec --> pat & fact & sem & judge --> cond --> base
    base -->|yes| hit --> dec
    base -->|no| esc
    esc -->|yes| pend --> dec
    esc -->|no| dec
```

`final_action` is the most-restrictive action over all hits (block ▸ quarantine ▸
allow). `pending_fides` carries the rule questions that only a judge can resolve —
the seam Path B uses next.

## 4. Level 2 — FIDES routing inside `rules_plus_fides`

```mermaid
flowchart TB
    facts["NormalizedFacts"]
    warden["WARDEN (yara_rules) over RuleEngine"]
    wdec{"WARDEN decision"}
    notcalled["GateDecision<br/>fides_verdict = not_called"]
    judge["FidesJudge.judge<br/>(pending checks as context)"]
    mode{"judge mode"}
    disabled["disabled -> verdict disabled"]
    testdouble["test_double -> fixture verdict"]
    sdk["copilot_sdk -> provider call"]
    merge["more-restrictive(<br/>verdict, recommended)"]
    out["GateDecision<br/>blocked_by = fides_judge"]

    facts --> warden --> wdec
    wdec -->|block / quarantine| notcalled
    wdec -->|allow| judge --> mode
    mode --> disabled & testdouble & sdk
    disabled & testdouble & sdk --> merge --> out
```

> **Note the routing.** When WARDEN already blocks or quarantines, the judge is
> short-circuited (`not_called`). The judge is consulted only on the WARDEN-allow
> branch. The deterministic `FidesIFCLayer` is **not** in this flow — see
> [§7](#7-known-gaps-data-view).

## 5. Level 2 — `.cases` corpus flow (`warden test`)

```mermaid
flowchart LR
    file[".cases file"]
    parse["parse_cases"]
    examples["CaseExample[]<br/>(header facts + detail -> block/allow)"]
    convert["case_example_to_attack_case"]
    case["AttackCase + GroundTruth"]
    eval["evaluate_case over 4 stacks"]
    cmp["compare stack decision<br/>vs expected behavior"]
    table["per-stack pass/fail table"]

    file --> parse --> examples --> convert --> case --> eval --> cmp --> table
```

The oracle is the **stack outcome** (block/allow), not a specific rule id — a case
passes when the stack's decision matches the expected behavior.

## 6. Level 2 — dataset evaluation flow (`eval`)

```mermaid
flowchart TB
    cfg["EvaluationRunConfig"]
    subgraph adapters["DatasetAdapter.load (per dataset)"]
      syn["SyntheticAdapter<br/>(always loaded)"]
      asb["ASBAdapter<br/>(CANARYWEAVE_ASB_ROOT)"]
      adb["AgentDefenseBenchAdapter<br/>(env-gated)"]
    end
    cases["AttackCase[]"]
    rawstore[("private_data<br/>raw payloads (private)")]
    ids["HMAC identifiers (public)"]
    run["run_evaluation<br/>iterations x stacks x cases"]
    decisions["GateDecision[]"]
    public["build_public_report<br/>(public_report.v1)"]
    artifact[("artifacts/evals/*.json (public)")]

    cfg --> adapters --> cases
    cases -.raw kept out of to_dict.-> rawstore
    cases -->|opaque id| ids
    cases --> run --> decisions --> public --> artifact
    ids --> public
```

Adapters hash raw material into opaque identifiers (override key via
`CANARYWEAVE_PUBLIC_HMAC_KEY`) and keep raw payloads in `private_data`, which is
excluded from every `to_dict`. Missing env-gated datasets resolve to a
`skipped_missing_local_path` result rather than an error.

## 7. Known gaps (data view)

These are data-flow consequences of the ADR 0003 refactor, surfaced for honesty
(cross-referenced from the [HLD gap table](hld.md#8-known-post-refactor-gaps)):

| # | Gap | Data-flow impact |
|---|---|---|
| 1 | `FidesIFCLayer` absent from `rules_plus_fides` | The deterministic IFC checks (trusted_action, permitted_flow) never run in Path B. ADR 0003 intends IFC stays always-on; only the LLM judge runs today. |
| 2 | Divergent stack vocabulary | `metrics.summarize_smoke` emits `regex_guard / structured_rule_guard / rules_plus_fides_ifc`; `build_public_report` emits canonical `StackName`. A consumer joining the two reports must map names by hand. |
| 3 | Two fact representations | `facts.NormalizedFacts` (Path B input) and `models.EvaluationRecord` (rule input) both describe "the facts", bridged by `_facts_to_trace_and_policy`. A reader tracing data must cross the bridge to follow a value. |
| 4 | `TraceEvent` is synthetic today | Every fact is derived from a framework-built `TraceEvent`, not yet from the MCP wire. The projection seam (`build_evaluation_record`) is where real MCP data will later enter. |

## Related documents

- [High-Level Design](hld.md) · [Low-Level Design](lld.md)
- [ADR 0003](../adr/0003-collapse-to-facts-and-cases.md) — the refactor of record.
- [`automation/mitre/README.md`](../../automation/mitre/README.md) — the MITRE
  enrichment data flow (separate offline pipeline).
