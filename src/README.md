This directory holds the `canaryweave_fides` Python package.

# `canaryweave_fides`

The CanaryWeave FIDES harness: a deterministic WARDEN rule engine, the FIDES/IFC
layer, the quarantined `query_llm` gate, the dataset/`.cases` evaluation paths, and
the CLI. For the architecture, read [`docs/architecture/`](../docs/architecture/README.md);
for domain vocabulary, read [`CONTEXT.md`](../CONTEXT.md).

## Package layout

```text
canaryweave_fides/
├── cli.py             # `python -m canaryweave_fides.cli` command tree
├── fact_registry.py   # the six frozen facts (closed vocabulary)
├── normalization.py   # text-feature helpers (hidden unicode, instruction shape)
├── semantics.py       # provider-free fuzzy-intent scoring (best_score)
├── rule_loader.py     # .war text -> structured rule dicts
├── rule_schema.py     # RuleDefinition + pattern/semantic/judge/technique types
├── rule_engine.py     # RuleEngine, build_evaluation_record, fact computation
├── models.py          # TraceEvent, EvaluationRecord, RuleHit, QueryResult, ...
├── query_llm.py       # Path A: preflight -> model stub -> postflight -> IFC
├── fides.py           # FidesIFCLayer (deterministic information-flow checks)
├── decisions.py       # StackName, Decision, GateDecision, FidesVerdict (enum)
├── facts.py           # NormalizedFacts (Path B gate input from an AttackCase)
├── gate.py            # Path B: evaluate_stack/evaluate_case + FidesJudge family
├── fides_prompt.py    # FIDES judge prompt builder + response parser
├── cases.py           # AttackCase, GroundTruth, ExpectedBehavior
├── cases_dsl.py       # .cases corpus parser
├── runner.py          # run_evaluation (iterations x stacks x datasets)
├── metrics.py         # legacy smoke summary (summarize_smoke)
├── reporting.py       # modern public report (build_public_report)
├── rich_report.py     # Rich console rendering for `warden check`
├── config.py          # YAML eval-config loading
├── fixtures.py        # legacy smoke fixtures
├── resources.py       # packaged-asset resolution (rules_root)
├── mappings.py        # taxonomy / label mapping helpers
├── adapters/          # DatasetAdapter base + synthetic / ASB / AgentDefenseBench
├── providers/         # JudgeProvider base + Copilot SDK + fake providers
├── simulators/        # simulate_case + API / MCP simulation wrappers
└── assets/            # packaged rule and config assets
```

## Two evaluation paths, one core

Both the `query_llm` gate (`query_llm.py`) and the stack gate (`gate.py`) project
their normalized window onto a flat `EvaluationRecord{text, facts}` and run the
same `RuleEngine`. See the [HLD](../docs/architecture/hld.md) for the picture and
the [LLD](../docs/architecture/lld.md) for the module-by-module detail.

