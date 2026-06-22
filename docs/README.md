# CanaryWeave FIDES — documentation

CanaryWeave FIDES is a controlled research harness for detecting **indirect
prompt injection** against MCP-mediated agents. It compares a regex baseline, a
human-reviewable **WARDEN** rule layer, and an optional **FIDES/IFC** layer around
quarantined `query_llm` calls.

New here? Read the [root README](../README.md) for the thesis and quickstart, then
the [architecture overview](architecture/README.md). Domain vocabulary is defined
once in [`CONTEXT.md`](../CONTEXT.md).

## Start here

| Document | What it covers |
|---|---|
| [Architecture overview](architecture/README.md) | The system at three levels — [HLD](architecture/hld.md), [LLD](architecture/lld.md), [DFD](architecture/dfd.md). |
| [Thesis](thesis.md) | The research claim and how the harness substantiates it. |
| [`CONTEXT.md`](../CONTEXT.md) | Canonical glossary (NormalizedTrace, WARDEN, FIDES/IFC, guard stack, fact, rule, case). |
| [Developer guide](guides/developer.md) | Set up, test, run the harness, and verify locally. |
| [Build & run](guides/BUILD_AND_RUN.md) | Install, run, test, and build commands. |

## Architecture & design

| Document | What it covers |
|---|---|
| [Architecture overview](architecture/README.md) | The post-refactor architecture suite and entry point to HLD/LLD/DFD. |
| [HLD](architecture/hld.md) | High-Level Design — system purpose and components. |
| [LLD](architecture/lld.md) | Low-Level Design — modules, classes, algorithms, CLI surface. |
| [DFD](architecture/dfd.md) | Data Flow Diagrams (Level 0–3). |
| [MATH](architecture/math.md) | Mathematical foundations (lattice, similarity, metrics). |
| [GLOSSARY](GLOSSARY.md) | Field-by-field reference for every type, fact, and label. |

## Authoring rules & cases

| Document | What it covers |
|---|---|
| [Rule authoring guide](guides/rule_authoring.md) | How to write `.war` WARDEN rules. |
| [FIDES judge](guides/fides_judge.md) | The FIDES judge contract and modes. |
| [Attack-to-rule mapping](attack_to_rule_mapping.md) | Schema linking attacks to detecting rules. |

## Evaluation & datasets

| Document | What it covers |
|---|---|
| [Running evaluations](guides/running_evals.md) | Running smoke, `warden test`, and full dataset evals. |
| [Datasets](guides/datasets.md) | Dataset adapters and the public/private data contract. |
| [Dataset schema](guides/DATASET_SCHEMA.md) | The WARDEN benchmark dataset schema (MCP request format). |
| [MCP setup](guides/MCP_SETUP.md) | MCP endpoint config, trust model, and crawling. |
| [Case study](CASE_STUDY.md) | Personas, workflows, and empirical results. |

## Decisions (ADRs)

See [`docs/adr/`](adr/README.md) for the full list. The most consequential:

| ADR | Decision |
|---|---|
| [0001](adr/0001-warden-rule-grammar.md) | WARDEN rule grammar. |
| [0002](adr/0002-warden-rule-dsl.md) | WARDEN rule DSL. |
| [0003](adr/0003-collapse-to-facts-and-cases.md) | Collapse to frozen facts and `.cases` — **the refactor the architecture docs describe.** |

## Agent workflows

Conventions for AI agents and contributors working in this repo live in
[`docs/agents/`](agents/domain.md): the [domain model](agents/domain.md), the
[issue tracker](agents/issue-tracker.md) workflow, and [triage labels](agents/triage-labels.md).
