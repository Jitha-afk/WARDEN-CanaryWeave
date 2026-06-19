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
| [Developer guide](developer.md) | Set up, test, run the harness, and verify locally. |

## Architecture & design

| Document | What it covers |
|---|---|
| [Architecture: HLD / LLD / DFD](architecture/README.md) | The post-refactor architecture suite, including the [known gaps](architecture/README.md#known-gaps). |
| [`design/rule_schema.md`](../design/rule_schema.md) | Authoritative WARDEN `.war` rule DSL schema. |
| [`design/query_llm_gate.md`](../design/query_llm_gate.md) | The `query_llm` gate (Path A) contract. |
| [`design/evaluation_methodology.md`](../design/evaluation_methodology.md) | Regex vs structured rules vs rules+FIDES methodology on ASB. |
| [`design/multi_dataset_harness_architecture.md`](../design/multi_dataset_harness_architecture.md) | Multi-dataset harness design (planning draft). |
| [`design/next_phase_vigil_style_harness_plan.md`](../design/next_phase_vigil_style_harness_plan.md) | Forward plan for a Vigil-style multi-dataset gate harness. |

## Authoring rules & cases

| Document | What it covers |
|---|---|
| [Rule authoring guide](rule_authoring.md) | How to write `.war` WARDEN rules. |
| [FIDES judge](fides_judge.md) | The FIDES judge contract and modes. |
| [Attack-to-rule mapping](attack_to_rule_mapping.md) | Schema linking attacks to detecting rules. |
| [LLM threat rule coverage map](llm_threat_rule_mapping.md) | Coverage map for the `cwfr-llm-*` rule family. |

## Evaluation & datasets

| Document | What it covers |
|---|---|
| [Running evaluations](running_evals.md) | Running smoke, `warden test`, and full dataset evals. |
| [Datasets](datasets.md) | Dataset adapters and the public/private data contract. |
| [Demo plan](demo_plan.md) | Walkthrough for demonstrating the harness. |
| [Next-phase controlled evidence plan](next_phase_controlled_evidence_plan.md) | Plan for controlled-dataset evidence. |

## Research & review

| Document | What it covers |
|---|---|
| [Initial research report](initial_research_report.md) | Controlled multi-dataset evidence draft. |
| [Peer review report](peer_review_report.md) | Review of the harness. |
| [Paper peer review](paper_peer_review.md) | Review of the paper draft. |

## Developer & tooling

| Document | What it covers |
|---|---|
| [Developer guide](developer.md) | Prerequisites, tests, harness commands, local verification. |
| [GitHub workflows](workflows.md) | CI workflow notes. |
| [VS Code](vscode.md) · [Dev container / Codespaces](devcontainer.md) | Editor and container setup. |
| [`pyproject.toml` notes](pyproject.md) · [pre-commit config](pre-commit-config.md) · [pylint config](pylint.md) | Project and lint tooling reference. |
| [API reference (Sphinx)](index.rst) | Autodoc-level API reference for `canaryweave_fides`. |

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
