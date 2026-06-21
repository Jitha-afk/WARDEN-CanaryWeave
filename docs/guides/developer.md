# Developer Guide

How to set up, test, and extend CanaryWeave FIDES. For the architecture see
[`docs/architecture/`](architecture/README.md); for domain vocabulary see
[`CONTEXT.md`](../CONTEXT.md).

## Prerequisites

- **Python 3.10+** for the core harness.
- **[`uv`](https://docs.astral.sh/uv/)** for reproducible local execution.
- **Python 3.11+** only if you install the optional GitHub Copilot SDK FIDES
  provider (`pip install -e '.[copilot]'`).

The package is `canaryweave_fides`, sourced from `src/` (see
[`src/README.md`](../src/README.md) for the package map). Tests live in `tests/`
and run with `pythonpath = ["src"]` configured in `pyproject.toml`.

## Running the tests

```bash
uv run --with pytest pytest -q
```

The suite is provider-free and offline by default. Live provider tests require the
optional `copilot` extra and explicit opt-in flags (see below).

## Running the harness

```bash
# Legacy smoke run (exercises FidesIFCLayer); writes artifacts/smoke_report.json
uv run python -m canaryweave_fides.cli --fixture-set smoke --output artifacts/smoke_report.json

# Stack-level eval over a .cases corpus across all four guard stacks
uv run python -m canaryweave_fides.cli warden test --input data/cases/smoke.cases

# Scan a single prompt through the WARDEN (yara_rules) stack
uv run python -m canaryweave_fides.cli warden check --prompt "..." --origin tool_output --trust untrusted

# WARDEN + deterministic FIDES test double on one prompt
uv run python -m canaryweave_fides.cli judge one --prompt "..." --fides-mode test_double --test-verdict unsafe

# Full multi-dataset run via run_evaluation
uv run python -m canaryweave_fides.cli eval
```

See the [LLD CLI surface](architecture/lld.md#9-cli-surface) for the full command
tree and [`docs/running_evals.md`](running_evals.md) for evaluation guidance.

### Optional controlled datasets

ASB and AgentDefenseBench corpora are not committed. Point the adapters at local
copies via environment variables; when absent, the adapters report
`skipped_missing_local_path` rather than failing:

```bash
export CANARYWEAVE_ASB_ROOT=/path/to/controlled/ASB
export CANARYWEAVE_AGENTDEFENSEBENCH_ROOT=/path/to/controlled/AgentDefenseBench
```

### Optional FIDES provider

Provider calls are off by default. A live Copilot SDK FIDES call requires **all
three**: `--fides-mode copilot_sdk`, `--provider-calls-enabled`, and an explicit
`--model`. Inspect the provider without calling it:

```bash
uv run python -m canaryweave_fides.cli provider status --provider copilot_sdk --json
uv run python -m canaryweave_fides.cli provider doctor --provider copilot_sdk --model MODEL --json
```

## Local verification (pre-commit)

The repo runs [`pre-commit`](https://pre-commit.com/) with codespell,
trailing-whitespace, end-of-file-fixer, and mixed-line-ending hooks. Run the same
checks the CI and commit hooks run:

```bash
uv run python scripts/check_markdown_fences.py     # balanced code fences in Markdown
uv run python scripts/check_public_artifacts.py    # no private material in public artifacts
pre-commit run --all-files                          # codespell + whitespace + EOF + line endings
```

Documentation must keep code fences balanced and contain no spelling errors that
codespell flags; every file must end with a final newline.

## Writing rules and cases

- **`.war` rules**: see [`docs/rule_authoring.md`](rule_authoring.md) and the
  authoritative schema in [`design/rule_schema.md`](../design/rule_schema.md).
  Rules live in `rules/`; packaged assets are under
  `src/canaryweave_fides/assets/`.
- **`.cases` corpora**: see the [LLD cases section](architecture/lld.md#7-cases-dsl)
  and [`data/cases/smoke.cases`](../data/cases/smoke.cases) for the grammar.
- **Facts are frozen.** The six facts in `fact_registry.py` are a closed
  vocabulary; adding one is a documented framework change grounded in
  [ADR 0003](adr/0003-collapse-to-facts-and-cases.md), not an authoring task.

## Building the API docs (optional)

Sphinx config lives in `docs/conf.py` and pulls autodoc from `src/`. It renders
the docstring-level API reference only; the narrative docs in this directory are
GitHub-flavored Markdown and are read directly on GitHub.

```bash
uv run --with sphinx --with sphinx_rtd_theme sphinx-build -b html docs docs/_build/html
```

