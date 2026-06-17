# Running Evaluations

Milestone 1 adds Vigil-style configuration, dataset specs, manifests, docs, and helper scripts. It does not implement the multi-dataset runner yet.

## Smoke verification

From `poc/canaryweave-fides`:

```bash
scripts/run_smoke.sh
```

The script runs the existing CLI smoke path and then checks public artifacts.

## Multi-dataset eval

From `poc/canaryweave-fides`:

```bash
scripts/run_multi_dataset_eval.sh
```

The script validates the config files, runs the configured public-safe multi-dataset eval, and then checks public artifacts. Optional controlled datasets are reported as `skipped_missing_local_path` when their local roots are absent.

## Private reviewer CSV

For signature-improvement loops, the eval runner can also write a private reviewer CSV with raw input/output custody fields and per-stack labels:

```bash
CANARYWEAVE_ASB_ROOT=/path/to/controlled/ASB \
uv run python -m canaryweave_fides.cli eval \
  --config data/evals/multi_dataset_gate.yaml \
  --dataset asb \
  --iterations 1 \
  --output artifacts/evals/asb_controlled_public_report_1.json \
  --private-review-csv reverse-engineering/review/asb_gate_review.csv \
  --public-report
```

Keep reviewer CSVs under a git-ignored controlled path such as `reverse-engineering/review/`. They may contain raw source snippets, raw decision outputs, and labels intended for human review; they are not public artifacts and must not be committed.

## Required verification

Before committing this milestone, run:

```bash
uv run python scripts/check_markdown_fences.py
uv run --with pytest --with PyYAML pytest -q
```

## Public artifact safety

Run:

```bash
uv run python scripts/check_public_artifacts.py
```

The safety scanner rejects common raw payload shapes, credential-like strings, and provider transcript markers in public roots.
