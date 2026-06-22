# Running Evaluations

## Evaluation Tiers

WARDEN-CanaryWeave uses a 3-tier evaluation methodology, each with different data custody rules:

| Tier | Data Source | Custody | Purpose |
|---|---|---|---|
| **Tier 1: Synthetic CI** | `data/cases/smoke.cases` + synthetic adapter | Committed, public-safe | CI gate — runs on every PR, no credentials needed |
| **Tier 2: Controlled Local** | ASB / AgentDefenseBench (local paths) | Not committed, git-ignored | Signature improvement — raw payloads stay local |
| **Tier 3: Public-Safe Report** | Aggregate metrics from Tier 2 | Committed as opaque IDs + metrics | Shareable evidence — no raw payloads, no transcripts |

### What each tier can and cannot contain:

| Content | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Raw attack payloads | No (synthetic only) | Yes (local) | No |
| Provider transcripts | No | Yes (local) | No |
| Rule IDs + reason codes | Yes | Yes | Yes |
| Aggregate ASR/F1 metrics | Yes | Yes | Yes |
| Case-level raw text | No | Yes (CSV) | No (opaque IDs only) |
| Reviewer CSVs | No | Yes (git-ignored) | No |

## Quick Start

```bash
# Tier 1: Smoke (CI — always works)
uv run warden warden test --input data/cases/smoke.cases

# Tier 1: Full smoke eval
uv run warden eval --config data/evals/smoke.yaml

# Tier 2: Controlled local eval (requires dataset paths)
CANARYWEAVE_ASB_ROOT=/path/to/ASB uv run warden eval \
  --config data/evals/multi_dataset_gate.yaml --dataset asb

# Tier 3: Public-safe report (aggregate metrics only)
uv run warden eval --config data/evals/smoke.yaml --public-report
```

## Smoke Verification (Tier 1)

```bash
scripts/run_smoke.sh
```

Runs the CLI smoke path and checks public artifacts.

## Multi-Dataset Eval (Tier 2)

```bash
scripts/run_multi_dataset_eval.sh
```

Validates config files, runs the configured eval, checks public artifacts. Optional controlled datasets report `skipped_missing_local_path` when local roots are absent.

## Private Reviewer CSV (Tier 2)

For signature-improvement loops, the eval runner writes a private reviewer CSV with raw input/output fields:

```bash
CANARYWEAVE_ASB_ROOT=/path/to/controlled/ASB \
uv run warden eval \
  --config data/evals/multi_dataset_gate.yaml \
  --dataset asb \
  --iterations 1 \
  --output artifacts/evals/asb_controlled_public_report_1.json \
  --private-review-csv reverse-engineering/review/asb_gate_review.csv \
  --public-report
```

Keep reviewer CSVs under a git-ignored controlled path such as `reverse-engineering/review/`. They may contain raw source snippets, raw decision outputs, and labels intended for human review; they are not public artifacts and must not be committed.

## Verification

```bash
uv run python scripts/check_markdown_fences.py
uv run --with pytest pytest -q
uv run python scripts/check_public_artifacts.py
```

The safety scanner rejects common raw payload shapes, credential-like strings, and provider transcript markers in public roots.
