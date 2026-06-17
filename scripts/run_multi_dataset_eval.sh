#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

uv run python - <<'PY'
from pathlib import Path
import yaml

required = [
    Path('conf/default.yaml'),
    Path('conf/datasets.yaml'),
    Path('conf/stacks.yaml'),
    Path('data/evals/multi_dataset_gate.yaml'),
]
for path in required:
    with path.open('r', encoding='utf-8') as handle:
        yaml.safe_load(handle)
print('multi-dataset config ok')
PY

uv run python -m canaryweave_fides.cli eval \
  --config data/evals/multi_dataset_gate.yaml \
  --public-report \
  --output artifacts/evals/public_gate_eval_report_50.json

uv run python scripts/check_public_artifacts.py
