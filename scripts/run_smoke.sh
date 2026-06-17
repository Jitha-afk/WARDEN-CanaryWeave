#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

uv run python -m canaryweave_fides.cli \
  --fixture-set smoke \
  --output artifacts/smoke_report.json

uv run python scripts/check_public_artifacts.py
