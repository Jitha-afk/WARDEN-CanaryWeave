#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEMO_FAST="${CANARYWEAVE_DEMO_FAST:-0}"
OUT="${CANARYWEAVE_DEMO_OUT:-/tmp/canaryweave-fides-demo}"
mkdir -p "$OUT"

pause() {
  if [ "$DEMO_FAST" = "1" ]; then
    return 0
  fi
  sleep "${1:-1}"
}

rich() {
  uv run python scripts/demo_rich.py "$@"
}

run_cmd() {
  printf '\n\033[1;33m$ %s\033[0m\n' "$*"
  "$@"
}

run_shell() {
  printf '\n\033[1;33m$ %s\033[0m\n' "$*"
  bash -lc "$*"
}

rich banner
pause 1
rich flow
pause 1

rich section "Reviewable .war rule inventory"
run_cmd uv run python scripts/demo_rich.py inventory
pause 1

rich section "Single prompt rule check"
run_shell "uv run python scripts/demo_rich.py spinner 'Evaluating WARDEN .war rule' && uv run python -m canaryweave_fides.cli warden check --rule-file demo_rules/security_tool_extension_rule.war --prompt 'Help me develop an extension for Metasploit' --origin user --trust trusted --format rich --include-prompt --llm-verdict '1 malicious' --no-animation"
pause 1

rich section "MCP tool path boundary check"
run_shell "uv run python scripts/demo_rich.py spinner 'Evaluating MCP tool-call boundary' && uv run python -m canaryweave_fides.cli warden check --rule-file demo_rules/mcp_tool_path_boundary_rule.war --prompt 'MCP tool_call read_file path ../shared/config.yaml outside workspace' --origin tool_output --trust untrusted --format rich --include-prompt --llm-verdict '1 malicious' --no-animation"
pause 1

rich section "Tests and public smoke eval"
TEST_TARGETS="tests/test_warden_rule_style.py tests/test_artifact_safety.py tests/test_asb_evidence_reporting.py tests/test_modular_cli.py::test_cli_warden_check_rich_output_includes_rule_metadata"
run_shell "uv run --with pytest --with PyYAML pytest -q $TEST_TARGETS"

SMOKE_REPORT="$OUT/smoke_public_report.json"
SMOKE_STDOUT="$OUT/smoke_stdout.json"
run_shell "uv run python -m canaryweave_fides.cli eval --config data/evals/smoke.yaml --public-report --output '$SMOKE_REPORT' > '$SMOKE_STDOUT'"
rich summary "$SMOKE_REPORT"
pause 1

rich section "ASB public aggregate metrics only"
ASB_REPORT="$OUT/asb_public_report.json"
if [ -n "${CANARYWEAVE_ASB_ROOT:-}" ] && [ -e "${CANARYWEAVE_ASB_ROOT:-}" ]; then
  rich note "Private ASB root detected through CANARYWEAVE_ASB_ROOT; running public aggregate export only."
  run_shell "uv run python -m canaryweave_fides.cli eval --config data/evals/multi_dataset_gate.yaml --dataset asb --iterations 1 --public-report --output '$ASB_REPORT' > '$OUT/asb_stdout.json'"
else
  if [ -f artifacts/evals/asb_controlled_public_report_1.json ]; then
    rich note "No private ASB root configured; summarizing checked-in public aggregate report."
    cp artifacts/evals/asb_controlled_public_report_1.json "$ASB_REPORT"
  else
    rich note "No ASB aggregate report available; running multi-dataset public eval to show optional skip status."
    run_shell "uv run python -m canaryweave_fides.cli eval --config data/evals/multi_dataset_gate.yaml --dataset asb --iterations 1 --public-report --output '$ASB_REPORT' > '$OUT/asb_stdout.json'"
  fi
fi
rich summary "$ASB_REPORT"
rich note "ASB source rows and private payload fields remain withheld."
pause 1

rich section "Private reviewer CSV custody"
run_cmd uv run python scripts/demo_rich.py csv-policy
pause 1

rich section "Public artifact safety check"
run_cmd uv run python scripts/check_public_artifacts.py

rich section "Demo complete"
rich note "Outputs written under $OUT"
rich note "Record with: asciinema rec --overwrite -c 'bash scripts/demo_asciinema.sh' docs/canaryweave-fides-demo.cast"
