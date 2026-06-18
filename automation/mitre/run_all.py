"""One-command orchestrator for the MITRE -> WARDEN automation.

Runs the fetchers (ATT&CK, ATLAS, D3FEND, OWASP MCP Top 10) and then the WARDEN
transform, in dependency order. Each stage is independently selectable so a run
can refresh just one source.

Examples::

    python run_all.py                      # full pipeline, using cached raw data
    python run_all.py --refresh            # re-download every source, then transform
    python run_all.py --only attack atlas  # just those fetchers (no transform)
    python run_all.py --skip d3fend        # everything except D3FEND
    python run_all.py --transform-only     # re-run the transform over existing dumps
"""
from __future__ import annotations

import argparse
import time
import traceback

import config
from common import log

# Stage name -> (human label, callable factory). Imports are deferred into each
# stage so a syntax error or missing dep in one fetcher cannot break the others.
STAGES = ("attack", "atlas", "d3fend", "owasp", "transform")


def _run_attack(refresh: bool) -> dict:
    from fetch_attack import fetch_attack

    return fetch_attack(refresh=refresh)


def _run_atlas(refresh: bool) -> dict:
    from fetch_atlas import fetch_atlas

    return fetch_atlas(refresh=refresh)


def _run_d3fend(refresh: bool) -> dict:
    from fetch_d3fend import fetch_d3fend

    return fetch_d3fend(refresh=refresh)


def _run_owasp(refresh: bool) -> dict:
    from fetch_owasp_mcp import fetch_owasp_mcp

    return fetch_owasp_mcp(refresh=refresh)


def _run_transform(refresh: bool) -> dict:  # noqa: ARG001 - signature parity
    from transform_warden import transform

    return transform()


_RUNNERS = {
    "attack": _run_attack,
    "atlas": _run_atlas,
    "d3fend": _run_d3fend,
    "owasp": _run_owasp,
    "transform": _run_transform,
}


def run(stages: list[str], *, refresh: bool, keep_going: bool) -> int:
    config.RAW_DIR.mkdir(parents=True, exist_ok=True)
    config.NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
    config.WARDEN_DIR.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    for stage in stages:
        log(f"=== stage: {stage} ===")
        start = time.time()
        try:
            result = _RUNNERS[stage](refresh)
            log(f"stage {stage} ok in {time.time() - start:.1f}s -> {result}")
        except Exception as exc:  # noqa: BLE001 - we summarize and optionally continue
            failures.append(stage)
            log(f"stage {stage} FAILED: {exc}")
            traceback.print_exc()
            if not keep_going:
                log("aborting (use --keep-going to continue past failures)")
                break

    if failures:
        log(f"completed with failures: {', '.join(failures)}")
        return 1
    log("all requested stages completed successfully")
    return 0


def _resolve_stages(args: argparse.Namespace) -> list[str]:
    if args.transform_only:
        return ["transform"]
    if args.only:
        return [s for s in STAGES if s in set(args.only)]
    skip = set(args.skip or [])
    return [s for s in STAGES if s not in skip]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the MITRE -> WARDEN automation pipeline.")
    parser.add_argument("--refresh", action="store_true", help="Re-download all raw sources.")
    parser.add_argument(
        "--only",
        nargs="+",
        choices=STAGES,
        help="Run only these stages (order is normalized to the pipeline order).",
    )
    parser.add_argument("--skip", nargs="+", choices=STAGES, help="Run every stage except these.")
    parser.add_argument(
        "--transform-only",
        action="store_true",
        help="Skip fetchers; re-run the WARDEN transform over existing dumps.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue to later stages even if one fails.",
    )
    args = parser.parse_args()

    stages = _resolve_stages(args)
    if not stages:
        log("no stages selected")
        return 2
    log(f"pipeline stages: {' -> '.join(stages)} (refresh={args.refresh})")
    return run(stages, refresh=args.refresh, keep_going=args.keep_going)


if __name__ == "__main__":
    raise SystemExit(main())
