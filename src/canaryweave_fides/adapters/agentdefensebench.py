from __future__ import annotations

from pathlib import Path

from .asb import ASBAdapter
from .base import AdapterResult, AdapterStatus


class AgentDefenseBenchAdapter(ASBAdapter):
    """Optional local AgentDefenseBench adapter.

    Missing local paths are a normal CI condition and are reported explicitly as
    skipped_missing_local_path rather than treated as test failures.
    """

    dataset_id = "agentdefensebench"
    default_env_var = "CANARYWEAVE_AGENTDEFENSEBENCH_ROOT"

    def missing_result(self, root: Path | None = None) -> AdapterResult:
        return AdapterResult(
            dataset_id=self.dataset_id,
            status=AdapterStatus.SKIPPED_MISSING_LOCAL_PATH,
            cases=(),
            message="agentdefensebench skipped: missing configured local dataset path",
            safe_metadata={
                "absent_behavior": AdapterStatus.SKIPPED_MISSING_LOCAL_PATH.value
            },
        )
