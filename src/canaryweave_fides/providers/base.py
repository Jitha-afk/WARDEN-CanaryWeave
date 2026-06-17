from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class JudgeProviderConfig:
    provider: str = "fake"
    model: str | None = None
    copilot_home: Path | None = None
    timeout_seconds: int = 120
    provider_calls_enabled: bool = False


@dataclass(frozen=True)
class ProviderJudgeResponse:
    text: str
    latency_ms: float = 0.0
    provider_calls: int = 0
    model: str | None = None


class JudgeProvider(Protocol):
    config: JudgeProviderConfig

    def judge(self, prompt: str, *, case_id: str, request_id: str) -> ProviderJudgeResponse:
        ...
