from __future__ import annotations

from .base import JudgeProviderConfig, ProviderJudgeResponse


class FakeJudgeProvider:
    def __init__(self, response_text: str, *, model: str = "fake-fides") -> None:
        self.config = JudgeProviderConfig(provider="fake", model=model, provider_calls_enabled=True)
        self.response_text = response_text
        self.calls = 0

    def judge(self, prompt: str, *, case_id: str, request_id: str) -> ProviderJudgeResponse:
        self.calls += 1
        return ProviderJudgeResponse(text=self.response_text, latency_ms=0.0, provider_calls=1, model=self.config.model)
