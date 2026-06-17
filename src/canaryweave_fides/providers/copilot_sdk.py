from __future__ import annotations

import asyncio
import inspect
import time
from pathlib import Path
from typing import Any

from .base import JudgeProviderConfig, ProviderJudgeResponse


class CopilotSdkJudgeProvider:
    """Quarantined GitHub Copilot SDK provider for FIDES.

    The SDK import is lazy so normal public/test runs do not require the optional
    dependency. Live use is intentionally explicit and provider-call gated.
    """

    def __init__(self, config: JudgeProviderConfig) -> None:
        if not config.provider_calls_enabled:
            raise ValueError("copilot_sdk provider requires provider_calls_enabled=true")
        if not config.model:
            raise ValueError("copilot_sdk provider requires an explicit model")
        self.config = config

    @staticmethod
    def import_available() -> bool:
        try:
            import copilot  # noqa: F401
        except ImportError:
            return False
        return True

    @staticmethod
    def auth_status(*, copilot_home: Path | None = None) -> dict[str, Any]:
        return _run_async(_copilot_auth_status(copilot_home=copilot_home))

    @staticmethod
    def list_models(*, copilot_home: Path | None = None) -> list[dict[str, Any]]:
        return _run_async(_copilot_list_models(copilot_home=copilot_home))

    def judge(self, prompt: str, *, case_id: str, request_id: str) -> ProviderJudgeResponse:
        started = time.perf_counter()
        text = _run_async(_copilot_judge(prompt, config=self.config))
        latency_ms = (time.perf_counter() - started) * 1000.0
        return ProviderJudgeResponse(text=text, latency_ms=latency_ms, provider_calls=1, model=self.config.model)


def default_copilot_home() -> Path:
    return Path.home() / ".local" / "share" / "canaryweave-fides" / "copilot"


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("copilot_sdk provider cannot run inside an active event loop in the synchronous CLI path")


def _client_kwargs(*, copilot_home: Path | None = None, provider_calls_enabled: bool = False, model: str | None = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"mode": "empty", "base_directory": str(copilot_home or default_copilot_home())}
    # Let the SDK use its documented auth chain without exposing credentials.
    kwargs["use_logged_in_user"] = True
    return kwargs


async def _new_client(*, copilot_home: Path | None = None):
    try:
        from copilot import CopilotClient
    except ImportError as exc:
        raise RuntimeError("github-copilot-sdk is not installed; install canaryweave-fides[copilot]") from exc
    client = CopilotClient(**_client_kwargs(copilot_home=copilot_home))
    start = getattr(client, "start", None)
    if callable(start):
        result = start()
        if inspect.isawaitable(result):
            await result
    return client


async def _stop_client(client: Any) -> None:
    stop = getattr(client, "stop", None) or getattr(client, "close", None)
    if callable(stop):
        result = stop()
        if inspect.isawaitable(result):
            await result


async def _copilot_auth_status(*, copilot_home: Path | None = None) -> dict[str, Any]:
    client = await _new_client(copilot_home=copilot_home)
    try:
        method = getattr(client, "get_auth_status", None)
        if not callable(method):
            return {"available": True, "auth_status_supported": False}
        status = method()
        if inspect.isawaitable(status):
            status = await status
        return _public_obj(status)
    finally:
        await _stop_client(client)


async def _copilot_list_models(*, copilot_home: Path | None = None) -> list[dict[str, Any]]:
    client = await _new_client(copilot_home=copilot_home)
    try:
        method = getattr(client, "list_models", None)
        if not callable(method):
            return []
        models = method()
        if inspect.isawaitable(models):
            models = await models
        if isinstance(models, dict) and "models" in models:
            models = models["models"]
        return [_public_obj(model) for model in (models or [])]
    finally:
        await _stop_client(client)


def _reject_permission_request(*args: Any, **kwargs: Any) -> Any:
    try:
        from copilot.generated.rpc import PermissionDecisionReject

        return PermissionDecisionReject(feedback="FIDES judge rejects all tool and permission requests")
    except Exception:
        return {"kind": "reject", "feedback": "FIDES judge rejects all tool and permission requests"}


async def _copilot_judge(prompt: str, *, config: JudgeProviderConfig) -> str:
    client = await _new_client(copilot_home=config.copilot_home)
    try:
        create = getattr(client, "create_session", None)
        if not callable(create):
            raise RuntimeError("installed github-copilot-sdk lacks create_session")
        kwargs: dict[str, Any] = {
            "model": config.model,
            "system_message": {
                "mode": "append",
                "content": "You are FIDES, a quarantined JSON-only security judge. Do not request tools.",
            },
            "available_tools": [],
            "excluded_tools": ["*"],
            "on_permission_request": _reject_permission_request,
            "working_directory": str(config.copilot_home or default_copilot_home()),
            "skip_custom_instructions": True,
            "enable_config_discovery": False,
            "enable_file_hooks": False,
            "enable_host_git_operations": False,
            "enable_skills": False,
            "mcp_servers": {},
            "mcp_oauth_token_storage": "in-memory",
            "embedding_cache_storage": "in-memory",
        }
        try:
            session = create(**kwargs)
        except TypeError:
            kwargs.pop("available_tools", None)
            session = create(**kwargs)
        if inspect.isawaitable(session):
            session = await session
        send = getattr(session, "send_and_wait", None) or getattr(session, "send", None)
        if not callable(send):
            raise RuntimeError("installed github-copilot-sdk session lacks send method")
        response = send(prompt)
        if inspect.isawaitable(response):
            response = await response
        return _extract_text(response)
    finally:
        await _stop_client(client)


def _extract_text(response: Any) -> str:
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    for attr in ("content", "text", "message", "output"):
        value = getattr(response, attr, None)
        if isinstance(value, str):
            return value
    if isinstance(response, dict):
        for key in ("content", "text", "message", "output"):
            value = response.get(key)
            if isinstance(value, str):
                return value
    return str(response)


def _public_obj(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    elif hasattr(value, "to_dict"):
        value = value.to_dict()
    elif hasattr(value, "__dict__") and not isinstance(value, dict):
        value = vars(value)
    if not isinstance(value, dict):
        return {"value": _redact_public_value(value)}
    return {str(key): _redact_public_value(item) for key, item in value.items() if not _sensitive_key(str(key))}


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(secret in lowered for secret in ("token", "secret", "credential", "authorization"))


def _redact_public_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    elif hasattr(value, "to_dict"):
        value = value.to_dict()
    elif hasattr(value, "__dict__") and not isinstance(value, dict):
        value = vars(value)
    if isinstance(value, dict):
        return {str(key): _redact_public_value(item) for key, item in value.items() if not _sensitive_key(str(key))}
    if isinstance(value, list):
        return [_redact_public_value(item) for item in value]
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return str(value)
