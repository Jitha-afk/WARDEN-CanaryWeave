from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

_DEFAULT_PUBLIC_HMAC_KEY = "canaryweave-fides-public-artifact-v1"
_HMAC_ENV_VAR = "CANARYWEAVE_PUBLIC_HMAC_KEY"


def configured_public_hmac_key() -> str:
    """Return the public artifact HMAC key.

    A deployment may override this with CANARYWEAVE_PUBLIC_HMAC_KEY. The default
    key is stable for CI and public fixtures, but private benchmark runs should
    provide their own secret key when they need non-linkable IDs across runs.
    """

    return os.environ.get(_HMAC_ENV_VAR) or _DEFAULT_PUBLIC_HMAC_KEY


def public_hmac_hex(material: Any, *, key: str | bytes | None = None, length: int | None = None) -> str:
    key_bytes = (configured_public_hmac_key() if key is None else key)
    if isinstance(key_bytes, str):
        key_bytes = key_bytes.encode("utf-8")
    digest = hmac.new(key_bytes, str(material).encode("utf-8"), hashlib.sha256).hexdigest()
    return digest if length is None else digest[: int(length)]


def public_hash(material: Any, *, key: str | bytes | None = None) -> str:
    return "hmac-sha256:" + public_hmac_hex(material, key=key)


def public_id(dataset_id: str, material: Any, *, key: str | bytes | None = None, length: int = 16) -> str:
    return f"{dataset_id}.{public_hmac_hex(material, key=key, length=length)}"
