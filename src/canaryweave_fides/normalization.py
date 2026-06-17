from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import unicodedata


_HIDDEN_CATEGORIES = {"Cf", "Cc"}
_CREDENTIAL_RE = re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret[_-]?key|bearer)\s*[=:]\s*[^\s]+")
_CANARY_RE = re.compile(r"CANARY_[A-Z0-9_]+")
_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s]+")
_SHELLISH_RE = re.compile(r"(?i)\b(curl|wget|powershell)\b\s+\S+")
_INSTRUCTION_SHAPE_RE = re.compile(
    r"(?i)\b(system|developer|policy|priority|authority|role)\b.{0,80}\b(rule|message|instruction|directive|override|boundary)\b"
)


@dataclass(frozen=True)
class NormalizedText:
    length: int
    hidden_char_count: int
    normalization_changed: bool
    sha256: str
    redacted: str
    instruction_shape: bool
    encoded_or_high_entropy: bool


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def hidden_char_count(text: str) -> int:
    return sum(1 for ch in text if unicodedata.category(ch) in _HIDDEN_CATEGORIES)


def has_hidden_unicode_structure(text: str) -> bool:
    return hidden_char_count(text) > 0 or unicodedata.normalize("NFKC", text) != text


def looks_encoded_or_high_entropy(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 40:
        return False
    base64ish = sum(1 for ch in compact if ch.isalnum() or ch in "+/=_-") / max(len(compact), 1)
    return base64ish > 0.92 and any(ch.isdigit() for ch in compact)


def has_untrusted_instruction_shape(text: str) -> bool:
    return bool(_INSTRUCTION_SHAPE_RE.search(text))


def redact_for_judge(text: str) -> str:
    redacted = _URL_RE.sub("[URL]", text)
    redacted = _CREDENTIAL_RE.sub("[CREDENTIAL]", redacted)
    redacted = _SHELLISH_RE.sub("[COMMAND_SHAPE]", redacted)
    redacted = _CANARY_RE.sub("[CANARY]", redacted)
    return redacted


def normalize_text(text: str) -> NormalizedText:
    redacted = redact_for_judge(text)
    hidden = hidden_char_count(text)
    normalized = unicodedata.normalize("NFKC", text)
    # Default public export preserves features and digest, not readable raw content.
    export_text = "[REDACTED_TEXT]" if redacted else ""
    return NormalizedText(
        length=len(text),
        hidden_char_count=hidden,
        normalization_changed=(normalized != text) or hidden > 0,
        sha256=_digest(text),
        redacted=export_text,
        instruction_shape=has_untrusted_instruction_shape(text),
        encoded_or_high_entropy=looks_encoded_or_high_entropy(text),
    )
