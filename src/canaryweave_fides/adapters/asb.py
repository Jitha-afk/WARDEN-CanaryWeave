from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from canaryweave_fides.cases import AttackCase, GroundTruth

from .base import AdapterResult, AdapterStatus, DatasetAdapter
from .identifiers import public_hash, public_hmac_hex, public_id

_TEXT_FIELD_NAMES = {
    "attack goal",
    "attacker instruction",
    "attacker tool",
    "payload",
    "prompt",
    "instruction",
    "input",
    "content",
    "text",
    "message",
    "messages",
    "query",
    "goal",
    "task",
    "response",
    "completion",
    "tool_output",
    "tool name",
    "trace",
    "description",
    "expected achievements",
}
_ID_FIELD_NAMES = ("id", "case_id", "record_id", "example_id", "sample_id", "name")
_LABEL_FIELD_NAMES = ("label", "case_kind", "kind", "is_attack", "attack", "benign", "Attack Type")
_CATEGORY_FIELD_NAMES = ("category", "attack_category", "class", "type", "taxonomy", "Attack Type")
_SURFACE_FIELD_NAMES = ("surface", "source", "channel", "modality")
_SPLIT_FIELD_NAMES = ("split", "partition", "subset")
_ALLOWED_SUFFIXES = (".jsonl", ".json", ".yaml", ".yml", ".csv", ".txt")


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_label(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    return text or default


def _first_value(record: Mapping[str, Any], names: Iterable[str]) -> Any:
    lower_to_key = {str(key).lower(): key for key in record.keys()}
    for name in names:
        key = lower_to_key.get(name.lower())
        if key is not None:
            return record[key]
    return None


def _shape(value: Any) -> str:
    if isinstance(value, Mapping):
        return "json_object"
    if isinstance(value, list):
        return "json_array"
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return "empty_text"
        if stripped.startswith("{") and stripped.endswith("}"):
            return "json_object_text"
        if stripped.startswith("[") and stripped.endswith("]"):
            return "json_array_text"
        return "plain_text"
    return type(value).__name__


def _safe_key_path(path: tuple[str, ...]) -> str:
    safe_parts: list[str] = []
    for part in path:
        lowered = part.lower()
        if lowered in _TEXT_FIELD_NAMES:
            safe_parts.append(lowered.replace(" ", "_").replace("-", "_"))
        elif part.isdigit():
            safe_parts.append("index")
        else:
            safe_parts.append("field")
    return ".".join(safe_parts)


def _iter_text_candidates(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            lower = key_text.lower()
            next_path = (*path, key_text)
            if lower in _TEXT_FIELD_NAMES:
                if isinstance(item, str):
                    yield next_path, item
                elif isinstance(item, (list, tuple)):
                    joined = "\n".join(str(part) for part in item if isinstance(part, str))
                    if joined:
                        yield next_path, joined
                elif isinstance(item, Mapping):
                    strings = [text for _, text in _iter_text_candidates(item, next_path)]
                    if strings:
                        yield next_path, "\n".join(strings)
            yield from _iter_text_candidates(item, next_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_text_candidates(item, (*path, str(index)))


def _record_to_private_text(record: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
    candidates = list(_iter_text_candidates(record))
    if not candidates:
        return "", ()
    paths = tuple(_safe_key_path(path) for path, _ in candidates)
    text = "\n".join(text for _, text in candidates)
    return text, paths


def _classify_kind(record: Mapping[str, Any]) -> str:
    if _first_value(record, ("Attacker Tool", "Attacker Instruction", "Attack Type")) is not None:
        return "attack"
    if _first_value(record, ("Tool Name", "Expected Achievements")) is not None:
        return "benign"
    value = _first_value(record, _LABEL_FIELD_NAMES)
    if isinstance(value, bool):
        return "attack" if value else "benign"
    label = _stable_label(value, "attack")
    if label in {"benign", "safe", "allow", "allowed", "negative", "clean", "control"}:
        return "benign"
    return "attack"


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n"}:
        return False
    return None


def _asb_native_safe_features(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return public-safe ASB-native schema metadata without raw values."""
    features: dict[str, Any] = {}
    if _first_value(record, ("Attacker Tool", "Attacker Instruction", "Attack Type")) is not None:
        features["asb_record_family"] = "attack_tool"
    elif _first_value(record, ("Tool Name", "Expected Achievements")) is not None:
        features["asb_record_family"] = "normal_tool"

    attack_type = _first_value(record, ("Attack Type",))
    if attack_type is not None:
        features["asb_attack_type"] = _stable_label(attack_type, "unknown")

    aggressive = _optional_bool(_first_value(record, ("Aggressive",)))
    if aggressive is not None:
        features["asb_aggressive"] = aggressive

    corresponding_agent = _first_value(record, ("Corresponding Agent",))
    if corresponding_agent is not None:
        features["asb_corresponding_agent_hash"] = public_hash(str(corresponding_agent))
    return features


def _expected_behavior(kind: str) -> str:
    return "allow" if kind == "benign" else "block"


def _truth_from_record(record: Mapping[str, Any]) -> GroundTruth:
    case_kind = _classify_kind(record)
    return GroundTruth(
        case_kind=case_kind,
        expected_behavior=_expected_behavior(case_kind),
        attack_category=_stable_label(_first_value(record, _CATEGORY_FIELD_NAMES), "dataset_native"),
        labels={"dataset_label_present": _first_value(record, _LABEL_FIELD_NAMES) is not None},
    )


_CATEGORY_RULE_EVIDENCE: dict[str, dict[str, Any]] = {
    "mcp_execution/command_or_code_execution_request": {
        "expected_rule_ids": ("cwfr-0106",),
        "required_fields": ("features.command_execution_shape", "requested.capability"),
        "policy_violation_id": "untrusted_execution_request",
    },
    "mcp_resource_boundary/path_or_uri_boundary_escape": {
        "expected_rule_ids": ("cwfr-0105",),
        "required_fields": ("features.path_boundary_shape", "requested.capability"),
        "policy_violation_id": "resource_boundary_escape",
    },
    "mcp_network/unapproved_network_request": {
        "expected_rule_ids": ("cwfr-0107",),
        "required_fields": ("features.network_request_shape", "requested.capability"),
        "policy_violation_id": "unapproved_network_request",
    },
    "mcp_data_flow/credential_or_secret_exposure": {
        "expected_rule_ids": ("cwfr-0104",),
        "required_fields": ("features.credential_or_secret_shape",),
        "policy_violation_id": "credential_or_secret_exposure",
    },
    "mcp_prompt_boundary/instruction_hierarchy_violation": {
        "expected_rule_ids": ("cwfr-0003",),
        "required_fields": ("features.instruction_shape", "features.origin_labels"),
        "policy_violation_id": "instruction_hierarchy_violation",
    },
    "mcp_suspicious_structure/encoding_or_obfuscation": {
        "expected_rule_ids": ("cwfr-0004",),
        "required_fields": ("features.obfuscated",),
        "policy_violation_id": "suspicious_encoded_or_hidden_structure",
    },
    "mcp_prompt_boundary/protected_context_exfiltration": {
        "expected_rule_ids": ("cwfr-0108",),
        "required_fields": ("features.protected_context_extraction_shape", "features.origin_labels"),
        "policy_violation_id": "protected_context_exfiltration",
    },
    "mcp_impact/destructive_agent_action": {
        "expected_rule_ids": ("cwfr-0109",),
        "required_fields": ("features.destructive_action_shape", "requested.capability"),
        "policy_violation_id": "destructive_agent_action",
    },
    "mcp_abuse/recon_social_engineering": {
        "expected_rule_ids": ("cwfr-0110",),
        "required_fields": ("features.social_engineering_shape", "features.deception_shape", "features.origin_labels"),
        "policy_violation_id": "deceptive_social_engineering_tasking",
    },
}


def _rule_evidence_for_category(category: str, case_kind: str, flags: Mapping[str, Any]) -> dict[str, Any]:
    """Return public-safe scoring metadata for mapped attack categories.

    These labels are used only by evaluation/reporting. They are not consumed by
    WARDEN/FIDES detector facts. A category alone is not enough for expected-rule
    evidence when multiple safe shapes share a broad category; only attach a rule
    expectation when the exact facts required by that rule are present.
    """
    if case_kind != "attack":
        return {}
    if category == "mcp_data_flow/credential_or_secret_exposure" and not flags.get("credential_or_secret_shape"):
        return {}
    return dict(_CATEGORY_RULE_EVIDENCE.get(category, {}))


def _origin_labels_for_surface(surface: str, flags: Mapping[str, Any], *, descriptive_only: bool = False) -> list[str]:
    if descriptive_only:
        return ["api_message"]
    if surface in {"tool", "tool_result"}:
        return ["tool_output"]
    if surface in {"resource", "mcp_resource"}:
        return ["resource_content"]
    if surface in {"manifest", "server_manifest"}:
        return ["server_manifest"]
    if surface in {"sampling", "server_sampling"}:
        return ["server_sampling"]
    if flags.get("protected_context_extraction_shape") or flags.get("social_engineering_shape"):
        return ["resource_content"]
    if surface == "api_message" and flags.get("instruction_shape"):
        # Dataset-local API-message records are untrusted source material. Map
        # instruction-shaped records into an origin understood by cwfr-0003
        # without using dataset labels or raw text.
        return ["resource_content"]
    return ["api_message"]


def _safe_text_flags(text: str, surface: str) -> dict[str, Any]:
    lowered = text.lower()
    flags = {
        "instruction_shape": any(term in lowered for term in ("ignore", "override", "policy", "instruction", "developer", "system", "role", "jailbreak")),
        "command_execution_shape": any(term in lowered for term in ("shell", "command", "execute", "script", "python", "bash", "powershell", "terminal")),
        "credential_or_secret_shape": any(term in lowered for term in ("credential", "secret", "token", "password", "private key", "api key")),
        "exfiltration_shape": any(term in lowered for term in ("exfil", "send", "upload", "leak", "external", "webhook", "remote")),
        "path_boundary_shape": any(term in lowered for term in ("path", "file", "directory", "traversal", "workspace", "passwd", "parent directory")),
        "network_request_shape": any(term in lowered for term in ("http", "url", "network", "webhook", "endpoint", "ssrf")),
        "memory_poisoning_shape": any(term in lowered for term in ("memory", "remember", "store", "persist", "rag", "retrieval")),
        "approval_bypass_shape": any(term in lowered for term in ("approval", "consent", "without asking", "bypass", "permission")),
        "protected_context_extraction_shape": any(term in lowered for term in ("system prompt", "system policy", "developer message", "protected context", "hidden policy", "tool schema", "extract protected", "reveal protected")),
        "destructive_action_shape": any(term in lowered for term in ("delete", "wipe", "reset", "destroy", "destructive", "remove all", "erase")),
        "social_engineering_shape": any(term in lowered for term in ("target profile", "victim profile", "impersonation", "lure", "phishing", "outbound contact")),
        "deception_shape": any(term in lowered for term in ("deception", "deceptive", "impersonation", "lure", "phishing", "spoof")),
        "obfuscated": any(term in lowered for term in ("base64", "unicode", "encoded", "obfuscat", "hidden")),
        "tool_plan_shape": surface in {"tool", "api_message", "tool_result"},
    }
    return flags


def _shared_category(flags: Mapping[str, Any], fallback: str) -> str:
    if flags.get("protected_context_extraction_shape"):
        return "mcp_prompt_boundary/protected_context_exfiltration"
    if flags.get("destructive_action_shape"):
        return "mcp_impact/destructive_agent_action"
    if flags.get("social_engineering_shape") and flags.get("deception_shape"):
        return "mcp_abuse/recon_social_engineering"
    if flags.get("command_execution_shape"):
        return "mcp_execution/command_or_code_execution_request"
    if flags.get("path_boundary_shape"):
        return "mcp_resource_boundary/path_or_uri_boundary_escape"
    if flags.get("credential_or_secret_shape") or flags.get("exfiltration_shape"):
        return "mcp_data_flow/credential_or_secret_exposure"
    if flags.get("network_request_shape"):
        return "mcp_network/unapproved_network_request"
    if flags.get("memory_poisoning_shape"):
        return "mcp_context_integrity/memory_or_rag_poisoning"
    if flags.get("approval_bypass_shape"):
        return "mcp_tool_authority/approval_or_consent_bypass"
    if flags.get("instruction_shape"):
        return "mcp_prompt_boundary/instruction_hierarchy_violation"
    if flags.get("obfuscated"):
        return "mcp_suspicious_structure/encoding_or_obfuscation"
    return fallback


def _requested_from_flags(flags: Mapping[str, Any], *, descriptive_only: bool = False) -> dict[str, str]:
    if descriptive_only:
        return {}
    requested: dict[str, str] = {}
    if flags.get("destructive_action_shape"):
        requested.update({"requested_tool": "admin_action", "requested_capability": "admin_action", "requested_action": "destructive_update"})
    elif flags.get("command_execution_shape"):
        requested.update({"requested_tool": "execute_code", "requested_capability": "execute_code", "requested_action": "execute"})
    elif flags.get("path_boundary_shape"):
        requested.update({"requested_tool": "read_file", "requested_capability": "read_file", "requested_action": "read_resource"})
    elif flags.get("network_request_shape"):
        requested.update({"requested_tool": "network_request", "requested_capability": "network_request", "requested_action": "external_request"})
    elif flags.get("memory_poisoning_shape"):
        requested.update({"requested_tool": "memory_write", "requested_capability": "memory_write", "requested_action": "persist_context"})
    if flags.get("exfiltration_shape") or flags.get("credential_or_secret_shape") or flags.get("network_request_shape"):
        requested["requested_sink"] = "external_sink"
    return requested

def _load_json_records(path: Path) -> Iterable[Mapping[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, Mapping):
        for key in ("records", "cases", "examples", "data", "items"):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, Mapping):
                        yield item
                return
        yield data
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping):
                yield item


def _load_jsonl_records(path: Path) -> Iterable[Mapping[str, Any]]:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        item = json.loads(stripped)
        if isinstance(item, Mapping):
            yield item


def _load_yaml_records(path: Path) -> Iterable[Mapping[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, Mapping):
        for key in ("records", "cases", "examples", "data", "items"):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, Mapping):
                        yield item
                return
        yield data
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping):
                yield item


def _load_csv_records(path: Path) -> Iterable[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield dict(row)


def _load_txt_records(path: Path) -> Iterable[Mapping[str, Any]]:
    yield {"payload": path.read_text(encoding="utf-8")}


class ASBAdapter(DatasetAdapter):
    """Adapter for a private local ASB checkout.

    The adapter may inspect local files to compute safe structural features, but
    returned public AttackCase exports never contain native payload text or raw
    native identifiers.
    """

    dataset_id = "asb"
    default_env_var = "CANARYWEAVE_ASB_ROOT"

    def load(self) -> AdapterResult:
        if not self.config.enabled:
            return self.disabled_result()
        root = self.configured_root()
        if root is None or not root.exists():
            return self.missing_result(root)

        files = self._discover_files(root)
        cases: list[AttackCase] = []
        errors = 0
        for file_path in files:
            try:
                for index, record in enumerate(self._load_records(file_path)):
                    if not isinstance(record, Mapping):
                        continue
                    cases.append(self._record_to_case(record, root, file_path, index))
                    if self.config.max_cases is not None and len(cases) >= self.config.max_cases:
                        break
            except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, csv.Error):
                errors += 1
            if self.config.max_cases is not None and len(cases) >= self.config.max_cases:
                break

        status = AdapterStatus.LOADED if cases else AdapterStatus.EMPTY
        return AdapterResult(
            dataset_id=self.dataset_id,
            status=status,
            cases=tuple(cases),
            message=f"{self.dataset_id} adapter loaded {len(cases)} cases with {errors} unreadable files skipped",
            safe_metadata={"files_inspected": len(files), "unreadable_files": errors, "public_export": "redacted_features_only"},
        )

    def _discover_files(self, root: Path) -> list[Path]:
        if root.is_file():
            return [root] if root.suffix.lower() in _ALLOWED_SUFFIXES else []
        return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in _ALLOWED_SUFFIXES)

    def _load_records(self, path: Path) -> Iterable[Mapping[str, Any]]:
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            yield from _load_jsonl_records(path)
        elif suffix == ".json":
            yield from _load_json_records(path)
        elif suffix in {".yaml", ".yml"}:
            yield from _load_yaml_records(path)
        elif suffix == ".csv":
            yield from _load_csv_records(path)
        elif suffix == ".txt":
            yield from _load_txt_records(path)

    def _record_to_case(self, record: Mapping[str, Any], root: Path, file_path: Path, index: int) -> AttackCase:
        private_text, payload_paths = _record_to_private_text(record)
        native_id = _first_value(record, _ID_FIELD_NAMES)
        rel_path = file_path.relative_to(root) if file_path != root else Path(file_path.name)
        raw_ref = f"{self.dataset_id}:file_hmac={public_hmac_hex(str(rel_path), length=16)}#record={index}"
        opaque_material = f"{rel_path}:{index}:{native_id}:{_sha256_text(private_text)}"
        split = _stable_label(_first_value(record, _SPLIT_FIELD_NAMES), self.config.split or "dev")
        ground_truth = _truth_from_record(record)
        surface = _stable_label(_first_value(record, _SURFACE_FIELD_NAMES), "api_message")
        top_level_keys = tuple(sorted(str(key) for key in record.keys()))
        flags = _safe_text_flags(private_text, surface)
        native_features = _asb_native_safe_features(record)
        descriptive_only = native_features.get("asb_record_family") == "normal_tool"
        shared_category = _shared_category(flags, ground_truth.attack_category)
        requested = _requested_from_flags(flags, descriptive_only=descriptive_only)
        origin_labels = _origin_labels_for_surface(surface, flags, descriptive_only=descriptive_only)
        case_kind_value = getattr(ground_truth.case_kind, "value", str(ground_truth.case_kind))
        rule_evidence = _rule_evidence_for_category(shared_category, case_kind_value, flags)

        safe_features = {
            "length": len(private_text),
            "public_hash": public_hash(private_text),
            "schema_shape": _shape(record),
            "source_format": file_path.suffix.lower().lstrip(".") or "unknown",
            "payload_field_count": len(payload_paths),
            "payload_field_paths": payload_paths,
            "top_level_key_count": len(top_level_keys),
            "top_level_keys_hash": public_hash("\n".join(top_level_keys)),
            "native_id_hash": public_hash(str(native_id)) if native_id is not None else None,
            **native_features,
            **flags,
            **requested,
            "origin_labels": origin_labels,
            "trust_labels": ["untrusted"],
        }
        safe_features = {key: value for key, value in safe_features.items() if value is not None}
        labels = dict(ground_truth.labels)
        if rule_evidence:
            labels.update(
                {
                    "required_fields": list(rule_evidence.get("required_fields", ())),
                    "policy_violation_id": rule_evidence.get("policy_violation_id"),
                    "source_tier": "controlled_local",
                }
            )
        labels = {key: value for key, value in labels.items() if value is not None}
        ground_truth = GroundTruth(
            case_kind=ground_truth.case_kind,
            expected_behavior=ground_truth.expected_behavior,
            attack_category=shared_category,
            expected_rule_ids=tuple(rule_evidence.get("expected_rule_ids", ground_truth.expected_rule_ids)),
            labels=labels,
        )

        return AttackCase(
            case_id=public_id(self.dataset_id, opaque_material),
            dataset_id=self.dataset_id,
            split=split,
            case_kind=ground_truth.case_kind,
            attack_category=ground_truth.attack_category,
            surface=surface,
            safe_features=safe_features,
            policy_context={
                "trusted_origins": ["user", "host_policy"],
                "allowed_tools": ["read_task", "summarize_note"],
                "allowed_sinks": ["local_audit", "user_response"],
            },
            expected_behavior=ground_truth.expected_behavior,
            ground_truth=ground_truth,
            raw_ref=raw_ref,
            private_data={
                "source_format": file_path.suffix.lower().lstrip(".") or "unknown",
                "private_sha256": _sha256_text(private_text),
                "raw_input": private_text,
                "raw_output": "",
            },
        )
