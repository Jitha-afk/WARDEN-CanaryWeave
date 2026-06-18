from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .cases import AttackCase, _as_mapping, _public_safe


_FLAG_KEYS = (
    "instruction_shape",
    "tool_plan_shape",
    "exfiltration_shape",
    "obfuscated",
    "canary_present",
)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value)
    return (str(value),)


def _first_mapping_value(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _policy_tuple(policy: Mapping[str, Any], primary: str, aliases: tuple[str, ...] = ()) -> tuple[str, ...]:
    return _as_tuple(_first_mapping_value(policy, (primary, *aliases)))


def _restore_policy_tuples(policy: Mapping[str, Any]) -> dict[str, Any]:
    restored = dict(policy)
    for key in ("allowed_tools", "allowed_capabilities", "allowed_sinks", "trusted_origins", "protected_labels"):
        if key in restored:
            restored[key] = _as_tuple(restored[key])
    return restored


@dataclass(frozen=True)
class NormalizedFacts:
    """OPA-like gate input derived from AttackCase facts and raw text."""

    case_id: str
    dataset_id: str
    split: str
    surface: str
    origin_labels: tuple[str, ...] = ()
    trust_labels: tuple[str, ...] = ()
    role_labels: tuple[str, ...] = ()
    features: Mapping[str, Any] = field(default_factory=dict)
    requested: Mapping[str, Any] = field(default_factory=dict)
    policy: Mapping[str, Any] = field(default_factory=dict)
    capability: Mapping[str, Any] = field(default_factory=dict)
    flow: Mapping[str, Any] = field(default_factory=dict)
    text: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", str(self.case_id))
        object.__setattr__(self, "dataset_id", str(self.dataset_id))
        object.__setattr__(self, "split", str(self.split))
        object.__setattr__(self, "surface", str(self.surface))
        object.__setattr__(self, "origin_labels", _as_tuple(self.origin_labels))
        object.__setattr__(self, "trust_labels", _as_tuple(self.trust_labels))
        object.__setattr__(self, "role_labels", _as_tuple(self.role_labels))
        object.__setattr__(self, "features", _as_mapping(self.features))
        object.__setattr__(self, "requested", _as_mapping(self.requested))
        object.__setattr__(self, "policy", _as_mapping(self.policy))
        object.__setattr__(self, "capability", _as_mapping(self.capability))
        object.__setattr__(self, "flow", _as_mapping(self.flow))
        if self.text is not None:
            object.__setattr__(self, "text", str(self.text))

    @classmethod
    def from_attack_case(cls, case: AttackCase) -> "NormalizedFacts":
        safe = _as_mapping(case.safe_features)
        context = _as_mapping(case.policy_context)
        private = _as_mapping(case.private_data)

        origin_labels = _as_tuple(_first_mapping_value(safe, ("origin_labels", "origins", "origin")))
        trust_labels = _as_tuple(_first_mapping_value(safe, ("trust_labels", "trust", "integrity")))
        role_labels = _as_tuple(_first_mapping_value(safe, ("role_labels", "roles", "role", "source_label")))

        features = {key: bool(safe.get(key, False)) for key in _FLAG_KEYS}
        for source, target in (
            ("hidden_unicode", "obfuscated"),
            ("encoded_or_high_entropy", "obfuscated"),
            ("canary", "canary_present"),
        ):
            if source in safe:
                features[target] = features[target] or bool(safe[source])
        for key in (
            "length",
            "sha256",
            "text_hash",
            "public_hash",
            "schema_shape",
            "command_execution_shape",
            "credential_or_secret_shape",
            "path_boundary_shape",
            "network_request_shape",
            "memory_poisoning_shape",
            "approval_bypass_shape",
            "protected_context_extraction_shape",
            "destructive_action_shape",
            "social_engineering_shape",
            "deception_shape",
        ):
            if key in safe:
                features[key] = safe[key]

        requested_tool = _first_mapping_value(safe, ("requested_tool", "tool", "capability"))
        requested_capability = _first_mapping_value(safe, ("requested_capability", "capability", "requested_tool", "tool"))
        requested_sink = _first_mapping_value(safe, ("requested_sink", "sink", "target_sink"))
        requested = {
            "tool": requested_tool,
            "capability": requested_capability,
            "action": _first_mapping_value(safe, ("requested_action", "action")),
            "sink": requested_sink,
        }
        requested = {key: value for key, value in requested.items() if value is not None}

        allowed_tools = _policy_tuple(context, "allowed_tools", ("allowed_capabilities",))
        allowed_capabilities = _policy_tuple(context, "allowed_capabilities", ("allowed_tools",))
        allowed_sinks = _policy_tuple(context, "allowed_sinks", ("permitted_sinks", "allowed_canary_sinks"))
        trusted_origins = _policy_tuple(context, "trusted_origins")
        protected_labels = _policy_tuple(context, "protected_labels")
        policy = {
            "allowed_tools": allowed_tools,
            "allowed_capabilities": allowed_capabilities,
            "allowed_sinks": allowed_sinks,
            "trusted_origins": trusted_origins,
            "protected_labels": protected_labels,
        }
        if "canary_policy" in context:
            policy["canary_policy"] = context["canary_policy"]

        tool_allowed = None if requested_tool is None else str(requested_tool) in allowed_tools
        capability_allowed = None if requested_capability is None else str(requested_capability) in allowed_capabilities
        origin_trusted = None if not origin_labels or not trusted_origins else any(origin in trusted_origins for origin in origin_labels)
        sink_allowed = None if requested_sink is None else str(requested_sink) in allowed_sinks
        protected_flow = bool(features.get("canary_present")) or bool(protected_labels and requested_sink)
        flow_allowed = None if not protected_flow and requested_sink is None else bool(sink_allowed)

        return cls(
            case_id=case.case_id,
            dataset_id=case.dataset_id,
            split=case.split,
            surface=case.surface,
            origin_labels=origin_labels,
            trust_labels=trust_labels,
            role_labels=role_labels,
            features=features,
            requested=requested,
            policy=policy,
            capability={
                "tool_allowed": tool_allowed,
                "capability_allowed": capability_allowed,
                "origin_trusted": origin_trusted,
            },
            flow={
                "sink_allowed": sink_allowed,
                "protected_data_flow": protected_flow,
                "protected_flow_allowed": flow_allowed,
            },
            text=str(private.get("raw_input") or "") or None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "split": self.split,
            "surface": self.surface,
            "origin_labels": _public_safe(self.origin_labels),
            "trust_labels": _public_safe(self.trust_labels),
            "role_labels": _public_safe(self.role_labels),
            "features": _public_safe(self.features),
            "requested": _public_safe(self.requested),
            "policy": _public_safe(self.policy),
            "capability": _public_safe(self.capability),
            "flow": _public_safe(self.flow),
            "text": self.text,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NormalizedFacts":
        return cls(
            case_id=str(data["case_id"]),
            dataset_id=str(data["dataset_id"]),
            split=str(data["split"]),
            surface=str(data["surface"]),
            origin_labels=_as_tuple(data.get("origin_labels")),
            trust_labels=_as_tuple(data.get("trust_labels")),
            role_labels=_as_tuple(data.get("role_labels")),
            features=_as_mapping(data.get("features", {})),
            requested=_as_mapping(data.get("requested", {})),
            policy=_restore_policy_tuples(data.get("policy", {})),
            capability=_as_mapping(data.get("capability", {})),
            flow=_as_mapping(data.get("flow", {})),
            text=data.get("text"),
        )
