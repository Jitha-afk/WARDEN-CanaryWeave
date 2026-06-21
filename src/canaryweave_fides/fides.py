from __future__ import annotations

from enum import Enum
from typing import Any

from .lattice import (
    ConfidentialityLattice,
    IntegrityLattice,
    ProductLattice,
    security_label,
)
from .models import FidesVerdict, PolicyContext, TraceEvent


class FidesIFCMode(str, Enum):
    DISABLED = "disabled"
    TEST_DOUBLE = "test_double"

    @classmethod
    def coerce(cls, value: Any) -> "FidesIFCMode":
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return cls.TEST_DOUBLE if value else cls.DISABLED
        return cls(str(value))


# Policy thresholds expressed as lattice elements
_TRUSTED_THRESHOLD = IntegrityLattice.trusted()
_PUBLIC_THRESHOLD = ConfidentialityLattice.public()


def _event_integrity(event: TraceEvent) -> IntegrityLattice:
    """Derive the integrity label for a trace event."""
    if event.integrity == "low":
        return IntegrityLattice.untrusted()
    return IntegrityLattice.trusted()


def _event_confidentiality(event: TraceEvent) -> ConfidentialityLattice:
    """Derive the confidentiality label for a trace event."""
    if event.confidentiality == "restricted":
        return ConfidentialityLattice.secret()
    return ConfidentialityLattice.public()


def _event_label(event: TraceEvent) -> ProductLattice:
    """Derive the full security label for a trace event."""
    return security_label(_event_integrity(event), _event_confidentiality(event))


class FidesIFCLayer:
    """Deterministic FIDES Structural IFC layer.

    Enforces two fundamental policies from the FIDES paper (Costa et al., 2025)
    using formal lattice operations:

    1. Trusted Action (P-T): a consequential action is permitted only if the
       context integrity label ⊑ T (trusted). Formally: ℓ_integrity.leq(T).

    2. Permitted Flow (P-F): data may only flow to a sink if the sink is in the
       permitted set. Formally: ℓ_confidentiality.leq(public) OR sink ∈ permitted.

    Uses lattice.py abstractions for formal IFC guarantees rather than ad-hoc
    string comparisons.
    """

    def __init__(
        self,
        mode: FidesIFCMode | str | bool = FidesIFCMode.DISABLED,
        *,
        enabled: bool | None = None,
    ):
        if enabled is not None:
            mode = FidesIFCMode.TEST_DOUBLE if enabled else FidesIFCMode.DISABLED
        self.mode = FidesIFCMode.coerce(mode)

    @property
    def enabled(self) -> bool:
        return self.mode != FidesIFCMode.DISABLED

    def evaluate(
        self, trace: tuple[TraceEvent, ...], policy: PolicyContext
    ) -> FidesVerdict:
        """Evaluate trace events against IFC policies using lattice operations."""
        if not self.enabled:
            return FidesVerdict(
                verdict="disabled",
                confidence=0.0,
                blocks=False,
                rationale_short="FIDES/IFC disabled.",
            )

        checks: list[str] = []
        unsafe = False

        for event in trace:
            integrity = _event_integrity(event)
            confidentiality = _event_confidentiality(event)
            trusted_origin = event.origin in policy.trusted_origins

            # Policy 1: Trusted Action (P-T)
            # Consequential actions require integrity ⊑ T AND trusted origin
            if event.consequential_action:
                if not integrity.leq(_TRUSTED_THRESHOLD) or not trusted_origin:
                    checks.append("trusted_action")
                    unsafe = True

            # Policy 2: Permitted Flow (P-F)
            # Restricted data must only flow to permitted sinks
            if not confidentiality.leq(_PUBLIC_THRESHOLD) and event.sink:
                if event.sink not in policy.permitted_sinks:
                    checks.append("permitted_flow")
                    unsafe = True

        if unsafe:
            return FidesVerdict(
                verdict="unsafe",
                confidence=0.95,
                blocks=True,
                policy_checks=tuple(sorted(set(checks))),
                rationale_short="Low-integrity or restricted flow violated FIDES/IFC policy.",
            )
        return FidesVerdict(
            verdict="safe",
            confidence=0.9,
            blocks=False,
            policy_checks=("trusted_action", "permitted_flow"),
            rationale_short="No FIDES/IFC policy violation observed.",
        )
