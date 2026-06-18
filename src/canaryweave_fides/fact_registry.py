"""The frozen, framework-owned fact vocabulary for WARDEN rules.

A **fact** is a boolean the framework computes from a normalized trace and
exposes to a rule as a built-in ``$``-variable. The vocabulary is *closed*: a
rule may only reference the names defined here. The registry **is** the
declaration — there is no per-rule ``facts:`` block — so a rule that references
an unknown ``$fact`` fails at load time rather than silently evaluating False.

Adding a fact is a documented framework change grounded in the MCP
specification (see ``docs/adr/0003-collapse-to-facts-and-cases.md``), never an
authoring task. This bounds and owns the "what can a rule reason about"
surface.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FactSpec:
    """Identity of a single frozen fact.

    ``name`` is the bare token a rule references as ``$name``. ``summary`` is the
    human-readable meaning; ``mcp_source`` records where the fact is grounded in
    the MCP wire so the vocabulary stays owned and bounded.
    """

    name: str
    summary: str
    mcp_source: str


# The six frozen facts (ADR 0003). Order is meaningful: it is the order the
# vocabulary is documented in and the order surfaced by tooling.
FROZEN_FACTS: tuple[FactSpec, ...] = (
    FactSpec(
        "from_untrusted_origin",
        "content came from an untrusted MCP origin",
        "tools/call result, resources/read, server manifest, sampling/createMessage",
    ),
    FactSpec(
        "capability_denied",
        "requested tool/capability is not in the host's allowed set",
        "tools/list + host roots/permissions",
    ),
    FactSpec(
        "canary_outside_sink",
        "a canary marker is heading to a sink outside the allowed set",
        "data-flow overlay",
    ),
    FactSpec(
        "tool_call_shape",
        "message is structurally shaped like an MCP tool call/plan",
        "tools/call schema",
    ),
    FactSpec(
        "hidden_unicode",
        "text carries invisible / zero-width / normalizing characters",
        "text normaliser",
    ),
    FactSpec(
        "instruction_shape",
        "text is structurally shaped like injected instructions",
        "text normaliser",
    ),
)

# Frozen lookup surfaces derived from the registry.
FACT_SPECS: dict[str, FactSpec] = {spec.name: spec for spec in FROZEN_FACTS}
FACT_NAMES: frozenset[str] = frozenset(FACT_SPECS)


class UnknownFactError(KeyError):
    """Raised when a name outside the frozen vocabulary is treated as a fact."""


def is_fact(name: str) -> bool:
    """Return whether ``name`` is one of the frozen facts."""
    return name in FACT_NAMES


def fact_spec(name: str) -> FactSpec:
    """Return the :class:`FactSpec` for ``name`` or raise :class:`UnknownFactError`."""
    try:
        return FACT_SPECS[name]
    except KeyError as exc:
        known = ", ".join(sorted(FACT_NAMES))
        raise UnknownFactError(f"unknown fact ${name!r}; frozen facts are: {known}") from exc
