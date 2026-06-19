"""Variable Memory for FIDES selective hiding.

Implements the Variable Passing pattern from the FIDES paper (Costa et al., 2025):
untrusted tool results are stored behind opaque variable handles ($VAR_n).
The Planning LLM sees only handles in its context, never the raw untrusted content.
This prevents indirect prompt injection by design.

The Quarantined LLM can read one variable at a time to produce bounded output
(classification, summary, extraction) without tainting the planner's context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .lattice import IntegrityLattice, ProductLattice, security_label


@dataclass(frozen=True)
class StoredVariable:
    """A variable stored in memory with its security label."""

    variable_id: str
    content: str
    label: ProductLattice
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_trusted(self) -> bool:
        return self.label.integrity.leq(IntegrityLattice.trusted())

    def to_dict(self) -> dict[str, Any]:
        return {
            "variable_id": self.variable_id,
            "label": repr(self.label),
            "source": self.source,
            "content_length": len(self.content),
            "is_trusted": self.is_trusted,
        }


class VariableStore:
    """Client-side variable memory for selective hiding.

    Stores untrusted content behind opaque $VAR_n handles. The planning context
    sees only the variable ID, not the raw content. Content can only be accessed
    through controlled expansion (which taints context) or quarantined LLM queries
    (which process one variable in isolation).

    This matches the VariablePassingPlanner.memory pattern from fides/Tutorial.ipynb.
    """

    def __init__(self) -> None:
        self._storage: dict[str, StoredVariable] = {}
        self._counter: int = 0

    def store(
        self,
        content: str,
        label: ProductLattice,
        *,
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store content and return an opaque variable handle.

        Args:
            content: The raw content to hide.
            label: The security label for the content.
            source: Description of where this content came from.
            metadata: Additional metadata about the variable.

        Returns:
            A variable ID string (e.g., "$VAR_1").
        """
        self._counter += 1
        var_id = f"$VAR_{self._counter}"
        self._storage[var_id] = StoredVariable(
            variable_id=var_id,
            content=content,
            label=label,
            source=source,
            metadata=metadata or {},
        )
        return var_id

    def retrieve(self, var_id: str) -> StoredVariable:
        """Retrieve a stored variable by its handle.

        This should only be called by the Quarantined LLM path or during
        controlled variable expansion.

        Raises:
            KeyError: If the variable ID doesn't exist.
        """
        if var_id not in self._storage:
            raise KeyError(f"Variable {var_id} not found in store")
        return self._storage[var_id]

    def exists(self, var_id: str) -> bool:
        """Check if a variable ID exists."""
        return var_id in self._storage

    def list_variables(self) -> list[str]:
        """List all stored variable IDs."""
        return list(self._storage.keys())

    def get_label(self, var_id: str) -> ProductLattice:
        """Get the security label of a stored variable without revealing content."""
        return self.retrieve(var_id).label

    def redacted_view(self, var_id: str) -> str:
        """Return a safe representation for the planning context.

        The planner sees this instead of the raw content.
        """
        var = self.retrieve(var_id)
        return (
            f"[{var_id}: {var.source or 'stored content'}, "
            f"integrity={var.label.integrity}, "
            f"length={len(var.content)} chars]"
        )

    def clear(self) -> None:
        """Clear all stored variables."""
        self._storage.clear()

    @property
    def count(self) -> int:
        """Number of stored variables."""
        return len(self._storage)

    def should_hide(self, label: ProductLattice) -> bool:
        """Determine if content with this label should be hidden.

        Content is hidden when its integrity is untrusted (not ⊑ T).
        """
        return not label.integrity.leq(IntegrityLattice.trusted())


def store_if_untrusted(
    store: VariableStore,
    content: str,
    label: ProductLattice,
    *,
    source: str = "",
) -> str:
    """Store content if untrusted, otherwise return raw content.

    This is the primary entry point for selective hiding: tool results pass
    through this function, and only untrusted content gets hidden behind a handle.

    Returns:
        Either the raw content (if trusted) or a variable handle string (if untrusted).
    """
    if store.should_hide(label):
        var_id = store.store(content, label, source=source)
        return store.redacted_view(var_id)
    return content
