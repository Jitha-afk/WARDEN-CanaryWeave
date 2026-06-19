"""Formal Information-Flow Control lattice abstractions.

Implements the lattice structures from the FIDES paper (Costa et al., 2025):
- Integrity lattice: {T (trusted) ⊑ U (untrusted)}
- Confidentiality lattice: {L (public) ⊑ H (secret)}
- Powerset lattice for reader/writer sets (ordered by inverse subset)
- Product lattice combining integrity + confidentiality

The join operation (⊔) computes the least upper bound — the most restrictive
label when combining data from multiple sources. This is the core of label
propagation: if data z is derived from x and y, then ℓ_z = ℓ_x ⊔ ℓ_y.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class Lattice(ABC):
    """Abstract base class for bounded IFC lattices.

    A lattice is a partially ordered set where every pair of elements has
    a least upper bound (join) and greatest lower bound (meet).
    """

    @abstractmethod
    def leq(self, other: Any) -> bool:
        """Return True if self ⊑ other in the lattice ordering."""

    @abstractmethod
    def join(self, other: Any) -> "Lattice":
        """Return the least upper bound (⊔) of self and other."""

    @abstractmethod
    def meet(self, other: Any) -> "Lattice":
        """Return the greatest lower bound (⊓) of self and other."""

    def __le__(self, other: "Lattice") -> bool:
        return self.leq(other)

    def __ge__(self, other: "Lattice") -> bool:
        if not isinstance(other, Lattice):
            return NotImplemented
        return other.leq(self)

    @abstractmethod
    def __repr__(self) -> str:
        ...

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        ...

    @abstractmethod
    def __hash__(self) -> int:
        ...


# ---------------------------------------------------------------------------
# Standard Integrity Lattice: {T ⊑ U}
# ---------------------------------------------------------------------------


class IntegrityLevel(Enum):
    TRUSTED = 0
    UNTRUSTED = 1


class IntegrityLattice(Lattice):
    """Two-element integrity lattice: T (trusted) ⊑ U (untrusted).

    T ⊔ T = T, T ⊔ U = U, U ⊔ U = U (untrusted wins).
    """

    def __init__(self, level: IntegrityLevel) -> None:
        self.level = level

    def leq(self, other: Any) -> bool:
        if not isinstance(other, IntegrityLattice):
            return NotImplemented
        return self.level.value <= other.level.value

    def join(self, other: Any) -> "IntegrityLattice":
        if not isinstance(other, IntegrityLattice):
            raise TypeError(f"Cannot join IntegrityLattice with {type(other)}")
        return other if self.leq(other) else self

    def meet(self, other: Any) -> "IntegrityLattice":
        if not isinstance(other, IntegrityLattice):
            raise TypeError(f"Cannot meet IntegrityLattice with {type(other)}")
        return self if self.leq(other) else other

    def __repr__(self) -> str:
        return self.level.name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, IntegrityLattice):
            return self.level == other.level
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.level)

    @classmethod
    def trusted(cls) -> "IntegrityLattice":
        return cls(IntegrityLevel.TRUSTED)

    @classmethod
    def untrusted(cls) -> "IntegrityLattice":
        return cls(IntegrityLevel.UNTRUSTED)


# ---------------------------------------------------------------------------
# Standard Confidentiality Lattice: {L ⊑ H}
# ---------------------------------------------------------------------------


class ConfidentialityLevel(Enum):
    PUBLIC = 0
    SECRET = 1


class ConfidentialityLattice(Lattice):
    """Two-element confidentiality lattice: L (public) ⊑ H (secret).

    L ⊔ H = H (secret wins).
    """

    def __init__(self, level: ConfidentialityLevel) -> None:
        self.level = level

    def leq(self, other: Any) -> bool:
        if not isinstance(other, ConfidentialityLattice):
            return NotImplemented
        return self.level.value <= other.level.value

    def join(self, other: Any) -> "ConfidentialityLattice":
        if not isinstance(other, ConfidentialityLattice):
            raise TypeError(f"Cannot join ConfidentialityLattice with {type(other)}")
        return other if self.leq(other) else self

    def meet(self, other: Any) -> "ConfidentialityLattice":
        if not isinstance(other, ConfidentialityLattice):
            raise TypeError(f"Cannot meet ConfidentialityLattice with {type(other)}")
        return self if self.leq(other) else other

    def __repr__(self) -> str:
        return self.level.name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ConfidentialityLattice):
            return self.level == other.level
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.level)

    @classmethod
    def public(cls) -> "ConfidentialityLattice":
        return cls(ConfidentialityLevel.PUBLIC)

    @classmethod
    def secret(cls) -> "ConfidentialityLattice":
        return cls(ConfidentialityLevel.SECRET)


# ---------------------------------------------------------------------------
# Powerset Lattice (for reader/writer sets)
# ---------------------------------------------------------------------------


class PowersetLattice(Lattice):
    """Powerset lattice ordered by inverse subset inclusion.

    Used for confidentiality as a readers lattice: a label describes the set of
    authorized readers. Join is set intersection (fewer readers = more restrictive).

    Example: {A,B,C} ⊔ {B,C,D} = {B,C} — only common readers remain.
    """

    def __init__(self, subset: frozenset[str], universe: frozenset[str]) -> None:
        if not subset.issubset(universe):
            raise ValueError("subset must be contained in universe")
        self.subset = subset
        self.universe = universe

    def leq(self, other: Any) -> bool:
        """self ⊑ other iff self.subset ⊇ other.subset (inverse inclusion)."""
        if not isinstance(other, PowersetLattice):
            return NotImplemented
        return self.subset.issuperset(other.subset)

    def join(self, other: Any) -> "PowersetLattice":
        """Join is set intersection (most restrictive readers)."""
        if not isinstance(other, PowersetLattice):
            raise TypeError(f"Cannot join PowersetLattice with {type(other)}")
        return PowersetLattice(
            subset=self.subset & other.subset,
            universe=self.universe | other.universe,
        )

    def meet(self, other: Any) -> "PowersetLattice":
        """Meet is set union (least restrictive readers)."""
        if not isinstance(other, PowersetLattice):
            raise TypeError(f"Cannot meet PowersetLattice with {type(other)}")
        return PowersetLattice(
            subset=self.subset | other.subset,
            universe=self.universe | other.universe,
        )

    def __repr__(self) -> str:
        return f"Readers({{{', '.join(sorted(self.subset))}}})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PowersetLattice):
            return self.subset == other.subset
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.subset)


# ---------------------------------------------------------------------------
# Product Lattice (combines integrity + confidentiality)
# ---------------------------------------------------------------------------


class ProductLattice(Lattice):
    """Product of two lattices: operations applied component-wise.

    Typically: ProductLattice(IntegrityLattice, ConfidentialityLattice) or
    ProductLattice(IntegrityLattice, PowersetLattice).
    """

    def __init__(self, left: Lattice, right: Lattice) -> None:
        self.left = left
        self.right = right

    def leq(self, other: Any) -> bool:
        if not isinstance(other, ProductLattice):
            return NotImplemented
        return self.left.leq(other.left) and self.right.leq(other.right)

    def join(self, other: Any) -> "ProductLattice":
        if not isinstance(other, ProductLattice):
            raise TypeError(f"Cannot join ProductLattice with {type(other)}")
        return ProductLattice(
            left=self.left.join(other.left),
            right=self.right.join(other.right),
        )

    def meet(self, other: Any) -> "ProductLattice":
        if not isinstance(other, ProductLattice):
            raise TypeError(f"Cannot meet ProductLattice with {type(other)}")
        return ProductLattice(
            left=self.left.meet(other.left),
            right=self.right.meet(other.right),
        )

    def __repr__(self) -> str:
        return f"({self.left}, {self.right})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ProductLattice):
            return self.left == other.left and self.right == other.right
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.left, self.right))

    @property
    def integrity(self) -> Lattice:
        return self.left

    @property
    def confidentiality(self) -> Lattice:
        return self.right


# ---------------------------------------------------------------------------
# Convenience: SecurityLabel type alias
# ---------------------------------------------------------------------------

def security_label(
    integrity: IntegrityLattice | None = None,
    confidentiality: ConfidentialityLattice | None = None,
) -> ProductLattice:
    """Create a standard security label (integrity × confidentiality)."""
    return ProductLattice(
        left=integrity or IntegrityLattice.trusted(),
        right=confidentiality or ConfidentialityLattice.public(),
    )


def trusted_public() -> ProductLattice:
    """Bottom of the security lattice: trusted + public (least restrictive)."""
    return security_label(IntegrityLattice.trusted(), ConfidentialityLattice.public())


def untrusted_secret() -> ProductLattice:
    """Top of the security lattice: untrusted + secret (most restrictive)."""
    return security_label(IntegrityLattice.untrusted(), ConfidentialityLattice.secret())
