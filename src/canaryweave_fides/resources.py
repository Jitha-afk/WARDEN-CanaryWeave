from __future__ import annotations

from importlib import resources
from pathlib import Path

_PACKAGE = "canaryweave_fides"
EXPECTED_RULE_COUNT = 31


def source_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resource_root() -> Path:
    """Return the repo root in source checkouts, or packaged assets root.

    Source-tree development keeps conf/, data/, and rules/ at the project root.
    Wheels include a mirrored assets/ tree inside the Python package.
    """
    root = source_root()
    if (root / "rules").exists() and (root / "conf").exists() and (root / "data").exists():
        return root
    asset_root = resources.files(_PACKAGE).joinpath("assets")
    return Path(str(asset_root))


def validate_rules_root(root: Path | str, *, expected_count: int = EXPECTED_RULE_COUNT) -> Path:
    """Return a valid rules root or raise a clear portability error."""
    rules = Path(root)
    if not rules.exists():
        raise FileNotFoundError(f"rules root does not exist: {rules}")
    if not rules.is_dir():
        raise NotADirectoryError(f"rules root is not a directory: {rules}")
    rule_files = tuple(rules.rglob("*.war"))
    if len(rule_files) < expected_count:
        raise RuntimeError(
            f"rules root {rules} contains {len(rule_files)} .war rules; "
            f"expected at least {expected_count} .war rules in packaged/source rules"
        )
    return rules


def rules_root() -> Path:
    return validate_rules_root(resource_root() / "rules")


def conf_root() -> Path:
    return resource_root() / "conf"


def data_root() -> Path:
    return resource_root() / "data"
