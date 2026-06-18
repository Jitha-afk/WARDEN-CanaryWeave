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
    """Return a valid rules root or raise a clear portability error.

    Rules are authored as multi-rule rulesets, so the on-disk ``.war`` *file*
    count is not meaningful; the guard only confirms the tree exists and ships at
    least one ruleset. The exact rule count is asserted by the test suite via the
    loader instead.
    """
    rules = Path(root)
    if not rules.exists():
        raise FileNotFoundError(f"rules root does not exist: {rules}")
    if not rules.is_dir():
        raise NotADirectoryError(f"rules root is not a directory: {rules}")
    if not any(rules.rglob("*.war")):
        raise RuntimeError(
            f"rules root {rules} contains no .war rulesets; packaged/source rules are missing"
        )
    return rules


def rules_root() -> Path:
    return validate_rules_root(resource_root() / "rules")


def conf_root() -> Path:
    return resource_root() / "conf"


def data_root() -> Path:
    return resource_root() / "data"
