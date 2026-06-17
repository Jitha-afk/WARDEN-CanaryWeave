from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from .rule_schema import RuleDefinition, RuleValidationError, validate_rule


def load_rule_file(path: Path | str) -> RuleDefinition:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuleValidationError(f"Rule file did not contain a mapping: {p}")
    return validate_rule(data)


def load_rules(root: Path | str) -> tuple[RuleDefinition, ...]:
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"rules root does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"rules root is not a directory: {root_path}")
    paths = sorted(root_path.rglob("*.war"))
    if not paths:
        raise RuleValidationError(f"No .war rules found under: {root_path}")
    rules = [load_rule_file(path) for path in paths]
    ids: set[str] = set()
    names: set[str] = set()
    for rule in rules:
        if rule.id in ids:
            raise RuleValidationError(f"Duplicate rule id: {rule.id}")
        if rule.name in names:
            raise RuleValidationError(f"Duplicate rule name: {rule.name}")
        ids.add(rule.id)
        names.add(rule.name)
    return tuple(rules)
