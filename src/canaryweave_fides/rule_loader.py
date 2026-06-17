"""Parser for the CanaryWeave WARDEN rule DSL (``.war`` rulesets).

The DSL is YARA-flavoured and line-oriented. A file is a ruleset of one or more
``rule`` blocks::

    rule CommandOrCodeExecutionRequest {
        meta:
            id          = cwfr-0106
            kind        = policy
            severity    = high
            action      = block_and_audit
            technique   = T1059 (Execution, analogical)
            description = "Untrusted content requesting command or code execution."
        signals:
            $exec_shape = feature(command_execution_shape)
            $no_grant   = capability(not_in_allowed)
        semantics:
            $exec_intent = "Content requests command, code, or shell execution." (0.70)
        judge:
            $exec_judge = "Do redacted facts request command or code execution?" (0.65)
        condition:
            ($exec_shape and $no_grant) or $exec_intent or $exec_judge
    }

Grammar conventions the parser relies on (and the authoring guide documents):

* A rule header is ``rule <Name> {`` with the opening brace ending the line.
* The closing ``}`` of a rule sits on its own line.
* Sections are introduced by ``meta:`` / ``patterns:`` / ``signals:`` /
  ``semantics:`` / ``judge:`` / ``condition:`` headers.
* One entry per line. ``meta`` entries are ``key = value``; detection entries are
  ``$name = <expr>``.
* Comments occupy a whole line and start with ``//`` or ``#``.

The parser produces the structured dict :func:`canaryweave_fides.rule_schema.validate_rule`
consumes, then returns the validated :class:`RuleDefinition` objects.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .rule_schema import (
    RuleDefinition,
    RuleValidationError,
    _split_regex_literal,
    _split_top_level,
    validate_rule,
)


class RuleParseError(RuleValidationError):
    """Raised when ``.war`` source cannot be tokenized into rule blocks."""


_RULE_HEADER_RE = re.compile(r"^rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{$")
_SECTION_HEADER_RE = re.compile(r"^(meta|patterns|signals|semantics|judge|condition)\s*:(.*)$")
_META_ENTRY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_TERM_ENTRY_RE = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_SIGNAL_CTOR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$")
_SCORED_RE = re.compile(r"^(.*?)\(\s*([0-9]*\.?[0-9]+)\s*\)\s*$")
_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d*\.\d+$")

_DETECTION_SECTIONS = {"patterns", "signals", "semantics", "judge"}


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("#")


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return token


def _interpret_scalar(token: str) -> Any:
    token = token.strip()
    if not token:
        return ""
    if token[0] == '"':
        return _unquote(token)
    if token[0] == "[" and token[-1] == "]":
        return [_interpret_scalar(item) for item in _split_top_level(token[1:-1])]
    lowered = token.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if _INT_RE.match(token):
        return int(token)
    if _FLOAT_RE.match(token):
        return float(token)
    return token


def _interpret_meta_value(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] == '"':
        return _unquote(raw)
    if raw[0] == "[" and raw[-1] == "]":
        return [_interpret_scalar(item) for item in _split_top_level(raw[1:-1])]
    lowered = raw.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    # Everything else (ids, enums, version strings, technique anchors) stays a
    # raw string; rule_schema interprets controlled fields and technique anchors.
    return raw


def _parse_pattern_rhs(name: str, rhs: str) -> dict[str, Any]:
    rhs = rhs.strip()
    literal = _split_regex_literal(rhs)
    if literal is not None:
        pattern, flags = literal
        return {"name": name, "type": "regex", "pattern": pattern, "flags": flags}
    if rhs and rhs[0] == '"':
        return {"name": name, "type": "exact", "value": _unquote(rhs)}
    raise RuleParseError(f"pattern ${name} must be a /regex/flags literal or a \"quoted\" string, got: {rhs!r}")


def _parse_signal_rhs(name: str, rhs: str) -> dict[str, Any]:
    match = _SIGNAL_CTOR_RE.match(rhs.strip())
    if not match:
        raise RuleParseError(f"signal ${name} must be a constructor like feature(...), got: {rhs!r}")
    ctor = match.group(1)
    arg_text = match.group(2).strip()
    args = [_interpret_scalar(token) for token in _split_top_level(arg_text)] if arg_text else []
    return {"name": name, "ctor": ctor, "args": args}


def _parse_scored_rhs(name: str, rhs: str, *, key: str) -> dict[str, Any]:
    match = _SCORED_RE.match(rhs.strip())
    if not match:
        raise RuleParseError(f"${name} must look like \"text\" (0.70), got: {rhs!r}")
    text = match.group(1).strip()
    if not (len(text) >= 2 and text[0] == '"' and text[-1] == '"'):
        raise RuleParseError(f"${name} text must be quoted, got: {text!r}")
    return {"name": name, key: _unquote(text), "threshold": float(match.group(2))}


def _finalize_condition(lines: list[str]) -> str:
    return " ".join(part.strip() for part in lines if part.strip()).strip()


def parse_ruleset(text: str, *, source: str = "<string>") -> tuple[RuleDefinition, ...]:
    """Parse ``.war`` source into validated rules.

    Raises :class:`RuleParseError` for structural problems and
    :class:`RuleValidationError` for semantic ones, both annotated with ``source``.
    """
    rules: list[RuleDefinition] = []
    current: dict[str, Any] | None = None
    section: str | None = None
    condition_lines: list[str] = []

    def flush_rule(line_no: int) -> None:
        nonlocal current, section, condition_lines
        if current is None:
            return
        current["condition"] = _finalize_condition(condition_lines)
        try:
            rules.append(validate_rule(current))
        except RuleValidationError as exc:
            raise RuleValidationError(f"{source}: rule {current.get('name', '?')}: {exc}") from exc
        current = None
        section = None
        condition_lines = []

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or _is_comment(line):
            continue

        header = _RULE_HEADER_RE.match(line)
        if header:
            if current is not None:
                raise RuleParseError(f"{source}:{line_no}: nested rule '{header.group(1)}' before previous rule closed")
            current = {
                "name": header.group(1),
                "meta": {},
                "patterns": [],
                "signals": [],
                "semantics": [],
                "judge": [],
            }
            section = None
            condition_lines = []
            continue

        if current is None:
            raise RuleParseError(f"{source}:{line_no}: expected 'rule <Name> {{', got: {line!r}")

        if line == "}":
            flush_rule(line_no)
            continue

        section_header = _SECTION_HEADER_RE.match(line)
        if section_header:
            section = section_header.group(1)
            trailing = section_header.group(2).strip()
            if section == "condition":
                condition_lines = [trailing] if trailing else []
            elif trailing:
                raise RuleParseError(f"{source}:{line_no}: '{section}:' header should not carry inline content")
            continue

        if section is None:
            raise RuleParseError(f"{source}:{line_no}: entry outside any section: {line!r}")

        if section == "condition":
            condition_lines.append(line)
            continue

        if section == "meta":
            entry = _META_ENTRY_RE.match(line)
            if not entry:
                raise RuleParseError(f"{source}:{line_no}: meta entry must be 'key = value', got: {line!r}")
            current["meta"][entry.group(1)] = _interpret_meta_value(entry.group(2))
            continue

        entry = _TERM_ENTRY_RE.match(line)
        if not entry:
            raise RuleParseError(f"{source}:{line_no}: {section} entry must be '$name = ...', got: {line!r}")
        name, rhs = entry.group(1), entry.group(2)
        if section == "patterns":
            current["patterns"].append(_parse_pattern_rhs(name, rhs))
        elif section == "signals":
            current["signals"].append(_parse_signal_rhs(name, rhs))
        elif section == "semantics":
            current["semantics"].append(_parse_scored_rhs(name, rhs, key="description"))
        elif section == "judge":
            current["judge"].append(_parse_scored_rhs(name, rhs, key="prompt"))

    if current is not None:
        raise RuleParseError(f"{source}: rule '{current.get('name', '?')}' is missing its closing '}}'")
    if not rules:
        raise RuleParseError(f"{source}: no rules found")
    return tuple(rules)


def load_rule_file(path: Path | str) -> tuple[RuleDefinition, ...]:
    p = Path(path)
    return parse_ruleset(p.read_text(encoding="utf-8"), source=str(p))


def load_rules(root: Path | str) -> tuple[RuleDefinition, ...]:
    root_path = Path(root)
    if not root_path.exists():
        raise FileNotFoundError(f"rules root does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"rules root is not a directory: {root_path}")
    paths = sorted(root_path.rglob("*.war"))
    if not paths:
        raise RuleValidationError(f"No .war rules found under: {root_path}")
    rules: list[RuleDefinition] = []
    ids: dict[str, str] = {}
    names: dict[str, str] = {}
    for path in paths:
        for rule in load_rule_file(path):
            if rule.id in ids:
                raise RuleValidationError(f"Duplicate rule id {rule.id} in {path} (also in {ids[rule.id]})")
            if rule.name in names:
                raise RuleValidationError(f"Duplicate rule name {rule.name} in {path} (also in {names[rule.name]})")
            ids[rule.id] = str(path)
            names[rule.name] = str(path)
            rules.append(rule)
    return tuple(rules)
