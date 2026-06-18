from __future__ import annotations

import keyword

import pytest

from canaryweave_fides.fact_registry import (
    FACT_NAMES,
    FACT_SPECS,
    FROZEN_FACTS,
    UnknownFactError,
    fact_spec,
    is_fact,
)


EXPECTED_FACTS = (
    "from_untrusted_origin",
    "capability_denied",
    "canary_outside_sink",
    "tool_call_shape",
    "hidden_unicode",
    "instruction_shape",
)


def test_registry_is_the_six_frozen_facts_in_order():
    assert tuple(spec.name for spec in FROZEN_FACTS) == EXPECTED_FACTS
    assert FACT_NAMES == frozenset(EXPECTED_FACTS)


def test_every_fact_name_is_a_valid_bare_token():
    # Facts are referenced as ``$name`` in a condition, so each must be a plain
    # identifier that is not a Python/boolean keyword.
    for name in FACT_NAMES:
        assert name.isidentifier()
        assert not keyword.iskeyword(name)


def test_every_fact_has_a_summary_and_mcp_source():
    for spec in FROZEN_FACTS:
        assert spec.summary.strip()
        assert spec.mcp_source.strip()


def test_is_fact_discriminates_known_and_unknown():
    assert is_fact("from_untrusted_origin")
    assert not is_fact("command_execution_shape")  # a *_shape intent → semantics, not a fact
    assert not is_fact("")


def test_fact_spec_lookup_and_unknown_error():
    assert fact_spec("hidden_unicode").summary
    assert FACT_SPECS["hidden_unicode"] is fact_spec("hidden_unicode")
    with pytest.raises(UnknownFactError):
        fact_spec("not_a_fact")
