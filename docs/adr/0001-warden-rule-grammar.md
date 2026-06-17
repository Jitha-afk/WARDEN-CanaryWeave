# ADR 0001: WARDEN rule grammar

## Status

Superseded by [ADR 0002](0002-warden-rule-dsl.md).

## Context

WARDEN `.war` rules are defender-authored detection rules over NormalizedTrace events. The grammar is deliberately small so defenders can describe policy intent without knowing engine internals, and so rules remain portable across the deterministic WARDEN engine and later FIDES/IFC judging stages.

The implemented grammar has three main detection primitives: deterministic `keywords`, engine-automated `semantics`, and FIDES/IFC `fides` checks. It also supports optional structured `signals`, which are the structured-power core for policy facts derived from origins, surfaces, capabilities, canary movement, sinks, safe features, and text structure.

## Decision

### Rule envelope

A rule must define:

- `name`
- `severity`: one of `low`, `medium`, `high`, `critical`
- `condition`
- at least one detection section: `signals`, `keywords`, `semantics`, or `fides`

The validator defaults these optional fields:

- `id`: slug of `name` using lowercase hyphenated text, or `rule` if the slug would be empty
- `version`: `0.1.0`
- `category`: `uncategorized`
- `scope`: `event_window`
- `description`: empty string
- `recommended_action`: `audit`; allowed values are `allow`, `audit`, `quarantine`, `block_and_audit`
- `fixtures`: `{positive: [], negative: []}`
- `safety_notes`: empty string
- `meta`: empty mapping
- missing detection sections: empty

### `signals`

`signals` is a list of `{name, type, ...params}` entries. Names must be unique within the section. Signals are evaluated by the deterministic engine over structured event fields, policy context, safe feature metadata, or supported text-structure helpers.

Implemented signal types are:

- `event_field_equals`: `field` equals `value`
- `event_field_in`: `field` is in `values`
- `schema_shape`: event `schema_shape` equals `shape`
- `capability_policy`: `relation: not_in_allowed_capabilities`
- `canary_flow`: `relation: outside_allowed_sink`
- `feature_flag`: metadata `feature` equals `value`, defaulting to `true`
- `event_field_contains`: case-insensitive substring in a field value
- `text_structure`: `feature` is `hidden_unicode` or `untrusted_instruction_shape`

### `keywords`

`keywords` may be either a keyed mapping or a structured list. Keyword names must be unique within the section.

The terse keyed-by-name form is:

```yaml
keywords:
  browser_credentials: '/\\Chrome\\User Data\\.*\\Login Data/i'
  jailbreak_phrase: ignore previous instructions
```

A string value beginning with `/` is parsed as `/pattern/flags`, where the closing delimiter is the final `/`. Regex flags are Python `re` flags `i`, `m`, `s`, `x`, `a`, and `u`. Other string values become case-insensitive exact substring matches.

The structured list form is:

```yaml
keywords:
  - name: execution_shape
    type: feature
    feature: command_execution_shape
  - name: suspicious_text
    type: exact
    value: ignore previous instructions
```

Structured keyword `type` may be `exact`, `regex`, or `feature`. `exact` and `regex` require `pattern` or `value`; `regex` is compiled with optional `flags`; `feature` reads truthiness from event metadata. Exact matching is case-insensitive unless `case_sensitive: true` is set. Text matching runs over custody-safe event text.

### `semantics`

`semantics` is a list of `{name, description, threshold?, ...params}` entries. `threshold` defaults to `0.5` and must be in `[0, 1]`. Semantics are engine-automated similarity: the deterministic engine computes a provider-free token-similarity score (multiset token cosine blended with a sequence-ratio fallback, in `[0, 1]`) between the event text and the pattern's `description` plus any optional `phrases`/`examples`, and the term is satisfied when that score meets `threshold` for any event in scope. This default stands in for an embedding model without adding dependencies.

### `fides`

`fides` is a list of `{name, prompt, threshold?, ...params}` entries. `threshold` defaults to `0.5` and must be in `[0, 1]`; extra fields such as confidence metadata are preserved as params. The design intent is to route a natural-language check to the FIDES/IFC judge. In the current deterministic engine, FIDES names are schema-validated and condition-routed, but evaluate inertly as false until the judge stage supplies results.

### Conditions

`condition` composes rule terms with `and`, `or`, `not`, boolean literals, and parentheses. Namespaced references use:

- `signals.<name>`
- `keywords.<name>`
- `semantics.<name>`
- `fides.<name>`

Bare names are accepted only for signal names, preserving compatibility with older signals-only rules.

The condition grammar also supports quantifier sugar:

- `any of <namespace>.*`
- `all of <namespace>.*`
- `any of (a, b)`
- `all of (a, b)`

Wildcard quantifiers are expanded from the terms defined in that namespace during validation. List quantifiers use the listed terms as written.

## Consequences

Defenders can author engine-independent `.war` rules while the deterministic engine keeps keyword and signal evaluation predictable. `semantics` and `fides` are the two smart extension points, validated by the same grammar but supplied by separate scorer and judge stages. Bare signal names and signals-only rules remain supported for back compatibility.
