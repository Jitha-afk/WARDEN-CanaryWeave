# CanaryWeave FIDES Rule Schema

Rules use `.war` files. The format is YAML-based and built for defender-authored policy detections: metadata, pattern blocks, semantic intent, FIDES judge checks, named protocol signals, boolean conditions, fixtures, and safety notes.

## Required fields

- `id`
- `name`
- `version`
- `category`
- `severity`: `low`, `medium`, `high`, or `critical`
- `scope`
- `description`
- `signals`
- `condition`
- `recommended_action`: `allow`, `audit`, `quarantine`, or `block_and_audit`
- `fixtures`
- `safety_notes`

## Optional sections

### `meta`

Use `meta` for authorship, lifecycle, references, ATT&CK/D3FEND mappings, false-positive guidance, data requirements, and rule maturity.

### `keywords`

Use `keywords` for exact, regex, or feature-backed deterministic patterns. These are the fastest WARDEN checks and should be narrow enough to avoid overblocking benign content.

### `semantics`

Use `semantics` for meaning-level detection intent. A semantic item has a `description` and a `threshold` between `0.0` and `1.0`. The current implementation validates this section and treats it as a planned scoring input.

### `fides`

Use `fides` for redacted-fact judge checks. A FIDES item has a prompt and threshold. FIDES checks are only evaluated after deterministic WARDEN checks miss.

### `signals`

Use `signals` for structured protocol facts such as origin, surface, capability, sink, canary movement, schema shape, and text-structure features.

Initial signal types:

- `event_field_equals`
- `event_field_in`
- `schema_shape`
- `capability_policy` with `not_in_allowed_capabilities`
- `canary_flow` with `outside_allowed_sink`
- `text_structure` with `hidden_unicode` or `untrusted_instruction_shape`

## Condition syntax

Conditions support `and`, `or`, `not`, parentheses, bare signal names, and namespaced references:

```text
signals.source_is_untrusted and (signals.capability_not_granted or fides.policy_violation_judge)
```

Supported namespaces:

- `signals.<name>`
- `keywords.<name>`
- `semantics.<name>`
- `fides.<name>`

The validator checks that every condition identifier refers to a declared rule term.
