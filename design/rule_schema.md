# WARDEN `.war` Rule DSL Schema

A `.war` file is a ruleset: one or more YARA-style rule blocks. Each block declares rule identity in `meta:`, up to four detection layers, and one `condition:` over named terms.

```war
rule ServerSamplingOriginBoundary {
    meta:
        id          = cwfr-0001
        kind        = policy
        version     = 0.2.0
        severity    = high
        scope       = event_window
        action      = block_and_audit
        technique   = T1059 (Execution, analogical)
        defense     = D3-AM (Access Mediation)
        description = "Server-originated sampled content is acting as host-authoritative tool policy."

    signals:
        $origin_server_sampling = event_field_equals(origin, server_sampling)
        $tool_plan_shape        = schema_shape(tool_plan_like_json)
        $no_grant               = capability(not_in_allowed)

    semantics:
        $authority_intent = "Untrusted content is attempting to act as host or user authority for tool dispatch." (0.70)

    judge:
        $authority_judge = "Assess whether redacted facts show untrusted content causing a consequential tool action without authority." (0.65)

    condition:
        ($origin_server_sampling and $tool_plan_shape and $no_grant) or $authority_intent or $authority_judge
}
```

## File grammar

- Rule header: `rule <Name> {` with `{` ending the line.
- Rule close: `}` on its own line.
- Section headers: `meta:`, `patterns:`, `signals:`, `semantics:`, `judge:`, `condition:`.
- One entry per line. Full-line comments start with `//` or `#`.
- Detection terms are `$name = ...`; names are unique per rule across all layers.

## `meta:`

Entries are `key = value`. Bare values are used for ids, enums, anchors, booleans, and numbers; free text is double-quoted; lists use `[a, b]`; booleans are `true` or `false`.

Required by validation:

- `id`: stable rule id, must start with `cwfr-`.
- `kind`: `signature` or `policy`.
- `severity`: `low`, `medium`, `high`, or `critical`.
- `technique`: at least one ATT&CK or ATLAS technique anchor.

Recognized fields with defaults or optional use:

- `version`: defaults to `0.1.0`.
- `scope`: defaults to `event_window`.
- `description`: defaults to empty text.
- `action`: `allow`, `audit`, `quarantine`, or `block_and_audit`; defaults to `audit`.
- `defense`: optional D3FEND-only defense anchor.
- `safety`: optional public-safety guidance.
- `author`, `status`, and other extra meta keys are retained as free-form metadata.

### Technique anchors

Use compact anchors such as:

```war
technique = T1059 (Execution, analogical)
defense   = D3-AM (Access Mediation)
```

The framework is inferred from the id prefix: `T<digit>` is ATT&CK, `AML.T` is ATLAS, and `D3-` is D3FEND. The first parenthesized item is the MITRE tactic. The optional second item is `direct` or `analogical`. `defense` anchors must be D3FEND ids.

## Detection layers

### `patterns:`

Text indicators over custody-safe text:

```war
$path  = /(?:id_rsa|private[_-]?key|\.pem$)/i
$exact = "mcp.json"
```

Regex literals use `/pattern/flags`; supported flags are Python regex flags `i`, `m`, `s`, `x`, `a`, and `u`. Exact substrings are case-insensitive.

### `signals:`

Structured facts over the NormalizedTrace and policy context:

- `feature(flag)` or `feature(flag, false)`
- `capability(not_in_allowed)`
- `canary_flow(outside_allowed_sink)`
- `schema_shape(shape)`
- `origin(value, ...)`
- `sink_in(value, ...)`
- `text_structure(hidden_unicode)` or `text_structure(untrusted_instruction_shape)`
- `event_field_equals(field, value)`
- `event_field_in(field, [a, b])` or `event_field_in(field, a, b)`
- `event_field_contains(field, value)`

### `semantics:`

Engine-scored similarity checks:

```war
$exec_intent = "Content requests command, code, script, shell, or interpreter-like execution." (0.70)
```

The trailing threshold is numeric and must be between `0.0` and `1.0`.

### `judge:`

FIDES judge questions:

```war
$exec_judge = "Assess whether redacted facts indicate untrusted content is requesting command or code execution." (0.65)
```

Under `rules_plus_fides`, when deterministic WARDEN policy layers miss, the gate routes these per-rule questions to the FIDES/IFC judge path as miss-context. The judge path is separate from the quarantined task model.

## `condition:`

Conditions use bare `$term` references plus `and`, `or`, `not`, and parentheses:

```war
($exec_shape and $no_grant) or $exec_intent or $exec_judge
```

Quantifier sugar is supported:

- `any of patterns`, `all of signals`, `any of semantics`, `all of judge`
- `any of them` or `all of them` for all declared terms
- `any of ($a, $b)` or `all of ($a, $b)` for explicit term lists

## Validation rules

The validator enforces the defender-facing contract:

- `id`, `kind`, `severity`, and at least one ATT&CK or ATLAS `technique` are required.
- `kind = signature` must declare `patterns:` and may not declare `signals:`, `semantics:`, or `judge:`.
- `kind = policy` must declare at least one of `signals:`, `semantics:`, or `judge:`; it may also use `patterns:`.
- Every declared `$term` must appear in `condition:`.
- Every `$term` in `condition:` must be declared.
- `$term` names must be unique across all layers within a rule.
- Empty layer quantifiers, invalid regex flags, invalid thresholds, invalid enum values, and non-D3FEND `defense` anchors are rejected.

The `kind` rule prevents signatures from claiming policy-level reasoning. The no-dead-terms rule prevents copied but unused evidence, which keeps rules auditable for defenders.
