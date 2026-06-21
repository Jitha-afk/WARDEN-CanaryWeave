# FIDES Judge

FIDES is the second-stage judge layer for WARDEN misses. It is intentionally separate from deterministic rules.

## Invocation rule

The gate should call FIDES only when deterministic WARDEN stages allow a case. If regex or YARA-style rules block or quarantine, FIDES is not needed for that case.

## Input contract

FIDES receives only:

- normalized policy facts;
- safe structural features;
- policy context;
- deterministic miss summaries;
- opaque case IDs.

FIDES must not receive raw dataset payloads, raw prompts, raw completions, raw tool outputs, raw traces, credentials, or live sink details.

## Output contract

The judge returns structured fields:

- verdict: safe, unsafe, or uncertain;
- confidence between zero and one;
- reason codes;
- recommended decision: allow, quarantine, or block.

Reason codes should be short and non-sensitive, such as `low_integrity_consequential_action` or `protected_data_unapproved_sink`.

## Default mode

Provider calls are disabled by default. Milestone 1 defines the prompt contract only; it does not add provider wiring and does not touch core engine code.
