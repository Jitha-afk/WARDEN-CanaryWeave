# Attack-to-Rule Mapping Schema

WARDEN rule correctness is evaluated with explicit public-safe mappings between dataset-neutral cases and expected detections. The mapping schema keeps ground truth separate from detector facts: adapters may emit safe features, but expected outcomes live in mapping metadata and are used only for scoring/review.

## Required fields

- `mapping_id`: stable public mapping identifier.
- `case_id`: opaque case identifier.
- `dataset_id`: source dataset such as `synthetic`, `asb`, or `agentdefensebench`.
- `source_tier`: `synthetic`, `local_private`, or `public_safe_export`.
- `policy_violation_id`: stable policy-shape identifier.
- `surface`: prompt/tool/API/MCP surface label.
- `origin_class`: source/provenance class.
- `impact_class`: one or more effects such as consequential action or protected data flow.
- `evasion_class`: obfuscation/evasion label, or `none`.
- `expected_behavior`: `allow`, `quarantine`, or `block`.
- `expected_rule_ids`: WARDEN `cwfr-*` rule IDs expected to fire.
- `expected_fides_checks`: FIDES checks expected to catch WARDEN misses.
- `should_not_fire_rule_ids`: false-positive guardrails.
- `required_fields`: telemetry fields required for a fair rule evaluation.
- `required_correlation`: same-event/window or source-to-action/source-to-sink requirements.
- `benign_near_miss_controls`: benign cases that should not trigger the rule.
- `external_mappings`: optional ATT&CK/D3FEND-style references with caveat notes.

## Safety requirements

Mappings must not contain raw payload text, raw prompts, provider transcripts, or raw-to-case pointers. They may contain category labels, opaque IDs, rule IDs, reason codes, and structural telemetry names.

## Validation

`canaryweave_fides.mappings.validate_mappings` checks that:

- mapping IDs are unique;
- expected and should-not-fire rule IDs are known;
- required telemetry is present;
- benign near-miss controls are present;
- expected behavior is valid.
