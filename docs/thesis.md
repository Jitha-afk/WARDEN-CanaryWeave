# Thesis

CanaryWeave FIDES evaluates a narrow security claim:

Defender-maintainable deterministic policy rules should run before untrusted dataset content reaches an agent context window. A separate FIDES judge layer should then inspect only deterministic misses, using redacted policy facts rather than raw prompts or raw payloads.

## WARDEN and FIDES

WARDEN is the deterministic gate. In this POC it includes regex, YARA-style manifests, existing `.war` rules, and future OPA-like policy engines.

FIDES is a separate LLM-as-judge layer for WARDEN misses. It is not the rule engine. It receives a public-safe policy view and returns a structured verdict.

## Defense ladder

Every evaluation stack should be measured separately:

1. `no_guard`: unguarded baseline.
2. `regex_baseline`: shallow baseline over safe features.
3. `yara_rules`: defender-authored deterministic policy rules.
4. `rules_plus_fides`: deterministic rules first, FIDES only on misses.

## Proof target

The harness should show more than raw block rate. It should report attack success rate reduction, benign overblock, deterministic catch rate, FIDES incremental catch rate, and rule reuse across datasets.

## Safety boundary

Public artifacts must not contain raw dataset payloads, raw prompts, raw completions, tool outputs, judge transcripts, or raw-to-case mappings. Reports should contain aggregate metrics, opaque IDs, rule IDs, reason codes, and synthetic examples only.
