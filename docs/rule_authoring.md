# Rule Authoring

CanaryWeave FIDES rules should be written as portable policy shapes, not as memorized dataset strings.

## Good rule properties

A good WARDEN rule is:

- declarative and reviewable;
- tied to origin, surface, capability, sink, data label, canary, or structural facts;
- independent of a single dataset split;
- backed by synthetic fixtures;
- explicit about severity, category, scope, and recommended action;
- safe to publish without raw payload content.

## Current executable format

The current executable rules live in `rules/` as `.war` files. They include metadata, signals, a boolean condition, recommended action, fixtures, and safety notes.

The Milestone 1 `data/yara/` files are manifests for the future Vigil-style harness. They point at the current rules and define how the rule sets participate in the evaluation ladder.

## Rule review checklist

Before committing a rule, verify that it:

1. avoids raw adversarial text and raw prompt fragments;
2. detects a stable policy shape;
3. uses public-safe synthetic fixture names;
4. includes clear safety notes;
5. can be explained to a defender without engine internals;
6. does not require provider calls.

## Transferability goal

Prefer rules that can fire across ASB, AgentDefenseBench, and synthetic cases when the same policy violation appears. Dataset-specific signatures should be marked and minimized.
