# Policy Rules, OPA/Rego, and FIDES Research Framing

## Source-grounded anchors

OPA describes itself as a general-purpose policy engine that decouples policy decision-making from policy enforcement. Software supplies structured data as input, and OPA evaluates that input against declarative policies. Its philosophy page emphasizes that policies should be specified declaratively, updated without recompiling or redeploying services, and managed by the people responsible for policy.

Human-reviewable detection rules are useful because they combine metadata, named signals, condition logic, tests, and optional semantic or judge-assisted sections. This POC uses that defender-friendly shape while keeping its own YAML schema, rule IDs, payload safety model, and MCP-native assumptions.

FIDES/IFC contributes a second layer: track confidentiality and integrity labels, propagate taint, enforce trusted-action and permitted-flow policies, and use quarantined inspection only through controlled interfaces.

## Project philosophy

The defender should not hard-code every security decision inside the host application. Instead, the host emits structured MCP traces, and defenders author declarative rules that can be versioned, reviewed, tested, and measured.

That gives us a ladder:

1. `regex_guard`: text-only baseline.
2. `structured_rule_guard`: declarative MCP-aware rules over NormalizedTrace.
3. `rules_plus_fides_ifc`: deterministic rules plus information-flow policy checks.
4. Optional later: LLM arbitration for ambiguous cases, reported as secondary and never treated as primary ground truth.

## Claim boundary

The claim is not universal MCP security. The claim is controlled-benchmark evidence that structured policy detections can catch categories that regex misses, and that FIDES/IFC can block additional policy-relevant flows by reasoning over labels and causality.
