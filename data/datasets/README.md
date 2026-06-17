# Dataset Specs

This directory contains public-safe dataset specifications for the CanaryWeave FIDES harness.

The specs are manifests and contracts, not raw corpora. They describe how a dataset adapter should emit normalized, policy-relevant case metadata for the pre-context gate.

Public-safe rules:

- Do not commit raw dataset payloads.
- Do not commit raw prompts, completions, tool outputs, or judge transcripts.
- Use opaque case identifiers for real datasets.
- Export structural features, labels, counts, hashes, and policy context only.
- Keep raw-to-case mappings private.
- Synthetic examples may be committed only when hand-authored and non-operational.

Initial datasets:

- `synthetic.yaml`: always available, CI-safe structural fixtures.
- `asb.yaml`: optional controlled local adapter spec for ASB-derived redacted cases.
- `agentdefensebench.yaml`: optional controlled local adapter spec for AgentDefenseBench-derived redacted cases.
