# Datasets

The harness treats every source as a dataset adapter that emits the same public-safe case envelope.

## Supported specs

- `data/datasets/synthetic.yaml`: always available, CI-safe, hand-authored structural cases.
- `data/datasets/asb.yaml`: optional local ASB adapter contract. Raw source material remains private.
- `data/datasets/agentdefensebench.yaml`: optional local AgentDefenseBench adapter contract. Missing local paths are reported as skipped.

## Case envelope

Adapters should emit:

- opaque `case_id`;
- `dataset_id` and split;
- attack or benign label;
- shared category and surface labels;
- safe structural features;
- policy context;
- expected behavior.

Raw payload pointers may exist only in private local manifests. They must not be exported in public reports.

## Public export boundary

Allowed public fields include opaque IDs, labels, structural booleans, lengths, counts, hashes, policy labels, rule IDs, reason codes, and aggregate metrics.

Disallowed public fields include raw prompts, raw completions, raw tool outputs, raw traces, provider transcripts, and raw-to-case mappings.

## Missing optional datasets

Optional datasets should not break CI. If a local AgentDefenseBench path is not configured, the report should include `skipped_missing_local_path` for that dataset.
