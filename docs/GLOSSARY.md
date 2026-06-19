# WARDEN-CanaryWeave Field Glossary

Complete reference for every field, type, and concept in the system.

---

## IFC Facts (6 Frozen Booleans)

These are the only boolean facts a `.war` rule can reference. They are computed by the framework from the MCP wire — rule authors cannot add new ones.

| Fact | Meaning | MCP Source | When True |
|---|---|---|---|
| `$from_untrusted_origin` | Content came from an untrusted MCP origin | `tools/call` result, `resources/read`, server manifest, `sampling/createMessage`, `notifications/message`, `roots/list_changed` | The origin field matches any untrusted MCP surface |
| `$capability_denied` | Requested tool/capability is not in the host's allowed set | `tools/list` + host roots/permissions | Agent tries to call a tool not in `policy.allowed_capabilities` |
| `$canary_outside_sink` | A canary marker is heading to a sink outside the allowed set | Data-flow overlay | `event.canary_present=True` AND `event.sink` not in `policy.allowed_canary_sinks` |
| `$tool_call_shape` | Message is structurally shaped like an MCP tool call/plan | `tools/call` schema | `event.schema_shape` is `tool_plan_like_json`, `tool_plan`, or `tool_call` |
| `$hidden_unicode` | Text carries invisible/zero-width/normalizing characters | Text normalizer | Zero-width chars detected OR NFKC normalization changes the text |
| `$instruction_shape` | Text is structurally shaped like injected instructions | Text normalizer | Generic instruction patterns, MCP role markers (`<\|im_start\|>`), or protocol injection shapes detected |

---

## Lattice Labels

| Label | Type | Values | Meaning |
|---|---|---|---|
| `integrity` | `IntegrityLattice` | `TRUSTED` / `UNTRUSTED` | Whether the content decision-context can be trusted. `T ⊔ U = U` (untrusted wins) |
| `confidentiality` | `ConfidentialityLattice` | `PUBLIC` / `SECRET` | Whether the data can be shared broadly. `L ⊔ H = H` (secret wins) |
| `readers` | `PowersetLattice` | Set of user IDs | Who is authorized to read this data. Join = intersection (fewer readers) |

**Lattice operations:**
- `leq(other)` — "can flow to": `self ⊑ other` means self is less restrictive
- `join(other)` — "combine": least upper bound, most restrictive label from both
- `meet(other)` — "intersect": greatest lower bound, least restrictive of both

---

## TraceEvent Fields

| Field | Type | Meaning |
|---|---|---|
| `event_id` | `str` | Unique identifier for this trace event |
| `origin` | `str` | MCP surface where content entered: `resource_content`, `tool_output`, `server_manifest`, `server_sampling`, `notification_message`, `roots_list_changed`, `prompts_get`, `user`, `host` |
| `surface` | `str` | Evaluation surface: `resource`, `prompt`, `tool_result` |
| `text` | `str` | Raw content text |
| `schema_shape` | `str \| None` | Structural shape: `tool_plan_like_json`, `tool_plan`, `tool_call`, or `None` |
| `capability` | `str \| None` | Requested tool/capability name |
| `sink` | `str \| None` | Target destination for data flow |
| `canary_present` | `bool` | Whether a canary/honeytoken marker was detected |
| `integrity` | `"high" \| "low"` | Integrity level (maps to lattice: high=TRUSTED, low=UNTRUSTED) |
| `confidentiality` | `"public" \| "restricted"` | Confidentiality level (maps to lattice: public=PUBLIC, restricted=SECRET) |
| `consequential_action` | `bool` | Whether this event represents a state-changing action |

---

## PolicyContext Fields

| Field | Type | Meaning |
|---|---|---|
| `allowed_capabilities` | `tuple[str, ...]` | Tools/capabilities the host permits |
| `allowed_canary_sinks` | `tuple[str, ...]` | Sinks where canary markers are allowed to appear |
| `trusted_origins` | `tuple[str, ...]` | Origins considered trusted (default: `user`, `host_policy`, `host`, `planner`) |
| `permitted_sinks` | `tuple[str, ...]` | Sinks that restricted data may flow to |

---

## EvaluationRecord Fields

| Field | Type | Meaning |
|---|---|---|
| `text` | `str` | Concatenated raw text from all trace events |
| `facts` | `dict[str, bool]` | The 6 frozen boolean facts computed from the trace |

---

## RuleDefinition Fields

| Field | Type | Meaning |
|---|---|---|
| `id` | `str` | Stable rule ID, must start with `cwfr-` |
| `name` | `str` | PascalCase rule name (e.g., `DirectInstructionOverride`) |
| `version` | `str` | Semver (e.g., `0.1.0`) |
| `severity` | `str` | `low` / `medium` / `high` / `critical` |
| `scope` | `str` | `event_window` / `text_field` / `trace` |
| `description` | `str` | Human-readable detection goal |
| `action` | `str` | `allow` / `audit` / `quarantine` / `block_and_audit` |
| `tactic` | `str` | MITRE tactic from technique anchor |
| `technique` | `tuple[TechniqueRef]` | ATT&CK / ATLAS / D3FEND anchors |
| `defense` | `tuple[TechniqueRef]` | D3FEND defense anchors |
| `condition` | `str` | Boolean expression over `$terms` and `$facts` |
| `patterns` | `tuple[PatternDef]` | Regex/exact text matchers |
| `facts` | `tuple[str]` | Referenced frozen fact names |
| `semantics` | `tuple[SemanticPattern]` | Similarity-based intent checks |
| `judge_checks` | `tuple[JudgeCheck]` | FIDES judge questions (escalated on miss) |

---

## GateDecision Fields

| Field | Type | Meaning |
|---|---|---|
| `stack` | `StackName` | Which stack produced this: `no_guard`, `regex_baseline`, `yara_rules`, `rules_plus_fides` |
| `decision` | `Decision` | `ALLOW` / `QUARANTINE` / `BLOCK` |
| `blocked_by` | `BlockedBy` | `NONE` / `REGEX` / `YARA_RULE` / `FIDES_JUDGE` |
| `rule_ids` | `tuple[str]` | IDs of rules that fired |
| `fides_verdict` | `FidesVerdict` | `SAFE` / `UNSAFE` / `UNCERTAIN` / `DISABLED` / `NOT_CALLED` |
| `reason_codes` | `tuple[str]` | Matched signal names |
| `latency_ms` | `float \| None` | FIDES judge API latency |
| `provider_calls` | `int` | Number of real LLM API calls made |

---

## Variable Memory

| Field | Type | Meaning |
|---|---|---|
| `$VAR_n` | Handle | Opaque reference to hidden content — planner sees this, not raw text |
| `StoredVariable.content` | `str` | The actual hidden content (only Quarantined LLM can read) |
| `StoredVariable.label` | `ProductLattice` | Security label (integrity × confidentiality) |
| `StoredVariable.is_trusted` | `bool` | `label.integrity.leq(TRUSTED)` — should never be True in store |

**Decision logic:** `store_if_untrusted(content, label)` → if `integrity = UNTRUSTED`, store behind `$VAR_n` and return redacted view. If `TRUSTED`, pass through unchanged.

---

## FIDES IFC Policies

| Policy | Formal Check | Meaning |
|---|---|---|
| **Trusted Action (P-T)** | `integrity.leq(TRUSTED) AND origin ∈ trusted_origins` | Consequential actions require trusted decision context |
| **Permitted Flow (P-F)** | `confidentiality.leq(PUBLIC) OR sink ∈ permitted_sinks` | Restricted data only flows to authorized sinks |

---

## Guard Stacks (evaluated in order)

| Stack | What it does | Speed | Catches |
|---|---|---|---|
| `no_guard` | Always allows | Instant | Nothing (baseline) |
| `regex_baseline` | Canary/obfuscation keywords | Fast | Obvious markers |
| `yara_rules` | WARDEN `.war` rule engine (patterns + semantics + facts) | Fast | Structural attacks |
| `rules_plus_fides` | WARDEN + FIDES judge (LLM on miss) | Slow (API call) | Subtle/novel attacks |

---

## CLI Commands

| Command | What it does |
|---|---|
| `warden scan "prompt"` | Quick single-prompt scan (untrusted, rich output) |
| `warden scan -f file.txt` | Batch scan from file |
| `warden scan "prompt" --fides` | With FIDES test-double judge |
| `warden scan "prompt" --fides-live` | With real Copilot SDK judge |
| `warden scan "prompt" --json` | JSON output |
| `warden scan "prompt" --trusted` | Mark as trusted origin |
| `warden warden check --prompt "..." ...` | Verbose check with all flags |
| `warden judge one --prompt "..." ...` | WARDEN + FIDES with full options |
| `warden warden test --input file.cases` | Run .cases corpus benchmark |
| `warden eval --config ...` | Full multi-dataset evaluation |
| `warden smoke` | Legacy smoke report |
| `warden provider status` | Check Copilot SDK auth |

---

## Autonomy Metrics (PRUDENTIA)

| Metric | Formula | Meaning |
|---|---|---|
| `hitl_load` | `sum(violations for completed tasks)` | Total human interventions needed |
| `tcr_at_k` | `count(completed AND violations ≤ k) / total` | Task completion rate under k interventions |
| `tcr_at_0` | Fully autonomous (zero violations) | Agent completes with no human help |
| `tcr_at_inf` | Unlimited interventions allowed | Pure task-solving capability |
