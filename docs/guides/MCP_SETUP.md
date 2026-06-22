# WARDEN-IFC: MCP Security Testing Architecture

## Overview

WARDEN sits between the MCP Client and MCP Servers, evaluating every tool call against `.war` rules and IFC policies. It supports both external (untrusted) and internal (trusted) MCP tools, with configurable trust boundaries.

### Schema-Aware Security Fuzzing

The `warden crawl` command implements **schema-aware fuzzing** for MCP tool security:

| Traditional Fuzzing | WARDEN Crawl Fuzzing |
|---|---|
| Random byte mutation | Schema-aware prompt generation |
| Target: crash / memory corruption | Target: prompt injection / data exfiltration |
| Guided by code coverage | Guided by tool parameter types |
| Finds software bugs | Finds security policy gaps |

How it works:
1. Connect to MCP server via stdio
2. Call `tools/list` to discover tool schemas (names, descriptions, parameter types)
3. **Generate adversarial prompts per tool** based on parameter types:
   - `path`/`file` params → path traversal attacks
   - `string`/`text` params → prompt injection attacks
   - Any tool → capability escalation, social engineering, tool poisoning
4. Evaluate each generated prompt through WARDEN+FIDES gate
5. Report per-tool coverage: which attack types are caught, which slip through

This is not random — it knows the attack surface. A tool with `path: string` gets path traversal attacks. A tool with `message: string` gets injection attacks.

## Architecture

```
                                    Config {
                                      Internal/External
                                      MCP/TOOLS
                                    }
                                        |
                                        v
                        +-------------------------------+
                        |           WARDEN              |
  MCP Client  -------->|                               |------> MCP Tool Call
  (Copilot,             |   +-------+     +-------+    |        (done via framework)
   Claude,              |   | .war  |     |  IFC  |    |
   Agent)               |   | Rules |     | Gate  |    |------> Prompt, Tool
                        |   +---+---+     +---+---+    |
                        |       |   CHECK     |        |
                        |       v  /    \     v        |
                        |      OK /      \ BLOCK       |
                        +-------------------------------+
                                    |
                    +---------------+----------------+
                    |                                |
          "We provide prompts"            "Bring your own prompts"
          Malicious / Benign              (your attack scenarios)
                    |                                |
              List {                           List {
                tool1                            tool1
                tool2                            tool2
                tool3                            tool3
              }                                }
```

## Two Data Sources

### External MCP (Untrusted)
- **Source:** Public attack datasets
- **ASB:** https://github.com/agiresearch/ASB/blob/main/data/all_attack_tools.jsonl (400 attacks)
- **MCPSecBench:** AgentDefense-Bench/mcp_specific/mcpsecbench_mcp_attacks.json (510 attacks)
- **Trust level:** UNTRUSTED — all content labeled with `integrity = U`
- **Purpose:** Benchmark WARDEN detection coverage against known attacks

### Internal MCP (Trusted / Mixed)
- **Source:** Your own MCP servers and tools
- **ASB Normal:** https://github.com/agiresearch/ASB/blob/main/data/all_normal_tools.jsonl (benign tools)
- **Custom:** Your internal tool descriptions, prompts, and workflows
- **Trust level:** Configurable per-tool — some trusted, some untrusted
- **Purpose:** Test false positive rate, ensure legitimate tools aren't blocked

## How WARDEN Distinguishes Trust

```
Tool Call from MCP Server
         |
         v
  What is the ORIGIN?
         |
    +----+----+
    |         |
  TRUSTED   UNTRUSTED
  (user,     (tool_output, resource_content,
   host,      server_manifest, server_sampling,
   planner)   notification_message, prompts_get)
    |         |
    v         v
  $from_untrusted_origin = False    $from_untrusted_origin = True
    |                                |
    v                                v
  Rules with $from_untrusted_origin  Rules fire when origin is untrusted
  in condition WON'T fire            AND pattern/semantic matches
```

### The 6 Facts WARDEN Checks

| Fact | What WARDEN checks | Trust signal |
|---|---|---|
| `$from_untrusted_origin` | Did content come from an MCP data source? | Origin trust |
| `$capability_denied` | Is the tool in the allowed list? | Tool trust |
| `$canary_outside_sink` | Is data going to an unauthorized destination? | Sink trust |
| `$tool_call_shape` | Does it look like a tool call/plan? | Structure |
| `$hidden_unicode` | Are there invisible characters? | Obfuscation |
| `$instruction_shape` | Does it look like injected instructions? | Injection |

## Usage Scenarios

### Scenario 1: "We Provide Prompts" (Pre-built Benchmarks)

Test against known attack/benign datasets:

```bash
# Attack coverage (how many attacks does WARDEN catch?)
uv run warden bench coverage --dataset mcp \
  --path ../AgentDefense-Bench/mcp_specific/mcpsecbench_mcp_attacks.json \
  --fides-live --detail artifacts/mcp_detail.jsonl

# ASB attack coverage
uv run warden bench coverage --dataset asb \
  --path ../ASB/data/all_attack_tools.jsonl \
  --fides --detail artifacts/asb_detail.jsonl
```

### Scenario 2: "Bring Your Own Prompts" (Custom Testing)

Test with your own MCP tool descriptions and prompts:

```bash
# Single prompt
uv run warden scan "your tool description or prompt here"

# Batch from file (one prompt per line)
uv run warden scan -f your_prompts.txt

# JSONL format with custom fields
uv run warden bench scan --input your_data.jsonl --input-format jsonl \
  --text-field prompt --id-field id --origin tool_output --trust untrusted
```

### Scenario 3: "Give Us Your MCP Endpoint" (Auto-Crawl)

WARDEN has a built-in MCP client that connects to any endpoint, discovers tools,
generates adversarial prompts, and evaluates them:

```bash
# Crawl a real MCP server
uv run warden crawl --endpoint "npx @modelcontextprotocol/server-filesystem /tmp"

# Crawl with FIDES judge for misses
uv run warden crawl --endpoint "npx @modelcontextprotocol/server-filesystem /tmp" --fides-live

# Crawl from config (multiple endpoints)
uv run warden crawl --config conf/mcp_endpoints.yaml

# Save per-case detail to JSONL
uv run warden crawl --endpoint "..." --detail artifacts/crawl_detail.jsonl
```

### Scenario 4: Dataset as Mock MCP Server

Use ASB/MCPSecBench as a mock MCP server for end-to-end testing:

```bash
# ASB dataset served as MCP server
uv run warden crawl --endpoint "uv run python -m canaryweave_fides.mock_mcp_server --dataset asb --path ../ASB/data/all_attack_tools.jsonl"

# MCPSecBench dataset served as MCP server
uv run warden crawl --endpoint "uv run python -m canaryweave_fides.mock_mcp_server --dataset mcp --path ../AgentDefense-Bench/mcp_specific/mcpsecbench_mcp_attacks.json"
```

The mock server wraps any dataset as a real MCP stdio server. WARDEN connects,
discovers "tools" (grouped by attack category), generates adversarial prompts
per tool, and evaluates through the full WARDEN+FIDES gate.

## Model Card / Bench

WARDEN supports Bring Your Own Model (BYOM) for the quarantined LLM judge:

| Model | Type | Use Case |
|---|---|---|
| GPT-5.5 | Large LLM | Highest accuracy quarantined judge |
| GPT-5.4 | Large LLM | Good balance of accuracy and cost |
| Claude Opus 4.8 | Large LLM | Alternative provider |
| GLM 5.2 | Large LLM | Open-weight option |
| BYOM (MAI/MSEC) | Custom | Your own fine-tuned security model |
| SLM (DeBERTa) | Small LM | Fastest, cheapest — push determinism |

### Key Insight: Push Determinism First

```
Goal: Save costs on quarantined_llm calls

Strategy:
  1. Write deterministic .war rules to catch as much as possible (~42-80%)
  2. FIDES judge only called on misses (~20-58% of cases)
  3. Each rule improvement = fewer LLM calls = lower cost

Current coverage:
  MCPSecBench: WARDEN catches 42% → only 58% need LLM judge
  With better rules: WARDEN catches 80% → only 20% need LLM judge
```

### Benchmark Results by Model

| Model / Bench | Attack Scenarios Available | Sovereign Specific |
|---|---|---|
| GPT-5.5, 5.4, Opus 4.8 | MCPSecBench (510), ASB (400) | Configurable |
| GLM 5.2 | MCPSecBench (510), ASB (400) | Configurable |
| BYOM (MAI/MSEC) | MCPSecBench (510), ASB (400) | Custom scenarios |
| SLM (DeBERTa) | MCPSecBench (510), ASB (400) | Custom scenarios |

## Setup

### Clone Datasets

```bash
cd /path/to/workspace
git clone https://github.com/agiresearch/ASB.git
git clone https://github.com/arunsanna/AgentDefense-Bench.git
```

### Install WARDEN

```bash
cd WARDEN-CanaryWeave
uv pip install -e ".[copilot]"
```

### Run Full Benchmark

```bash
# WARDEN-only (deterministic, instant)
uv run warden bench coverage --dataset mcp \
  --path ../AgentDefense-Bench/mcp_specific/mcpsecbench_mcp_attacks.json \
  --detail artifacts/warden_only.jsonl

# WARDEN + FIDES judge (real LLM, ~30s per miss)
uv run warden bench coverage --dataset mcp \
  --path ../AgentDefense-Bench/mcp_specific/mcpsecbench_mcp_attacks.json \
  --fides-live --detail artifacts/warden_fides.jsonl

# Compare: diff the two JSONL files to see what FIDES caught
```

### Inspect Per-Case Decisions

```bash
# Pretty-print the detail JSONL
python -c "
import json
for line in open('artifacts/warden_only.jsonl'):
    row = json.loads(line)
    status = 'BLOCKED' if row['final_blocked'] else 'MISSED'
    rules = ', '.join(row['warden_rule_ids'][:2]) or 'none'
    print(f'{status:7s} | {rules:25s} | {row[\"text\"][:60]}')
"
```
