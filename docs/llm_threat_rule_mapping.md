# LLM threat rule coverage map (`cwfr-llm-*`)

This curated set translates a public community LLM-threat hunting ruleset into
WARDEN-native `.war` rules. Each rule is consolidated by **threat behavior** and
authored to the full four-evidence shape so it is evaluable by the deterministic
engine and routable to the FIDES/IFC judge.

## The four evidence layers

Every `cwfr-llm-*` rule combines all four evidence layers through its
`condition:`:

1. **`patterns:`** — deterministic regex/exact indicators over the raw record text.
2. **built-in facts** — framework-owned booleans (`$from_untrusted_origin`,
   `$capability_denied`, `$canary_outside_sink`, `$tool_call_shape`,
   `$hidden_unicode`, `$instruction_shape`) referenced directly in `condition:`.
3. **`semantics:`** — engine-scored intent similarity (provider-free).
4. **`judge:`** — a FIDES question the IFC gate adjudicates on a deterministic miss.

The canonical condition idiom gates the specific deterministic indicators behind
the most relevant structural fact, then falls back to fuzzy intent and the judge:

```
condition:
    (($pattern_a or $pattern_b) and $relevant_fact) or $semantic or $judge
```

This mirrors the authoring-guide reference rule (`cwfr-0106`): the patterns are
high-precision but only act with structural confirmation, while the semantic and
judge layers carry recall. It deliberately avoids using a generic
`($from_untrusted_origin and $instruction_shape)` pair as a standalone trigger,
because that signal is already owned by the boundary rule `cwfr-0003` and would
otherwise make every behavior rule fire on any instruction-shaped input.

## ID namespace

`cwfr-llm-NNNN` is a dedicated namespace for this curated LLM/prompt-threat set,
separate from the existing structured rules (`cwfr-NNNN`), the benchmark
signatures (`cwfr-ppe-NNNN`), and the demos (`cwfr-demo-NNNN`).

## Themed files

| File | Rules | Theme |
|---|---|---|
| `rules/llm_prompt_injection.war` | 0001–0003 | Instruction override, indirect injection, payload splitting |
| `rules/llm_jailbreak.war` | 0004–0007 | Persona, known templates, hypothetical pretext, policy puppetry |
| `rules/llm_obfuscation.war` | 0008–0010 | Encoding, invisible Unicode, language code-switching |
| `rules/llm_data_disclosure.war` | 0011–0013 | System-prompt extraction, sensitive disclosure, unsafe output |
| `rules/llm_offensive_tooling.war` | 0014–0017 | Malware, web shells, exploit research, offensive tool extension |
| `rules/llm_social_engineering.war` | 0018–0020 | Phishing, impersonation, target profiling |
| `rules/llm_agentic_abuse.war` | 0021–0024 | Command exec, destructive wipe, exfiltration, permission grant |

## Coverage mapping

Upstream taxonomy labels are listed for traceability; the WARDEN rule is the
authoritative artifact. One WARDEN rule may consolidate several upstream rules
that share a behavior.

| WARDEN rule | Behavior | Upstream category | MITRE anchor(s) | D3FEND | Severity / action |
|---|---|---|---|---|---|
| cwfr-llm-0001 DirectInstructionOverride | Override/redefine governing instructions | `prompt_manipulation/direct_injection` | AML.T0051.000 | — | high / block_and_audit |
| cwfr-llm-0002 IndirectContentInjection | Injected instructions via untrusted external content | `prompt_manipulation/indirect_injection` | AML.T0051.001 | — | high / block_and_audit |
| cwfr-llm-0003 PayloadSplittingInjection | Fragmented/reassembled payloads | `suspicious_patterns/fragmentation` | AML.T0051, T1027 | — | medium / quarantine |
| cwfr-llm-0004 RoleplayPersonaJailbreak | Persona/character restriction bypass | `prompt_manipulation/jailbreak` | AML.T0054 | — | high / block_and_audit |
| cwfr-llm-0005 KnownJailbreakTemplate | Named jailbreak personas / alt modes | `prompt_manipulation/jailbreak` | AML.T0054 | — | high / block_and_audit |
| cwfr-llm-0006 CognitiveHypotheticalJailbreak | Hypothetical/academic pretext | `prompt_manipulation/jailbreak` | AML.T0054 | — | medium / quarantine |
| cwfr-llm-0007 PolicyPuppetryBypass | Fabricated policy/config authorization | `prompt_manipulation/jailbreak` | AML.T0054 | — | high / block_and_audit |
| cwfr-llm-0008 EncodedPayloadObfuscation | Encoding/cipher/substitution evasion | `suspicious_patterns/encoding_obfuscation` | T1027, AML.T0051 | — | medium / quarantine |
| cwfr-llm-0009 InvisibleUnicodeSmuggling | Zero-width / tag-character smuggling | `suspicious_patterns/unicode_tricks`, `prompt_manipulation/hidden_instructions` | T1027 | — | high / block_and_audit |
| cwfr-llm-0010 CodeSwitchingEvasion | Multilingual/code-switching evasion | `suspicious_patterns/cross_modal` | AML.T0054, T1027 | — | medium / quarantine |
| cwfr-llm-0011 SystemPromptExtraction | System/developer prompt disclosure | `abnormal_outputs/system_prompt_leak` | AML.T0056 | D3-OTF | high / block_and_audit |
| cwfr-llm-0012 SensitiveInformationDisclosure | Secret / PII / proprietary disclosure | `abnormal_outputs/pii_exposure` | AML.T0057 | D3-OTF | high / block_and_audit |
| cwfr-llm-0013 UnsafeOutputHandling | Output shaped to execute downstream | `abnormal_outputs/malicious_content` | AML.T0057, T1059 | D3-EI | high / block_and_audit |
| cwfr-llm-0014 OffensiveCodeGeneration | Malware / ransomware generation | `abusing_functions/malware_generation` | T1059 | D3-EI | high / block_and_audit |
| cwfr-llm-0015 WebShellGeneration | Web shell / RCE endpoint | `abusing_functions/malware_generation` | T1505.003 | D3-EI | high / block_and_audit |
| cwfr-llm-0016 VulnerabilityExploitResearch | Weaponized exploit / PoC | `abusing_functions/crime_automation` | T1588.006, T1595 | — | medium / quarantine |
| cwfr-llm-0017 OffensiveToolExtension | Extend offensive/red-team tooling | `abusing_functions/supply_chain` | T1587.001 | D3-EI | medium / quarantine |
| cwfr-llm-0018 PhishingContentGeneration | Phishing / lure content | `abusing_functions/social_engineering` | AML.T0052, T1566 | D3-UBA | high / block_and_audit |
| cwfr-llm-0019 ImpersonationOfTrustedSource | Brand/authority impersonation | `abusing_functions/social_engineering` | AML.T0052, T1656 | D3-UBA | high / block_and_audit |
| cwfr-llm-0020 TargetReconnaissanceProfiling | Target dossier / profiling | `abusing_functions/reconnaissance` | T1591, T1589 | D3-UBA | medium / quarantine |
| cwfr-llm-0021 DynamicContextCommandExecution | Injected context drives tool exec | `abusing_functions/agentic_misuse` | T1059 | D3-EI | critical / block_and_audit |
| cwfr-llm-0022 DestructiveResourceWipe | Irreversible delete / wipe / encrypt | `abusing_functions/agentic_misuse` | T1485 | D3-EI | critical / block_and_audit |
| cwfr-llm-0023 AgenticDataExfiltration | Staged collection + outbound transfer | `abusing_functions/data_exfiltration` | T1567 | D3-OTF | critical / block_and_audit |
| cwfr-llm-0024 UnsafeToolPermissionGrant | Self-escalation / trust unverified tool | `abusing_functions/supply_chain`, `abusing_functions/agentic_misuse` | T1195.002, T1059 | D3-AM | high / block_and_audit |

All eighteen upstream taxonomy labels are covered by at least one rule.

## Forward compatibility for MITRE scraping automation

This set is structured so a future scraper that ingests MITRE ATT&CK, ATLAS, and
D3FEND techniques can extend it mechanically:

- **Anchors are first-class meta.** Every rule carries `technique` (ATT&CK/ATLAS)
  and, where it fits, `defense` (D3FEND), using the compact
  `ID (Tactic, mapping_strength)` form the loader already parses. A generator can
  emit these directly from scraped technique records.
- **Framework is inferred from the ID prefix.** `T<digit>` = ATT&CK, `AML.T` =
  ATLAS, `D3-` = D3FEND — no separate framework field to populate.
- **Behavior-first consolidation.** Rules are keyed to a behavior, not a single
  source string, so newly scraped techniques map onto existing behaviors (new
  anchors on an existing rule) or seed a new themed file without disturbing the
  `cwfr-llm-*` namespace.
- **Evidence layers degrade gracefully.** A generated rule can start as
  `semantics` + `judge` and gain `patterns` + facts as indicators are curated,
  while always satisfying the four-evidence criteria.

## Validation

```powershell
.venv-win\Scripts\python.exe -m pytest tests/test_warden_rule_style.py tests/test_rule_schema.py -q
# UTF-8 stdout is required so the invisible-unicode case renders on Windows consoles.
$env:PYTHONUTF8=1; .venv-win\Scripts\python.exe -m canaryweave_fides.cli warden test --input data\cases\llm_threats.cases
```

The corpus exercises one representative attack per `cwfr-llm-*` rule plus benign
controls; the deterministic `yara_rules` stack blocks every attack (ASR 0.00)
without blocking any benign case (FPR 0.00).
