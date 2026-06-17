# Paper Peer Review: CanaryWeave FIDES / WARDEN Draft

Date: 2026-06-03
Status: independent review summary
Scope: `poc/canaryweave-fides`

## Summary

The current draft presents CanaryWeave FIDES as a leakage-safe evaluation harness for pre-context agent defenses. The strongest current contribution is methodological and engineering-oriented: normalized public-safe facts, deterministic WARDEN `.war` rule execution, aggregate public reporting, expected-rule evidence, false-positive diagnostics, and a private reviewer CSV path for controlled raw inspection.

The evidence supports a bounded claim: WARDEN improves over a simple regex baseline on public synthetic fixtures and on a controlled-local ASB aggregate run, while public artifacts avoid raw source leakage. It does not yet support broad claims about production security, comprehensive ASB/AgentDefenseBench coverage, provider-backed FIDES effectiveness, or full downstream agent compromise prevention.

## Strengths

1. Clear public/private evidence boundary: public artifacts exclude raw payloads, model outputs, judge transcripts, and case-level rows.
2. Evidence-tier separation: synthetic smoke, FIDES test-double, and controlled-local ASB are distinguished.
3. Real WARDEN rule execution: current artifacts are backed by `.war` rule files and stable `cwfr-*` rule IDs.
4. Useful diagnostics beyond headline ASR: expected-rule evidence, false-positive diagnostics, rule coverage, and safe-fact completeness are available.
5. Conservative framing in the main report: the draft does not claim real-provider FIDES efficacy.

## Major weaknesses

1. Detection-effectiveness evidence is not yet paper-strength. ASB WARDEN recall remains partial and many attack-labeled cases are allowed.
2. Synthetic evidence is tiny: 250 synthetic case-iterations are only 5 unique cases repeated 50 times.
3. FIDES is not empirically evaluated with a provider-backed judge. The current test-double artifact is interface/accounting evidence only.
4. AgentDefenseBench has no current checked-in aggregate artifact.
5. Benign evidence is sparse. ASB has only 20 benign cases, so the current zero false-positive result is encouraging but not stable.
6. Current ASR is a gate-level proxy, not a demonstrated live-agent compromise outcome.
7. Expected-rule hit rate is 1.0 only for the mapped expected-rule subset, not all ASB cases.
8. A submission needs a related-work section covering prompt-injection benchmarks, guardrails, policy-as-code, IFC, LLM-as-judge, and public-safe benchmark publication.

## Claims-to-evidence table

| Claim | Evidence | Judgment |
|---|---|---|
| Public-safe reporting exists | Public artifacts omit raw source/model/judge rows and mark safety flags | Supported |
| WARDEN executes real rules | `.war` files load through `RuleEngine`; artifacts show `cwfr-*` rule IDs | Supported |
| WARDEN improves over regex on synthetic fixtures | Synthetic artifact: regex ASR 0.5000, WARDEN ASR 0.2500 | Supported, tiny fixture set |
| WARDEN improves over regex on controlled ASB | ASB artifact: regex ASR 0.9977, WARDEN ASR 0.6923 | Supported, incomplete recall |
| WARDEN comprehensively covers ASB | Many ASB attack cases remain allowed | Not supported |
| FIDES improves empirical security | Provider calls are zero; ASB WARDEN+FIDES equals WARDEN | Not supported |
| FIDES accounting works | Test-double artifact has one deterministic incremental catch | Supported as interface evidence |
| Multi-dataset generalization is shown | AgentDefenseBench is skipped in current checked-in artifacts | Not supported |
| Full downstream agent security is improved | No runtime/tool-execution validation | Not supported |

## Missing experiments before submission

1. Frozen split / holdout evaluation before additional rule tuning.
2. Larger benign and benign-near-miss suite.
3. Current public-safe AgentDefenseBench aggregate artifact.
4. ASB false-negative error analysis using the private reviewer CSV.
5. Provider-backed FIDES experiment with transcript-private custody and public aggregate reporting.
6. Downstream runtime validation showing whether gate decisions correlate with real tool/agent outcomes.
7. Confidence intervals or bootstrap intervals for ASR, recall, FPR, and incremental catch rates.
8. Ablation study by rule family.
9. Stronger baselines beyond regex.
10. Related-work section and explicit construct-validity discussion.

## Recommendation

- Main security/ML venue: reject / major revision at the current evidence level.
- Workshop/artifact/internal technical report: weak accept with careful framing.

Best framing:

> CanaryWeave FIDES is a leakage-safe, structured evaluation harness for pre-context agent defense. Current artifacts demonstrate end-to-end WARDEN rule execution, public-safe aggregate reporting, and measurable but incomplete WARDEN improvement over regex on synthetic and controlled-local ASB facts. FIDES is currently validated only as an interface/accounting path, not as empirical LLM judge performance.
