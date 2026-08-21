# Aggregate evaluation report

## Decision

**Insufficient evidence.** Eighteen documented terminal failures make primary paired effects and intervals undefined\. The resolved outcomes contain one additional vulnerable hit and one additional fixed-control false positive, for zero observed net lift, while sensitivity net lift ranges from minus four to plus two outcomes and both intervals include zero\. The frozen insufficient-evidence override therefore applies\.

## Corpus and protocol

- Eligible cases: 15
- Planned runs: 180
- Completed runs: 180
- Repetitions per cell: 3
- Snapshots: vulnerable, fixed
- Conditions: baseline, candidate
- Primary paired unit: case
- Invalid-output policy: retry_then_fail

## Paired results

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable lift | Unknown (1/45) | Unknown |
| Fixed false-positive increase | Unknown (1/45) | Unknown |
| Net useful lift | Unknown (0/45) | Unknown |

## Fixed-control impact

Candidate minus baseline fixed-control false positives: Unknown (1/45), 95% interval Unknown.

## Completeness and stability

- All planned runs terminal: yes
- Primary analysis complete: no
- Invalid outputs: 5
- Other failed outputs: 13

| Snapshot | Condition | Complete cases | Unresolved cases | Discordant cases | Mean within-case variance |
| --- | --- | ---: | ---: | ---: | ---: |
| vulnerable | baseline | 14 | 1 | 1 | 0.015873015873015876 |
| vulnerable | candidate | 12 | 3 | 2 | 0.03703703703703704 |
| fixed | baseline | 14 | 1 | 0 | 0.0 |
| fixed | candidate | 11 | 4 | 0 | 0.0 |

## Operations and cost

- Latency median / p95 (ms): 49723.10677089263 / 108959.90287489258
- Provider input tokens: Unknown
- Provider output tokens: Unknown
- Tokenizer-estimated input tokens: 733950.0
- Actual cost: Unknown (usage or matching dated price is incomplete)
- Projected total cost: Unknown (usage or matching dated price is incomplete)
- Frozen worst-case budget: $855.360000
- Price table: openai-gpt-5\.4-2026-08-18 (effective 2026-08-18)

## Aggregate breakdowns

| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |
| --- | --- | ---: | ---: | ---: |
| category | correctness | 11 | Unknown | Unknown |
| category | operational\_contract | 5 | Unknown | 0.0 |
| category | security | 5 | Unknown | Unknown |
| context\_size | medium | 7 | Unknown | Unknown |
| context\_size | small | 6 | Unknown | Unknown |
| repository | agentic-preflight | 5 | 0.06666666666666667 | 0.0 |
| repository | jobwright | 5 | Unknown | Unknown |
| severity | high | 10 | Unknown | Unknown |
| severity | medium | 5 | Unknown | Unknown |

## Exploratory valid-issue discovery

- Model finding instances reviewed: 188
- Valid finding instances: 171
- Deduplicated valid issues: 52
- Known-issue matches: 11
- Additional valid issue instances: 160
- Deduplicated additional valid issues: 49
- False-positive findings: 17
- Repaired-mechanism false positives: 1
- Other false-positive findings: 16
- Valid code issue instances / unique: 169 / 51
- Valid documentation issue instances / unique: 2 / 1
- Code / documentation false positives: 10 / 7
- Uncertain findings: 0
- Resolved finding precision: 0.9095744680851063
- False-positive rate: 0.09042553191489362

| Condition | Snapshot | Findings | Valid instances | Unique valid issues | Additional valid | False positives | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | vulnerable | 53 | 46 | 27 | 41 | 7 | 0.8679245283018868 |
| baseline | fixed | 49 | 43 | 27 | 43 | 6 | 0.8775510204081632 |
| candidate | vulnerable | 44 | 41 | 24 | 35 | 3 | 0.9318181818181818 |
| candidate | fixed | 42 | 41 | 24 | 41 | 1 | 0.9761904761904762 |

## Limitations

- Provider token usage, request identifiers, and actual billed cost were unavailable\.
- Results cover a local 15-case development corpus and do not estimate reserved-set performance\.
- Terminal failures leave primary paired effects and confidence intervals unresolved\.
- The frozen split has no reserved OSWorldTasks or large-context coverage\.

## Exclusions

- Case-level and finding-level identities remain private\.
- Seven frozen reserved cases were not executed and did not inform profile edits\.

## Protocol deviations

- Eighteen runs ended in documented output-limit or exhausted invalid-output failures\.
- For this MVP, the operator authorized Sonnet 5, Nemotron Ultra, and Fable 5 in roles documented as human adjudicators\.
- The authorized checkpoint used 15 development cases rather than the issue's original 24-case scope\.

Report digest: `sha256:c99a16cb6d8ea3a48561f6d6bb943a00ebbbe9d7e69992b95407be3abbf8a0ff`
