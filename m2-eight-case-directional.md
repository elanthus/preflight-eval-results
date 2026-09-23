# Aggregate evaluation report

## Decision

**Insufficient evidence.** The corrected eight-case directional M2 execution validates mechanics and discovery reporting but is not decision-quality evidence\.

## Corpus and protocol

- Eligible cases: 8
- Planned runs: 32
- Completed runs: 32
- Repetitions per cell: 1
- Snapshots: vulnerable, fixed
- Conditions: baseline, candidate
- Primary paired unit: case
- Invalid-output policy: retry_then_fail

## Paired results

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable lift | Unknown (2/8) | Unknown |
| Fixed false-positive increase | 0.000 (0/8) | Unknown |
| Net useful lift | Unknown (2/8) | Unknown |

## Fixed-control impact

Candidate minus baseline fixed-control false positives: 0.000 (0/8), 95% interval Unknown.

## Completeness and stability

- All planned runs terminal: yes
- Primary analysis complete: no
- Invalid outputs: 1
- Other failed outputs: 0

| Snapshot | Condition | Complete cases | Unresolved cases | Discordant cases | Mean within-case variance |
| --- | --- | ---: | ---: | ---: | ---: |
| vulnerable | baseline | 8 | 0 | 0 | 0.000 |
| vulnerable | candidate | 7 | 1 | 0 | 0.000 |
| fixed | baseline | 8 | 0 | 0 | 0.000 |
| fixed | candidate | 8 | 0 | 0 | 0.000 |

## Operations and cost

- Latency median / p95 (ms): 67,858 / 133,876
- Provider input tokens: Unknown
- Provider output tokens: Unknown
- Tokenizer-estimated input tokens: 112,986
- Actual cost: Unknown (usage or matching dated price is incomplete)
- Projected total cost: Unknown (usage or matching dated price is incomplete)
- Frozen worst-case budget: $152.06
- Price table: openai-gpt-5\.4-2026-08-18 (effective 2026-08-18)

## Aggregate breakdowns

| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |
| --- | --- | ---: | ---: | ---: |
| category | correctness | 6 | Unknown | 0.000 |
| context\_size | medium | 6 | Unknown | 0.000 |
| severity | high | 5 | 0.200 | 0.000 |

## Exploratory valid-issue discovery

- Model finding instances reviewed: 46
- Valid finding instances: 25
- Deduplicated valid issues: 20
- Known-issue matches: 4
- Additional valid issue instances: 21
- Deduplicated additional valid issues: 17
- False-positive findings: 21
- Repaired-mechanism false positives: 0
- Other false-positive findings: 21
- Valid code issue instances / unique: 25 / 20
- Valid documentation issue instances / unique: 0 / 0
- Code / documentation false positives: 21 / 0
- Uncertain findings: 0
- Resolved finding precision: 0.543
- False-positive rate: 0.457

| Condition | Snapshot | Findings | Valid instances | Unique valid issues | Additional valid | False positives | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | vulnerable | 11 | 5 | 5 | 4 | 6 | 0.455 |
| baseline | fixed | 11 | 6 | 6 | 6 | 5 | 0.545 |
| candidate | vulnerable | 11 | 8 | 8 | 5 | 3 | 0.727 |
| candidate | fixed | 13 | 6 | 6 | 6 | 7 | 0.462 |

## Limitations

- Eight development cases, one repetition per cell, one independent adjudicator, and one terminal invalid output are not decision-quality evidence\.

## Exclusions

None recorded.

## Protocol deviations

- The directional pilot used one independent adjudicator instead of two-person calibration and separate resolution\.
- The frozen analysis-plan heading says version 1\.2 while the experiment definition records version 1\.1; the content digest binds the exact reviewed inputs\.

Report digest: `sha256:a7edfbd9bde2303fcd9b3b7980cdd09e5c853d556e2fe3c7f4a702fae72d6300`
