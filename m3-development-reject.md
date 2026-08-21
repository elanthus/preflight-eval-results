# Aggregate evaluation report

## Decision

**Reject.** The linked recovery made all 180 planned runs analyzable\. Candidate minus baseline net useful lift is minus one outcome out of 45, while candidate fixed-control false positives increase by two outcomes out of 45\. Either result independently triggers the frozen reject rule\.

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
| Vulnerable lift | 0.022222222222222223 (1/45) | [-0.1111111111111111, 0.15555555555555553] |
| Fixed false-positive increase | 0.044444444444444446 (2/45) | [0.0, 0.13333333333333333] |
| Net useful lift | -0.022222222222222223 (-1/45) | [-0.13333333333333333, 0.06666666666666667] |

## Fixed-control impact

Candidate minus baseline fixed-control false positives: 0.044444444444444446 (2/45), 95% interval [0.0, 0.13333333333333333].

## Completeness and stability

- All planned runs terminal: yes
- Primary analysis complete: yes
- Invalid outputs: 0
- Other failed outputs: 0

| Snapshot | Condition | Complete cases | Unresolved cases | Discordant cases | Mean within-case variance |
| --- | --- | ---: | ---: | ---: | ---: |
| vulnerable | baseline | 15 | 0 | 1 | 0.014814814814814815 |
| vulnerable | candidate | 15 | 0 | 2 | 0.02962962962962963 |
| fixed | baseline | 15 | 0 | 0 | 0.0 |
| fixed | candidate | 15 | 0 | 1 | 0.014814814814814815 |

## Operations and cost

- Latency median / p95 (ms): 52529.70379195176 / 114000.08170888759
- Provider input tokens: Unknown
- Provider output tokens: Unknown
- Tokenizer-estimated input tokens: 733950.0
- Actual cost: Unknown (usage or matching dated price is incomplete)
- Projected total cost: Unknown (usage or matching dated price is incomplete)
- Frozen worst-case budget: $940.896000
- Price table: openai-gpt-5\.4-2026-08-18 (effective 2026-08-18)

## Aggregate breakdowns

| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |
| --- | --- | ---: | ---: | ---: |
| category | correctness | 11 | 0.0 | 0.06060606060606061 |
| category | operational\_contract | 5 | 0.0 | 0.0 |
| category | security | 5 | -0.06666666666666667 | 0.0 |
| context\_size | medium | 7 | 0.0 | 0.09523809523809523 |
| context\_size | small | 6 | 0.05555555555555555 | 0.0 |
| repository | agentic-preflight | 5 | 0.06666666666666667 | 0.0 |
| repository | jobwright | 5 | 0.0 | 0.0 |
| severity | high | 10 | 0.03333333333333333 | 0.0 |
| severity | medium | 5 | 0.0 | 0.13333333333333333 |

## Exploratory valid-issue discovery

- Model finding instances reviewed: 224
- Valid finding instances: 201
- Deduplicated valid issues: 63
- Known-issue matches: 12
- Additional valid issue instances: 189
- Deduplicated additional valid issues: 59
- False-positive findings: 22
- Repaired-mechanism false positives: 2
- Other false-positive findings: 20
- Valid code issue instances / unique: 199 / 62
- Valid documentation issue instances / unique: 2 / 1
- Code / documentation false positives: 15 / 7
- Uncertain findings: 1
- Resolved finding precision: 0.9013452914798207
- False-positive rate: 0.09865470852017937

| Condition | Snapshot | Findings | Valid instances | Unique valid issues | Additional valid | False positives | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | vulnerable | 59 | 52 | 32 | 47 | 7 | 0.8813559322033898 |
| baseline | fixed | 55 | 47 | 29 | 47 | 8 | 0.8545454545454545 |
| candidate | vulnerable | 55 | 49 | 30 | 42 | 5 | 0.9074074074074074 |
| candidate | fixed | 55 | 53 | 30 | 53 | 2 | 0.9636363636363636 |

## Limitations

- One supplemental discovery finding has uncertain source validity; it does not affect primary mechanism scoring\.
- Provider token usage, request identifiers, and actual billed cost were unavailable\.
- Results cover a local 15-case development corpus and do not estimate reserved-set performance\.
- The frozen split has no reserved OSWorldTasks or large-context coverage\.

## Exclusions

- Case-level and finding-level identities remain private\.
- Seven frozen reserved cases were not executed and did not inform profile edits\.

## Protocol deviations

- An approved linked recovery reran only the 18 terminal source failures at a later implementation revision with enlarged output-capture limits\. The cases, order tuples, profiles, prompt, schema, model, reasoning effort, tool policy, retry policy, price assumptions, and environment lock were preserved\.
- The 36 recovered findings received supplemental primary-only mechanism and source-validity assessment after the original calibrated adjudication\.

Report digest: `sha256:e4fde5f124e1ceb4400c486514641013db33768ddd868af680687fbeeafeaaf4`
