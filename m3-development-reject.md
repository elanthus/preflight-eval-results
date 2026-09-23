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
| Vulnerable lift | 0.022 (1/45) | [-0.111, 0.156] |
| Fixed false-positive increase | 0.044 (2/45) | [0.000, 0.133] |
| Net useful lift | -0.022 (-1/45) | [-0.133, 0.067] |

## Fixed-control impact

Candidate minus baseline fixed-control false positives: 0.044 (2/45), 95% interval [0.000, 0.133].

## Completeness and stability

- All planned runs terminal: yes
- Primary analysis complete: yes
- Invalid outputs: 0
- Other failed outputs: 0

| Snapshot | Condition | Complete cases | Unresolved cases | Discordant cases | Mean within-case variance |
| --- | --- | ---: | ---: | ---: | ---: |
| vulnerable | baseline | 15 | 0 | 1 | 0.015 |
| vulnerable | candidate | 15 | 0 | 2 | 0.030 |
| fixed | baseline | 15 | 0 | 0 | 0.000 |
| fixed | candidate | 15 | 0 | 1 | 0.015 |

## Operations and cost

- Latency median / p95 (ms): 52,530 / 114,000
- Provider input tokens: Unknown
- Provider output tokens: Unknown
- Tokenizer-estimated input tokens: 733,950
- Actual cost: Unknown (usage or matching dated price is incomplete)
- Projected total cost: Unknown (usage or matching dated price is incomplete)
- Frozen worst-case budget: $940.90
- Price table: openai-gpt-5\.4-2026-08-18 (effective 2026-08-18)

## Aggregate breakdowns

| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |
| --- | --- | ---: | ---: | ---: |
| category | correctness | 11 | 0.000 | 0.061 |
| category | operational\_contract | 5 | 0.000 | 0.000 |
| category | security | 5 | -0.067 | 0.000 |
| context\_size | medium | 7 | 0.000 | 0.095 |
| context\_size | small | 6 | 0.056 | 0.000 |
| repository | agentic-preflight | 5 | 0.067 | 0.000 |
| repository | jobwright | 5 | 0.000 | 0.000 |
| severity | high | 10 | 0.033 | 0.000 |
| severity | medium | 5 | 0.000 | 0.133 |

## Exploratory valid-issue discovery

- Model finding instances reviewed: 224
- Valid finding instances: 202
- Deduplicated valid issues: 64
- Known-issue matches: 12
- Additional valid issue instances: 190
- Deduplicated additional valid issues: 60
- False-positive findings: 22
- Repaired-mechanism false positives: 2
- Other false-positive findings: 20
- Valid code issue instances / unique: 200 / 63
- Valid documentation issue instances / unique: 2 / 1
- Code / documentation false positives: 15 / 7
- Uncertain findings: 0
- Resolved finding precision: 0.902
- False-positive rate: 0.098

| Condition | Snapshot | Findings | Valid instances | Unique valid issues | Additional valid | False positives | Precision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| baseline | vulnerable | 59 | 52 | 32 | 47 | 7 | 0.881 |
| baseline | fixed | 55 | 47 | 29 | 47 | 8 | 0.855 |
| candidate | vulnerable | 55 | 50 | 31 | 43 | 5 | 0.909 |
| candidate | fixed | 55 | 53 | 30 | 53 | 2 | 0.964 |

## Limitations

- One supplemental discovery finding required a blind source-context amendment; the terminal amendment does not affect primary mechanism scoring\.
- Provider token usage, request identifiers, and actual billed cost were unavailable\.
- Results cover a local 15-case development corpus and do not estimate reserved-set performance\.
- The frozen split has no reserved OSWorldTasks or large-context coverage\.

## Exclusions

- Case-level and finding-level identities remain private\.
- Seven frozen reserved cases were not executed and did not inform profile edits\.

## Protocol deviations

- An approved linked recovery reran only the 18 terminal source failures at a later implementation revision with enlarged output-capture limits\. The cases, order tuples, profiles, prompt, schema, model, reasoning effort, tool policy, retry policy, price assumptions, and environment lock were preserved\.
- One evidence-insufficient recovery source assessment was resolved by a separately blinded, digest-linked amendment using the exact cited implementation excerpt\.
- The 36 recovered findings received supplemental primary-only mechanism and source-validity assessment after the original calibrated adjudication\.

Report digest: `sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313`
