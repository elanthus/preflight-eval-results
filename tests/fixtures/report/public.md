# Aggregate evaluation report

## Decision

**Revise.** Synthetic evidence requires another profile revision\.

## Corpus and protocol

- Eligible cases: 2
- Planned runs: 16
- Completed runs: 16
- Repetitions per cell: 2
- Snapshots: vulnerable, fixed
- Conditions: baseline, candidate
- Primary paired unit: case
- Invalid-output policy: retry_then_fail

## Paired results

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable lift | 0.5 (2/4) | [0.0, 1.0] |
| Fixed false-positive increase | 0.5 (2/4) | [0.0, 1.0] |
| Net useful lift | 0.0 (0/4) | [-1.0, 1.0] |

## Fixed-control impact

Candidate minus baseline fixed-control false positives: 0.5 (2/4), 95% interval [0.0, 1.0].

## Completeness and stability

- All planned runs terminal: yes
- Primary analysis complete: yes
- Invalid outputs: 0
- Other failed outputs: 0

| Snapshot | Condition | Complete cases | Unresolved cases | Discordant cases | Mean within-case variance |
| --- | --- | ---: | ---: | ---: | ---: |
| vulnerable | baseline | 2 | 0 | 0 | 0.0 |
| vulnerable | candidate | 2 | 0 | 0 | 0.0 |
| fixed | baseline | 2 | 0 | 0 | 0.0 |
| fixed | candidate | 2 | 0 | 0 | 0.0 |

## Operations and cost

- Latency median / p95 (ms): 2000.5 / 2000.5
- Provider input tokens: 16000.0
- Provider output tokens: 3200.0
- Tokenizer-estimated input tokens: 32000.0
- Actual cost: $0.084400
- Projected total cost: $0.084400
- Frozen worst-case budget: $1.920000
- Price table: synthetic-prices-v1 (effective 2026-08-18)

## Aggregate breakdowns

| Dimension | Value | Cases | Vulnerable lift | Fixed false-positive increase |
| --- | --- | ---: | ---: | ---: |
| category | correctness | 2 | 0.5 | 0.5 |
| category | operational\_contract | 2 | 0.5 | 0.5 |
| severity | medium-to-critical | 2 | 0.5 | 0.5 |

## Limitations

- Results do not establish broad generality\.
- Synthetic corpus only\.

## Exclusions

- External-setting cases were excluded\.

## Protocol deviations

None recorded.

Report digest: `sha256:7984d0f7514281fa955cee5a442b141e9356c698d4a64bca271c9709c77be7ea`
