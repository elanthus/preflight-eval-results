# Synthetic replay method v1

`synthetic-replay-v1` is an offline implementation check for developers evaluating the code.
It is not a new measurement of reviewer quality and does not reconstruct the private M3 run.

## Inputs and procedure

The committed `examples/synthetic-v1/inputs.json` contains the complete invented experiment,
16 terminal run records, two gold records, scripted adjudication decisions, and a toy price
table. Inputs use the same typed contracts as the library. The replay rejects an unknown
method version or missing explicit `synthetic: true` marker.

The CLI parses those contracts, calls `score_experiment`, then `calculate_statistics`, and
serializes canonical JSON. The output includes the exact input-file SHA-256 and explicit
`synthetic_replay`, `scripted_fixture`, and zero-provider-call markers. SHA-256 verifies
artifact identity, not the truth of the input claims. This command does not invoke the
provider adapter, create a corpus, or collect new adjudications.

## Hand-checkable outcomes

Each row below occurs twice, once per repetition. A positive on a vulnerable snapshot means
a primary-mechanism catch; a positive on a fixed snapshot means a false positive for the
repaired primary mechanism.

| Fictional case | Snapshot | Baseline positive | Candidate positive |
| --- | --- | ---: | ---: |
| repo-one | vulnerable | 0 | 1 |
| repo-one | fixed | 0 | 0 |
| repo-two | vulnerable | 1 | 1 |
| repo-two | fixed | 0 | 1 |

Across four paired observations per snapshot, vulnerable lift is +2/4, the fixed false-positive
increase is +2/4, and net useful lift is 0/4. The bootstrap samples **cases**, retaining their
paired conditions and repetitions together. It uses 100,000 resamples, NumPy PCG64 seed
2026081802, and nearest-rank percentile endpoints for 95% intervals. Net lift has interval
[-1, +1] in this deliberately tiny example. The seed and algorithm are recorded in output.

Unresolved runs stay unresolved in primary estimates and have separate optimistic and
pessimistic sensitivity bounds. The included library tests exercise failed terminal runs,
linked recovery, inconsistent contracts, and supplemental Gold 2.0 mechanisms. The default
replay fixture uses fully resolved Gold 1.0 outcomes and does not claim to exercise every
execution branch.

## Reproducibility boundary

Use the README commands with `--locked`. The expected bytes are committed separately in
`expected.json`; tests also assert the hand-calculated numerators and denominators so a
snapshot comparison is not the only oracle. CI installs the built wheel into a fresh virtual
environment using hashed requirements exported from the lock, changes to an empty directory,
and checks the replay again. Linux Python 3.12 and 3.13 are the CI-supported environments.

The replay can run offline after dependencies are installed. Bundle tests may populate the
`tiktoken` encoding cache on first use; that download is not a model call. Source exports are
listed and hash-checked in `source-manifest.json`. That manifest covers provenance, not a
security audit or a claim that the private historical artifacts are public.

All reported operational fields are fixture values. No latency, billed cost, model accuracy,
adoption benefit, or generalization estimate can be inferred from this replay.
