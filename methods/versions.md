# Method versions and evidence limits

This table separates methods that produced historical results from code published later.
Changing a contract requires a newly frozen experiment; it does not upgrade an old result.

| Method or contract | Status | What it establishes |
| --- | --- | --- |
| M3 development v1 | Historical aggregate reports, including a disclosed recovery | The recorded decision was reject on 15 private development cases; raw inputs are unavailable publicly |
| Bundle schema 1 / legacy request contract | Historical compatibility only | Exposed case identity and snapshot metadata to reviewer input; complete provider blinding is not established |
| Bundle schema 2 / prompt manifest 1.3 | Current exported implementation | Opaque HMAC request identity, scorer metadata excluded from reviewer input, labels checked on harness-controlled surfaces |
| M3 v2 prepared | Prepared private protocol; not executed | Requires bundle schema 2 and a label-free prompt; no new outcome or holdout evidence |
| `synthetic-replay-v1`, package 1.0.0 | Public runnable implementation | Byte-stable replay of invented paired outcomes using the exported scorer and statistics code |
| Product `public-smoke-v2` | Separate synthetic CLI regression method | Neutral per-snapshot Git repositories and wrapper-level input checks; see the product's regression-eval documentation |

## Corrections to the case study

The earlier narrative called adjudication human. The recorded M3 execution summary instead
uses model adjudicator labels: primary and recovery primary `Claude Sonnet`, calibration
`Nemotron Ultra`, and resolution `Fable 5`. These are recorded labels, not verified exact model
versions or evidence of a human annotation study. The public narrative now describes
adjudication without claiming human validation.

Adjudication-packet masking and provider-input blinding are different boundaries. The legacy
request contract included case IDs and snapshot labels. The later schema-2 input and leakage
fixes cannot retroactively establish provider blinding for the historical results. Legacy
contracts remain readable for artifact compatibility; they are not the contract for fresh
label-free experiments. Source file contents can legitimately contain words such as `fixed`
or `vulnerable`; current label checks distinguish source content from harness instructions.

All three published primary intervals **include** zero. The fixed false-positive interval
starts at zero; it does not straddle zero. The predeclared effect of practical interest of
three cases (about 20 percentage points) is not an empirically established minimum detectable
effect. No power analysis here justifies the claim that smaller effects are undetectable.

## Provenance and what cannot be reproduced

The exported implementation is pinned in `source-manifest.json`. The methodology correction
was checked against the M3 execution summary in that source revision. Its report digest is
`sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313`, which differs from the
`sha256:e4fde5f124e1ceb4400c486514641013db33768ddd868af680687fbeeafeaaf4` report digest published
with the case study. This is a provenance gap: the current private summary does not establish
an exact artifact binding to the public report. It is sufficient to withdraw the unsupported
human-adjudication claim, not to certify exact public-report adjudicator versions.

`historical-artifacts.json` pins the SHA-256 of each original Markdown file. Those **file-byte
hashes** are distinct from the report's internal content digest. Original reports are left
unchanged; corrections live here and in the case-study narrative.

Private case membership, source snapshots, raw findings, adjudication records, frozen prompts,
and holdout membership are not published. Consequently, the public repository cannot fully
reproduce the historical aggregate results or independently validate their adjudication.
The new synthetic replay demonstrates implementation behavior and exposes inspectable code;
it supplies no replacement evidence for the historical decision and makes no holdout claim.
