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

## Corrections

Every correction to the case study, the method write-up, and the aggregate reports is listed
here once, oldest first. Other pages point here rather than restating them.

- **2026-08-21: beyond-planted count.** The case study first presented 63 deduplicated issues
  as all lying beyond the planted mechanisms. Of those 63, 59 were beyond them.
- **2026-09-04: adjudication was by models, not people.** The earlier narrative called
  adjudication human. The recorded M3 execution summary instead uses model adjudicator labels:
  primary and recovery primary `Claude Sonnet`, calibration `Nemotron Ultra`, and resolution
  `Fable 5`. These are recorded labels, not verified exact model versions or evidence of a
  human annotation study.
- **2026-09-04: masking is not provider-input blinding.** Adjudication packets were masked,
  but the legacy request contract sent case IDs and snapshot labels to the reviewer. The later
  schema-2 input and leakage fixes cannot retroactively establish provider blinding for the
  historical results. Legacy contracts remain readable for artifact compatibility; they are
  not the contract for fresh label-free experiments. Source file contents can legitimately
  contain words such as `fixed` or `vulnerable`; current label checks distinguish source
  content from harness instructions.
- **2026-09-04: intervals and effect size.** All three published primary intervals
  **include** zero. The fixed false-positive interval starts at zero; it does not straddle
  zero. The predeclared effect of practical interest of three cases (about 20 percentage
  points) is not an empirically established minimum detectable effect, and no power analysis
  here justifies the claim that smaller effects are undetectable.
- **2026-09-23: the final report now shows 64 valid issues.** The M3 reject report was first
  published on 2026-08-21 under digest `sha256:e4fde5f124e1ceb4400c486514641013db33768ddd868af680687fbeeafeaaf4` with 63 deduplicated valid issues (59 beyond the
  planted mechanisms); on 2026-08-25 it was regenerated under digest `sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313` after a separately
  blinded, digest-linked source-context amendment resolved the one supplemental discovery
  finding whose source validity had been uncertain as a valid issue, raising those counts to
  64 and 60 while leaving the primary mechanism metrics and the reject decision unchanged.
  The [final report](../m3-development-reject.md) now publishes the `d86cc844` revision, and
  `historical-artifacts.json` records the replaced file.
- **2026-09-23: report Markdown re-rendered; JSON published.** The aggregate reports now show
  ratios and interval bounds to three decimals, latency in whole milliseconds, and money to two
  decimals. Each report's canonical JSON is published beside its Markdown and keeps the exact
  values. Apart from the reject report above, no report's content digest changed.
- **2026-09-23: Luna and Terra.** The fixed-control audit's `Luna` and `Terra` actor labels
  correspond to the Codex models `gpt-5.6-luna` and `gpt-5.6-terra`; these are Codex model
  names, not dated model snapshots.

## Provenance and what cannot be reproduced

The exported implementation is pinned in `source-manifest.json`. The methodology correction
was checked against the M3 execution summary in that source revision, whose report digest,
`sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313`, is the digest the final report now publishes.

`historical-artifacts.json` pins the SHA-256 of each published report's Markdown and JSON file
and records every replaced file's earlier hash and content digest. Those **file-byte hashes**
are distinct from each report's internal content digest.

Private case membership, source snapshots, raw findings, adjudication records, frozen prompts,
and holdout membership are not published. Consequently, the public repository cannot fully
reproduce the historical aggregate results or independently validate their adjudication.
The new synthetic replay demonstrates implementation behavior and exposes inspectable code;
it supplies no replacement evidence for the historical decision and makes no holdout claim.
