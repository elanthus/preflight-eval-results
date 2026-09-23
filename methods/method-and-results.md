# Evaluation of an adversarial review profile

## Method

The harness compares a baseline review profile with a candidate profile on paired vulnerable
and fixed snapshots. Each experiment freezes its case manifest, execution order, profiles,
prompt, output schema, model configuration, retry policy, analysis plan, and environment by
digest before execution. Requests are randomized and interleaved.

A leakage gate scans serialized requests before reviewer invocation, but the historical
bundle-1 request contract still exposed case and snapshot metadata. Adjudication packets
masked labels independently of that provider-input boundary. Review outputs and adjudication
imports are append-only. Later bundle-2 repairs do not retroactively establish provider
blinding for M3; see [method versions and provenance limits](https://elanthus.github.io/preflight-eval-results/methods/versions.html).

Canonical JSON reports use sorted, byte-stable serialization and content digests. The public
disclosure boundary rejects case identities, source commits, private identifiers, repository
locations, small membership-revealing cells, raw findings, prompts, and investigation links.
Publication is a separate operator action.

## Frozen M3 decision rule

The M3 analysis plan froze this rule before execution:

> `adopt` requires all 180 planned records to be terminal successes, candidate vulnerable
> lift to be positive in at least two of three repetition strata, at least nine additional
> net useful outcomes, no increase in candidate fixed-control false positives, and a
> strictly positive lower bound for the paired 95% net-useful-lift interval.
>
> `revise` applies when the net-useful point estimate is positive without satisfying every
> adoption criterion and fixed-control false positives do not increase.
>
> `reject` applies when net useful lift is non-positive or fixed-control false positives
> increase.
>
> `insufficient evidence` overrides those labels if any planned run is unresolved, the
> frozen invariant set changes, blinding fails, or adjudication remains incomplete.

The final M3 report applies the rule directly:

> Candidate minus baseline net useful lift is minus one outcome out of 45, while candidate
> fixed-control false positives increase by two outcomes out of 45. Either result
> independently triggers the frozen reject rule.

## M3 result

M3 used 15 development cases, two snapshots, two conditions, and three repetitions. A linked,
approved recovery made all 180 planned runs analyzable. Candidate minus baseline vulnerable
lift was 1/45, or 0.0222, with a 95% interval from -0.1111 to 0.1556. Fixed-control false
positives increased by 2/45, or 0.0444, with an interval from 0 to 0.1333. Net useful lift was
-1/45, or -0.0222, with an interval from -0.1333 to 0.0667. The frozen decision was reject;
both the non-positive net lift and the false-positive increase triggered that decision.

The current private execution summary reports 224 finding instances, 202 classified as
valid and 22 as false positives. It records **64 deduplicated valid issues, including 60
beyond the planted mechanisms**, matching the
[final report](https://elanthus.github.io/preflight-eval-results/m3-development-reject.html)
(digest `sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313`).
An earlier version of that report recorded 63; [the correction note](https://elanthus.github.io/preflight-eval-results/methods/versions.html#corrections) explains the change. These
exploratory measures do not alter the primary decision.

The export also retains the historical M3 pre-recovery report, named
`m3-development-insufficient-evidence` in both Markdown and JSON. Its 15 cases and 180 planned
runs include 18 terminal failures; primary paired effects are therefore undefined. Its
exploratory totals are 188 finding instances, 171 valid instances, and 52 deduplicated issues.
The linked recovery superseded that decision with the final M3 reject report above. This
historical checkpoint is separate from the incomplete M3.1 analysis below.

## M3.1 result

According to the operator's execution record, the offline combined analysis scores 264
existing terminal records from 22 cases. It retains 2 unresolved adjudication decisions.
Candidate minus baseline fixed-control false positives
are -3/66, or -0.0455, but vulnerable lift and net useful lift remain undefined. The
decision-driving project-clustered bounds are suppressed while adjudication is incomplete.
The result is insufficient evidence, not a pass or a reject.

The operator's execution record states that GPT-5.4 and Claude Opus performed the M3.1
adjudication. All M3.1 numbers, the incomplete result, and this roster are attributed to the
operator record. No M3.1 combined report is present in the tracked public evidence, so these
claims cannot be independently reproduced from this export.

## Adjudication record

The M3 execution summary records `Claude Sonnet` as primary adjudicator for 188 source
assignments and then 36
recovery assignments in primary-only mode. Nemotron Ultra independently covered the 38
preselected calibration assignments. It agreed on 36, for 94.74% raw calibration agreement.
Fable 5 independently resolved the two disagreements. This is raw agreement only; no kappa or
other chance-corrected statistic was computed.

The operator authorized these LLMs in roles originally described as human. Blinding refers to
the information withheld from adjudicators, not to adjudicators being human.

## Implemented repairs and proposed method changes

The input-contract repair pinned by the public reference implementation’s
[source manifest](https://elanthus.github.io/preflight-eval-results/source-manifest.json)
implements reviewer bundle schema 2 and prompt manifest 1.3. It replaces case and snapshot fields with an opaque HMAC request identity.
Snapshot-label checks apply to harness-controlled text; repository source may legitimately
contain words such as `fixed` or `vulnerable`. Case IDs and source PR tokens remain forbidden
on both surfaces. This describes that repair revision, not the historical M3 inputs or a
claim that the repair has reached main.

The scorer still requires accepted path and location, category, severity, and adjudicated
mechanism agreement for vulnerable primary hits. Fixed-control primary false positives use
mechanism agreement. Gold 2.0 adds verified per-snapshot supplemental expectations and keeps
those discovery metrics separate from the primary adoption outcome.

A semantic-only primary scoring policy was proposed, but this implementation has no
selectable scoring-policy field. The earlier write-up incorrectly presented it as shipped.
Such a change requires its own contract version, tests, and newly frozen experiment. No new
metric values or retrospective score changes are claimed here.

## Limits

M3 covers a local development corpus and does not estimate reserved-set performance. M3.1 is
incomplete until the two unresolved adjudication decisions are resolved. Provider-reported
token use and actual billed cost were unavailable for both analyses. Aggregate disclosure
does not make private source material, labels, prompts, or case-level outcomes public.
