# Case study: a pre-registered evaluation that said no

**One-line summary.** I built a pre-registered evaluation harness to test whether a
candidate adversarial review profile improved an LLM code reviewer, ran the frozen
experiment, and published the negative result unedited: **reject**.

## Result

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable-detection lift | +1/45 (+2.2pp) | [−11.1pp, +15.6pp] |
| Fixed-control false-positive increase | +2/45 (+4.4pp) | [0.0pp, +13.3pp] |
| Net useful lift | −1/45 (−2.2pp) | [−13.3pp, +6.7pp] |

**In plain terms.** Each of 15 test cases is a real bug in two versions of the same code: a
*vulnerable* snapshot with the bug and a *fixed* snapshot with it repaired. Each snapshot was
reviewed three times with the existing review instructions (the *baseline* profile) and three
times with the new ones (the *candidate* profile). Across the 15 cases, that gives 45
baseline-versus-candidate pairs on the vulnerable snapshots, 45 on the fixed snapshots, and
180 runs in all.

- **Vulnerable-detection lift.** On the vulnerable snapshots, the candidate caught the known
  bug once more than the baseline.
- **Fixed-control false-positive increase.** On the fixed snapshots, the candidate reported
  the already-repaired bug twice more than the baseline.
- **Net useful lift.** The first figure minus the second: one extra catch against two extra
  false alarms.

**Decision: reject.** Net useful lift was non-positive and fixed-control false positives
increased. Either result independently triggers the reject rule, which was frozen before the
experiment ran.

**How far this goes.** This is a "no demonstrated benefit, slight harm signal" rejection —
every interval includes zero, and the observed effects are smaller than the pre-declared
effect of practical interest. The rule is deliberately asymmetric: the candidate carries the
burden of proof, and a tie goes to the baseline. The result is not proof the candidate is
harmful; it is proof the candidate did not earn adoption on this corpus.

Earlier versions of this page and its reports needed corrections; they are listed with
dates under [Corrections](https://elanthus.github.io/preflight-eval-results/methods/versions.html#corrections). Read them before relying on these results.

## The question

[Agentic Preflight](https://pypi.org/project/agentic-preflight/) is a quality gate that runs
an LLM review over a branch before it ships.
The hypothesis: a candidate "adversarial" review profile would help the reviewer find real,
known defects (better recall on vulnerable code) without making it hallucinate problems in
code that had already been fixed (false positives on repaired code).

Vibes were not an acceptable answer. The evaluation had to distinguish "finds more real
bugs" from "flags more of everything."

## Method

Other pages on this site call this experiment M3.

- **Corpus.** 15 development cases reconstructed from real dogfooding evidence — the
  observational record behind them is a separate two-week dogfooding case study in the
  product's documentation, built from public pull-request records. Which findings became
  evaluation cases remains private. The fixed snapshot of each case is a built-in
  false-positive control: a reviewer that claims the repaired defect is still present is
  measurably wrong.
- **Design.** Paired baseline-vs-candidate runs over vulnerable and fixed × 3 repetitions —
  180 planned runs. Execution order randomized and interleaved; model, prompt, schema,
  retry policy, and environment frozen by digest before the first provider call.
- **Pre-registered decision rule.** Frozen before execution: *adopt* required repeatable
  lift with a strictly positive 95% interval lower bound and no false-positive increase;
  *reject* triggered on non-positive net lift **or** any fixed-control false-positive
  increase. The minimum effect of practical interest (3 cases, ~20 percentage points) was
  declared in advance.
- **Statistics.** Exact paired counts with case-clustered percentile bootstrap intervals
  (100,000 resamples, fixed seed). The case, not the run, is the unit of analysis: repeated
  runs of one case share its code and defect, so they are not independent evidence.
  Intervals computed over 180 runs would have overstated precision.
- **Adjudication.** Models, not people, judged the reviewer's findings. The tracked
  execution summary records `Claude Sonnet` as the primary adjudicator, `Nemotron Ultra` for
  calibration, and `Fable 5` for disagreement resolution. These are actor labels, not
  independently verified exact model versions. Adjudication packets exposed neither the
  condition, the snapshot label, nor the expected answer beyond a short matching rubric.
  The recorded calibration statistic was raw agreement only (94.74%); no kappa or other
  chance-corrected statistic was computed.

## What went wrong, and what that's worth

- **Failed runs were recovered, not dropped.** The first analysis pass ended in
  **insufficient evidence**, not reject: 18 of 180 runs terminated in documented failures,
  leaving the primary paired effects undefined. The frozen protocol prohibited quietly
  dropping them, so that result was published as-is. A scoped, approved recovery then reran
  exactly the 18 failed runs with enlarged output-capture limits while preserving the cases,
  ordering, profiles, prompt, schema, model, and retry policy. The final report discloses
  the deviation. Both reports — the inconclusive one and the reject — are published with
  digests.
- **A claim about adjudicators was withdrawn.** The earlier narrative said people adjudicated
  the findings. The records did not support that, so the claim was withdrawn.
- **Request identity was repaired forward, not backward.** Legacy reviewer requests carried
  case and snapshot metadata, so the reviewer's input was not blind to them. The current
  contract uses an opaque HMAC request identity, but that repair does not retroactively
  establish blinding for the historical run.

## Limitations, stated plainly

- Fifteen cases give imprecise estimates. The ~20pp practical-interest threshold is not a
  demonstrated detection limit; these intervals do not establish equivalence or exclude
  smaller improvements.
- The provider used for the pre-registered experiment exposed no billed usage, so its actual
  cost remains unknown against a frozen worst-case budget. The later
  [Claude Sonnet 5 operational rerun](#supplemental-claude-sonnet-5-rerun) reported a $78.57
  known-cost lower bound, but it does not recover the original experiment's cost.
- Results cover a local development corpus; no holdout or large-context generalization is
  claimed. M3 did not run the reserved holdout set of seven cases. According to the
  operator's execution record, the later M3.1 follow-up ran that set in a combined 22-case
  analysis, which ended in insufficient evidence; see the
  [method and results write-up](https://elanthus.github.io/preflight-eval-results/methods/method-and-results.html).

## Why publish a negative result

The rule was frozen before the first provider call, so its answer is the result. A harness
that can only say yes is not evidence of anything.

The implementation exposes frozen manifests, leakage validation, append-only adjudication
records, paired scoring, and canonical reports. The historical reject decision shows that
the adoption rule could decline a candidate. It does not establish the correctness of every
input boundary or adjudication. The public reference implementation makes synthetic replay
inspectable and runnable; the versioned method records the remaining evidence gaps.

Next step, when warranted: a revised candidate profile, informed by the
[exploratory error analysis](#exploratory-issue-discovery), evaluated under a newly frozen
experiment against the same discipline.

## Beyond the pre-registered result

Nothing in this section changes the reject decision. It records one exploratory analysis of
the M3 runs, a later rerun with a different reviewer model, and an audit of that rerun's
fixed-snapshot findings. The M3.1 follow-up is noted under
[Limitations](#limitations-stated-plainly).

### Exploratory issue discovery

The reviewer also reported issues other than the known bugs. The exploratory (non-primary)
analysis reported ~0.90 overall finding precision. On fixed snapshots, candidate finding
precision was 0.96 versus the baseline's 0.85. The final report records
**64 deduplicated valid issues, including 60 beyond the planted mechanisms**.
"Planted mechanisms" means the known bugs: the defect each case was built around.
An earlier version of that report recorded 63; [the correction note](https://elanthus.github.io/preflight-eval-results/methods/versions.html#corrections) explains the change.

### Supplemental Claude Sonnet 5 rerun

The same 180-run development plan was later rerun through Claude Code with
`claude-sonnet-5` to validate provider-reported cost collection. This was an operational
rerun with a different reviewer model, not a replacement for the pre-registered result. It
completed 179 of 180 planned runs. One vulnerable candidate run ended in a local
trace-retention error after the provider process exited successfully; it was not repeated
because doing so could have created a duplicate billed request.

The table below uses a cruder score than the Result table and must not be compared with it.
These are raw per-run detection scores, not the protocol's adjudicated expected-mechanism
metrics: a run is positive when the reviewer emits at least one finding, and vulnerable
snapshots are the positive class. A finding on a fixed snapshot therefore counts as a false
positive even if it identifies a legitimate unrelated defect. The one failed vulnerable run
is scored pessimistically as a false negative.

| Profile | Precision | Recall | F1 | TP / FP / FN / TN |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 56.06% | 82.22% | 66.67% | 37 / 29 / 8 / 16 |
| Candidate | 60.66% | 82.22% | 69.81% | 37 / 24 / 8 / 21 |
| Combined | 58.27% | 82.22% | 68.20% | 74 / 53 / 16 / 37 |

For the same reason, these figures must not be compared directly with the adjudicated
finding-precision figures elsewhere on this page. The table preserves the historical M3
descriptive calculation. New aggregate-report `2.0` outputs replace that shortcut for
supplemental discovery: they use each mechanism's verified snapshot expectation, exclude
`unverified` pairs, and keep those metrics separate from the unchanged primary adoption
decision.

Claude Code reported **$78.57 in known provider cost** across 180 attempts with retained
billing metadata: $78.35 attached to 179 terminal records plus $0.22 for one invalid-output
attempt that succeeded on retry. That sum is a lower bound, not the experiment's cost: the
trace-retention failure lost the remaining successful provider response's request ID, token
usage, and cost. Known attempts reported 11,285,403 input tokens, including 5,855,131 cached
input tokens, and 3,354,730 output tokens.

### Fixed-control finding audit

This audit reviewed the rerun's fixed-snapshot findings, not those of the original M3 runs.
The rerun's raw per-run table deliberately labels every fixed run with a finding as
positive, but that convention does not establish that every finding is wrong. The later
audit record
describes all 66 finding instances from the 53 fixed-positive runs passing through actors
labeled `Luna` and `Terra`, followed by `Terra` disagreement resolution. These are recorded
model actor labels, not independently verified exact model versions. The record describes
separate passes with masked adjudication packets; it does not independently establish actor
independence or complete blinding, including the provider-input boundary. It classified
**50 findings as valid issues, 16 as invalid claims, and none as unresolved**, for 75.76%
finding precision.
After opaque within-case deduplication, the valid findings represented 28 issue keys.

At the run level, 42 of 53 nominal fixed positives contained at least one valid issue; 11
contained only invalid claims. Baseline finding precision was 27/35 (77.14%), and candidate
precision was 23/31 (74.19%). These results explain why raw vulnerable-versus-fixed
precision understates useful code-review behavior. They do not change the pre-registered
M3 mechanism score or the raw table.

The audit's packet and decision payloads have a $0.60 API-list-price estimate: $0.03 for
Luna and $0.57 for Terra. This is not provider-reported Codex billing; it excludes system
prompts, reasoning tokens, caching, and platform overhead. The private audit summary is
bound by digest
`sha256:b34883a22f5d6c1c5a0231e9a324b44cab761283a65263bdf01041b29862b3bc`.

Those 28 issue keys now seed a separately versioned, development-only Gold 2.0 expectation
set. Gold 2.0 records each mechanism as present, absent, or unverified on each snapshot, so a
fixed-snapshot defect can be a true positive without being confused with the repaired
primary mechanism. Case-level labels remain private, and the frozen M3 gold is unchanged.

## Full aggregate reports

- [Final result: reject](https://elanthus.github.io/preflight-eval-results/m3-development-reject.html)
- [Initial result: insufficient evidence (pre-recovery)](https://elanthus.github.io/preflight-eval-results/m3-development-insufficient-evidence.html)

---

*Only aggregate results appear on this page. Case identities, source revisions, prompts, raw
findings, and reserved-set assignments remain private by design. The final-report digest below
identifies the linked final report; it does not bind the supplemental operational rerun:
`sha256:d86cc844b750e3eb2cd6aa9e9068c3d2cad6742c5180a4ee3b589eb59bc8d313`.*
