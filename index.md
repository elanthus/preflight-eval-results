# Case study: a pre-registered evaluation that said no

**One-line summary.** I built a pre-registered evaluation harness to test whether a
candidate adversarial review profile improved an LLM code reviewer, ran the frozen
experiment, and published the negative result unedited: **reject**.

**Method correction:** historical provider inputs exposed scorer labels, and the available
records do not support a human-adjudication claim. The reports below are preserved; see
[versioned methodology and provenance limits](methods/versions.md) and the
[runnable synthetic implementation](README.md).

## The question

Agentic Preflight is a quality gate that runs an LLM review over a branch before it ships.
The hypothesis: a candidate "adversarial" review profile would help the reviewer find real,
known defects (better recall on vulnerable code) without making it hallucinate problems in
code that had already been fixed (false positives on repaired code).

Vibes were not an acceptable answer. The evaluation had to distinguish "finds more real
bugs" from "flags more of everything."

## Method

- **Corpus.** 15 development cases reconstructed from real dogfooding evidence — the
  observational record behind them is published separately as a
  [two-week dogfooding case study](https://github.com/elanthus/agentic-preflight/blob/main/docs/dogfooding-case-study.md)
  built from public pull-request records. Which findings became evaluation cases remains
  private. Each case has a
  *vulnerable* snapshot (defect present) and a *fixed* snapshot (defect repaired). The fixed
  snapshot is a built-in false-positive control: a reviewer that claims the repaired defect
  is still present is measurably wrong.
- **Design.** Paired baseline-vs-candidate runs over vulnerable/fixed × 3 repetitions —
  180 planned runs. Execution order randomized and interleaved; model, prompt, schema,
  retry policy, and environment frozen by digest before the first provider call.
- **Adjudication.** The workflow masked condition labels in adjudication packets. Available
  execution records name model adjudicators; this was not established as a human annotation
  study. Historical provider-input labels and an artifact-binding gap limit the evidence;
  see the versioned method before interpreting the results.
- **Pre-registered decision rule.** Frozen before execution: *adopt* required repeatable
  lift with a strictly positive 95% interval lower bound and no false-positive increase;
  *reject* triggered on non-positive net lift **or** any fixed-control false-positive
  increase. The minimum effect of practical interest (3 cases, ~20 percentage points) was
  declared in advance.
- **Statistics.** Exact paired counts with case-clustered percentile bootstrap intervals
  (100,000 resamples, fixed seed). The case, not the run, is the unit of analysis.

## Result

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable-detection lift | +1/45 (+2.2pp) | [−11.1pp, +15.6pp] |
| Fixed-control false-positive increase | +2/45 (+4.4pp) | [0.0pp, +13.3pp] |
| Net useful lift | −1/45 (−2.2pp) | [−13.3pp, +6.7pp] |

Net useful lift was non-positive and fixed-control false positives increased. Either result
independently triggers the frozen reject rule. **Decision: reject.**

Read carefully, this is a "no demonstrated benefit, slight harm signal" rejection — every
interval includes zero, and the observed effects are smaller than the
pre-declared effect of practical interest. The rule is deliberately asymmetric: the candidate
carries the burden of proof, and a tie goes to the baseline. The result is not proof the
candidate is harmful; it is proof the candidate did not earn adoption on this corpus.

## What went wrong, and what that's worth

The first analysis pass ended in **insufficient evidence**, not reject: 18 of 180 runs
terminated in documented failures, leaving the primary paired effects undefined. The frozen
protocol prohibited quietly dropping them, so that result was published as-is, and a scoped,
approved recovery reran exactly the 18 failed runs with enlarged output-capture limits while
preserving the cases, ordering, profiles, prompt, schema, model, and retry policy. The
deviation is disclosed in the final report. Both reports — the inconclusive one and the
reject — are published with digests.

Separately, the exploratory (non-primary) analysis showed the candidate wasn't inert: its
finding precision on fixed snapshots was 0.96 versus the baseline's 0.85, and across the
experiment the exploratory assessment classified 63 deduplicated issues as valid (59 beyond
the planted mechanisms) at ~0.90 overall precision. The candidate changes reviewer behavior — it just
doesn't detectably improve detection of the target defects, which is the thing adoption
was gated on.

## Limitations, stated plainly

- Fifteen cases give imprecise estimates. The ~20pp practical-interest threshold is not a
  demonstrated detection limit; the intervals do not establish equivalence or exclude
  smaller improvements.
- The provider CLI exposed no billed usage, so actual cost is reported as unknown against a
  frozen worst-case budget rather than estimated and presented as fact.
- Results cover a local development corpus; no holdout or large-context generalization is
  claimed. A reserved holdout set exists and remains unexecuted.

## Why publish a negative result

The implementation exposes frozen manifests, leakage validation, append-only adjudication
records, paired scoring, and canonical reports. The historical reject decision shows that
the adoption rule could decline a candidate. It does not establish the correctness of every
input boundary or adjudication. The public synthetic replay makes the current code
inspectable and runnable while the versioned method states the remaining evidence gaps.

Next step, when warranted: a revised candidate profile, informed by the exploratory error
analysis, evaluated under a newly frozen experiment against the same discipline.

## Full aggregate reports

- [Final result: reject](https://elanthus.github.io/preflight-eval-results/m3-development-reject.html)
- [Initial result: insufficient evidence (pre-recovery)](https://elanthus.github.io/preflight-eval-results/m3-development-insufficient-evidence.html)

---

*Only aggregate, disclosure-validated results appear above. Case identities, source
revisions, prompts, raw findings, and holdout membership remain private by design. Final
report digest: `sha256:e4fde5f124e1ceb4400c486514641013db33768ddd868af680687fbeeafeaaf4`.*
