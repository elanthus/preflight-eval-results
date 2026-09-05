# Public implementation review repairs

These repairs apply to the public reference implementation. They do not change the frozen
historical reports, the synthetic replay inputs, its expected output, or the primary scoring
rule. They have not been backported to the private evaluation repository.

## Contracts and failure handling

- Failed provider result envelopes retain validated billing metadata. An unreadable outer
  envelope still has unknown usage; the adapter does not infer a bill from malformed bytes.
- Reviewer output must serialize to canonical UTF-8 before the adapter reports success.
  Lone surrogates become `invalid_output` records at that boundary.
- Unknown contract names raise a sanitized `SchemaError`. Retry-recovery record failures
  raise `ExecutionError`, matching the other freeze entry points.
- Parsed latency retains its original JSON integer or fractional representation for digest
  validation while the model exposes a float for calculations.
- Investigation links require valid HTTPS URIs and retain the Markdown character restrictions.
  The dependency lock includes the URI format validator.

## Packaging and provenance

The installed package reads its version from the `preflight-eval-reference` distribution.
The wheel check verifies that version, URI format validation, and the bundled replay outside
the source checkout. The configured `artifacts/` output directory is ignored by Git.

Source manifest version 2 separates imported files from public implementation assets.
Adapted imports retain their original source hashes and describe each repair. Public asset
hashes include the replay entry point, input and expected-output files, packaging scripts,
and regression tests. The checker rejects changed bytes and implementation files omitted
from either inventory. It detects accidental drift, not an attacker rewriting both a file
and its manifest.

The minimum aggregate-report fixture already contained only required fields. It remains the
snapshot for a report without optional discovery data. The full fixture now adds optional
issue-discovery data, with a new content digest and report ID; tests validate both variants.

## Performance and limits

Context truncation still returns the longest fitting candidate for the configured `head`
or `head_tail` policy. It uses tiktoken's completion-stable prefix tokens to eliminate
candidates whose prefix alone exceeds the budget. It never assumes the final token count
is monotonic: all remaining candidates are checked in descending retained length. Tests
compare the result with exhaustive enumeration across three encodings, Unicode, whitespace,
and the existing non-monotonic BPE example.

The remaining scan can still be expensive when stable prefixes give a weak bound, such as a
long unbroken tokenizer piece. This is a pruning optimization, not a linear-time guarantee.
The tokenizer dependency is locked; changes to its unstable-prefix API require rerunning the
exhaustive oracle tests.

Corpus freezing performs its exhaustive optimum search once and reuses that result only in
its private construction path. Generic parsing still recomputes the optimum, including the
seeded tie-break. This avoids duplicate freeze work without trusting a self-supplied digest.
Generic split validation remains combinatorial for large corpora.

Bootstrap modes share one lazily allocated, read-only index matrix per statistics call. The
matrix is released after that calculation; no process-global cache retains large arrays.
The seed, index values, sample means, intervals and synthetic expected bytes are unchanged.
Execution and recovery also share the same terminal-record predicate. Supplemental tests
assert failed-recovery accounting, real scorer boundaries, and a larger synthetic split with
a development lock. Unused scaffolding for the omitted private CLI tests was removed.
