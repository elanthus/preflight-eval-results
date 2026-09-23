# Preflight evaluation reference

I built a pre-registered evaluation harness to test whether a candidate adversarial review
profile improved an LLM code reviewer, ran the frozen experiment, and published the negative
result unedited: **reject**.

| Metric | Exact difference | 95% interval |
| --- | ---: | ---: |
| Vulnerable-detection lift | +1/45 (+2.2pp) | [−11.1pp, +15.6pp] |
| Fixed-control false-positive increase | +2/45 (+4.4pp) | [0.0pp, +13.3pp] |
| Net useful lift | −1/45 (−2.2pp) | [−13.3pp, +6.7pp] |

In plain terms: each of 15 test cases is a real bug in two versions of the same code, one
with the bug and one with it fixed, and each was reviewed three times with the old review
instructions and three times with the new ones: 45 old-versus-new pairs for each version,
90 pairs and 180 runs in all. On the buggy versions, the new instructions caught the bug
once more than the old ones; on the fixed versions, they complained about already-fixed code
twice more. That is no demonstrated benefit and a slight sign of harm, so
the rule written down before the experiment said not to adopt them. The sample is small, and
every interval includes zero.

Read the full case study at **[elanthus.github.io/preflight-eval-results](https://elanthus.github.io/preflight-eval-results/)**.

*By Michael Swailes.*

This repository publishes that case study, its aggregate reports, and the reusable evaluation
library, with an offline synthetic replay you can run. The replay makes **zero model calls**.
It reproduces the synthetic result exactly; the private inputs needed to reproduce the
historical 15-case experiment are not included.

## Reproduce the example

Install Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/getting-started/installation/),
then run from a clone of this repository:

```sh
uv sync --locked --all-groups
uv run --locked preflight-eval-reference --out replay-output --check examples/synthetic-v1/expected.json
```

The command validates typed experiment, run, gold, and adjudication records; runs the real
scorer and paired case-clustered bootstrap; and writes `replay-output/report.json` and
`SHA256SUMS`. `--check` exits with status 2 before writing output if the bytes differ.

Expected report SHA-256:

```text
e90b359a8ee7df5416d2183acceab8766ffce55a5760dd81b9e93dd07fe1d596
```

The example has two fictional cases, two repetitions, two conditions, and two snapshots:
16 scripted terminal records. Candidate detection increases by 2/4 and fixed-control false
positives by 2/4, yielding zero net lift. All adjudications, timing, usage, prices, repository
names, and source identifiers in the example are invented fixtures. Inner schema labels such
as `measured` or `provider_reported` exercise the production contracts; they describe no real
measurements here. See [the exact method](methods/synthetic-replay-v1.md).

## Inspect and validate the implementation

```sh
uv run --locked ruff check .
uv run --locked mypy
uv run --locked pytest -q
uv run --locked python scripts/check_source_manifest.py
uv run --locked python scripts/verify_distribution.py
```

[CI](.github/workflows/ci.yml) runs these checks on Linux with Python 3.12 and 3.13, including
replay from an installed wheel outside the source checkout. The dependency graph is pinned
in `uv.lock`; the package includes schemas and example data.

The public `preflight_evals` package contains:

| Modules | Responsibility |
| --- | --- |
| `bundle`, `request_contract`, `leakage` | Deterministic reviewer input, opaque request identity, and approval before invocation |
| `adapter`, `execution` | Bounded subprocess execution, frozen plans, retries, and linked recovery |
| `adjudicate`, `score` | Adjudication contracts, primary-mechanism scoring, fixed controls, and unresolved outcomes |
| `statistics`, `report` | Paired effects, seeded intervals, sensitivity bounds, aggregate reports, and disclosure validation |

The command-line entry point is deliberately limited to offline synthetic replay. The Python
library exposes the underlying evaluation components; the private corpus-curation CLI and
operational corpus are not distributed. The adapter tests exercise real subprocess stdin,
timeouts, bounded output, minimal environments, and label rejection without contacting a
provider. These are local integration tests, not evidence of live-provider performance.

[source-manifest.json](source-manifest.json) records the exported library's original source
revision `7e8bebc77111da89461c4ca073fb472239d217dc`, original hashes for adapted exports, and
current hashes with individual repair notes. Its separate `public_files` inventory pins the
replay entry point, inputs, expected output, packaging checks, and public regression tests.
The checker rejects changed bytes and unlisted implementation assets. These hashes detect
accidental drift; they do not authenticate a manifest modified together with its files.
See [the public review repairs](methods/public-review-repairs.md). No private Git history,
case corpus, holdout membership, raw findings, or provider traces are exported.

## Historical evidence

Read the [case study](index.md), the [method and results write-up](methods/method-and-results.md),
the [final aggregate report](m3-development-reject.md), and the
[initial aggregate report](m3-development-insufficient-evidence.md). Each report's canonical
JSON sits beside its Markdown. [Method versions](methods/versions.md) distinguish the
historical request contract, current leakage controls, and this synthetic replay, and list
every correction with its date. Current fixes cannot retroactively establish properties such
as complete provider blinding for an earlier run.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
