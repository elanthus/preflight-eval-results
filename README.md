# Preflight evaluation reference

Run a complete offline scoring and statistical replay with public synthetic inputs. This
repository also publishes the reusable evaluation library and preserves the historical
aggregate reports for the Agentic Preflight review-profile experiment.

The replay makes **zero model calls**. It reproduces the synthetic result exactly; the private
inputs needed to reproduce the historical 15-case experiment are not included.

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

[source-manifest.json](source-manifest.json) pins the exported library and synthetic test
files to source revision `7e8bebc77111da89461c4ca073fb472239d217dc`. Runtime modules are copied
unchanged; test adaptations are recorded individually. New public replay code is versioned
by this repository's Git history. No private Git history, case corpus, holdout membership,
raw findings, or provider traces are exported.

## Historical evidence

Read the [corrected case study](index.md), [final aggregate report](m3-development-reject.md),
and [initial aggregate report](m3-development-insufficient-evidence.md). The reports retain
their original bytes. [Method versions](methods/versions.md) distinguish the historical
request contract, current leakage controls, and this synthetic replay. Historical claims of
human adjudication and complete provider blinding are withdrawn; current fixes cannot
retroactively establish those properties for an earlier run.

This is a public reference implementation. The existing proprietary licensing designation is
retained; publication does not add an open-source license.
