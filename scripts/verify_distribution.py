"""Build with locked tools, install outside the checkout, and verify bundled replay data."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*argv: str, cwd: Path = ROOT) -> None:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    subprocess.run(argv, cwd=cwd, env=environment, check=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="preflight-reference-wheel-") as directory:
        scratch = Path(directory)
        dist = scratch / "dist"
        run(sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist))
        (wheel,) = dist.glob("*.whl")
        requirements = scratch / "requirements.txt"
        run(
            "uv",
            "export",
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
            "--output-file",
            str(requirements),
            "--quiet",
        )
        environment = scratch / "venv"
        run("uv", "venv", "--python", sys.executable, str(environment))
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "-r",
            str(requirements),
        )
        run("uv", "pip", "install", "--python", str(python), "--no-deps", str(wheel))
        outside = scratch / "empty"
        outside.mkdir()
        run(
            str(python),
            "-c",
            "from importlib.metadata import version; "
            "import preflight_evals; "
            "assert preflight_evals.__version__ == version('preflight-eval-reference'); "
            "from jsonschema import FormatChecker; "
            "assert not FormatChecker().conforms('not a valid URI', 'uri')",
            cwd=outside,
        )
        run(
            str(python),
            "-m",
            "preflight_evals.public_replay",
            "--out",
            str(scratch / "replay"),
            "--check",
            str(ROOT / "examples/synthetic-v1/expected.json"),
            cwd=outside,
        )
        print("Installed-wheel replay matches expected bytes outside the source checkout")


if __name__ == "__main__":
    main()
