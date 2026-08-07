"""
Run the full CVE database pipeline, one step at a time, stopping immediately
if any step fails.

Steps:
    1. auditor/audit.py --github-dates             -> auditor/audit-results.csv
    2. database/verify_ingestion_search.py --generate-rating-dates
                                                      -> database/rating_dates.csv
    3. database/build_cve_db.py                     -> database/cve.db
    4. database/verify_ingestion_search.py           (sanity check against cve.db)

Usage:
    python run_pipeline.py
    python run_pipeline.py --skip-audit    # reuse the existing audit-results.csv
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
AUDITOR_DIR = ROOT_DIR / "auditor"
DATABASE_DIR = ROOT_DIR / "database"


def run_step(description: str, cmd: list[str], cwd: Path) -> None:
    print(f"\n==> {description}", flush=True)
    print(f"    $ {' '.join(cmd)}  (in {cwd})", flush=True)
    # PYTHONUNBUFFERED so the child process's output interleaves live with
    # ours, instead of Python block-buffering it and dumping it all at once
    # at the end (which happens by default when stdout isn't a real tty).
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    result = subprocess.run(cmd, cwd=cwd, env=env)
    if result.returncode != 0:
        raise SystemExit(
            f"ERROR: step failed ({description}), exit code {result.returncode}. "
            "Stopping -- later steps were not run."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full CVE database pipeline.")
    parser.add_argument(
        "--skip-audit", action="store_true",
        help="Skip step 1 and reuse the existing auditor/audit-results.csv.",
    )
    args = parser.parse_args()

    python = sys.executable

    if args.skip_audit:
        print("\n==> Skipping step 1 (audit.py) -- reusing existing audit-results.csv")
    else:
        run_step(
            "Step 1/4: audit.py --github-dates",
            [python, "audit.py", "--github-dates"],
            cwd=AUDITOR_DIR,
        )

    run_step(
        "Step 2/4: verify_ingestion_search.py --generate-rating-dates",
        [python, "verify_ingestion_search.py", "--generate-rating-dates"],
        cwd=DATABASE_DIR,
    )

    run_step(
        "Step 3/4: build_cve_db.py",
        [python, "build_cve_db.py"],
        cwd=DATABASE_DIR,
    )

    run_step(
        "Step 4/4: verify_ingestion_search.py (verify against cve.db)",
        [python, "verify_ingestion_search.py"],
        cwd=DATABASE_DIR,
    )

    print("\nPipeline complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
