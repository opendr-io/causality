"""
CVE Prediction Audit
For each CVE in journal.md, finds the earliest prediction file where it was
rated and quotes that exact line.

Usage:
    python audit.py                          # hardcoded dates
    python audit.py --github-dates           # fetch first-commit dates from GitHub
    python audit.py --github-token ghp_xxx  # same, with auth token
    python audit.py --journal path/to/journal.md
"""

import argparse
import csv
import re
import sys
import urllib.request
import urllib.error
import json
from datetime import datetime
from pathlib import Path

# ── Prediction files in chronological order (earliest first) ──────────────────
# Add new runs here. When --github-dates is used the date is replaced with the
# actual first-commit timestamp from the repo.
# NOTE: a "January 31 2025" run is referenced in the journal but no matching
#       file was found in this repo — may exist in a newer version of the data.
PREDICTION_FILES = [
    {"date": "2025-01-03", "label": "Jan 3 2025 run (2024 CVEs)",  "path": r"2024\2024-predictions.txt"},
    {"date": "2025-01-07", "label": "Jan 7 2025 run (2024 CVEs)",  "path": r"2024\predictions-jan-7-run.txt"},
    {"date": "2025-01-08", "label": "Jan 8 2025 run (2025 CVEs)",  "path": r"2025\output-jan-8.txt"},
    {"date": "2025-01-15", "label": "Jan 15 2025 run",             "path": r"2025\jan-15-run.txt"},
    {"date": "2025-01-17", "label": "Jan 17 2025 run (2024 CVEs)", "path": r"2024\2024-predictions-jan-17-run.txt"},
    {"date": "2025-01-17", "label": "Jan 17 2025 run (2025 CVEs)", "path": r"2025\jan-17-run.txt"},
    {"date": "2025-02-15", "label": "Feb 15 2025 run",             "path": r"2025\feb-15-run.txt"},
    {"date": "2025-05-08", "label": "May 8 2025 run",              "path": r"2025\may-8-run.txt"},
    {"date": "2025-05-13", "label": "May 13 2025 run",             "path": r"2025\may-13-o4.txt"},
    {"date": "2025-05-24", "label": "May 24 2025 run (2024 CVEs)", "path": r"2024\2024-output-may-24.txt"},
    {"date": "2025-08-01", "label": "August 2025 run",             "path": r"2025\August\august-2025-combined-ratings.txt"},
    {"date": "2025-09-14", "label": "Sep 14 2025 run",             "path": r"2025\September\2025-ratings-sep-14.txt"},
    {"date": "2025-12-02", "label": "Dec 2 2025 run",              "path": r"2025\November\december-2-ratings.txt"},
    {"date": "2026-01-01", "label": "Jan 2026 run",                "path": r"2025\Final run Jan 2026\2025-ratings-final.txt"},
    {"date": "2026-01-15", "label": "2025 processed-clean (HEAD)", "path": r"HEAD\2025-processed-clean.txt"},
    {"date": "2026-03-01", "label": "March 2026 run",              "path": r"HEAD\2026-MARCH-RUN.csv"},
    {"date": "2026-04-01", "label": "April 2026 run",              "path": r"HEAD\2026-april-run.csv"},
    {"date": "2026-06-01", "label": "June 1 2026 run",             "path": r"HEAD\2026-june-1.txt"},
]

GITHUB_REPO = "cyberdyne-ventures/predictions"

MONTH_MAP = {
    "january": "01", "february": "02", "march": "03",    "april": "04",
    "may": "05",     "june": "06",     "july": "07",     "august": "08",
    "september": "09","october": "10",  "november": "11", "december": "12",
    "jan": "01", "feb": "02", "mar": "03", "apr": "04",
    "jun": "06", "jul": "07", "aug": "08", "sep": "09",
    "oct": "10", "nov": "11", "dec": "12",
}

CVE_RE   = re.compile(r"CVE-\d{4}-\d+")
YEAR_RE  = re.compile(r"^\s*(\d{4})\s*:?\s*$")
DATE_RE  = re.compile(
    r"^\s*(January|February|March|April|May|June|July|August|September|"
    r"October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\w*\s+(\d{1,2})\s*:",
    re.IGNORECASE,
)
DATE_COMPACT_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(\d{1,2})\s",
    re.IGNORECASE,
)


def get_journal_dates(journal_path: Path) -> dict:
    """Return {cve_id: earliest_kev_date} by scanning the journal.

    The journal is reverse-chronological, so we overwrite on every hit;
    the last write for any CVE is the earliest (oldest) KEV addition date.
    """
    cve_dates = {}
    current_year = ""
    current_date = ""

    for line in journal_path.read_text(encoding="utf-8").splitlines():
        m = YEAR_RE.match(line)
        if m:
            current_year = m.group(1)
            continue

        m = DATE_RE.match(line)
        if m:
            month = MONTH_MAP.get(m.group(1).lower(), "")
            day   = m.group(2).zfill(2)
            if current_year and month:
                current_date = f"{current_year}-{month}-{day}"

        m = DATE_COMPACT_RE.match(line)
        if m:
            month = MONTH_MAP.get(m.group(1).lower(), "")
            day   = m.group(2).zfill(2)
            if current_year and month:
                current_date = f"{current_year}-{month}-{day}"

        if current_date:
            for cve in CVE_RE.findall(line):
                cve_dates[cve] = current_date   # overwrite keeps earliest

    return cve_dates


def get_first_commit_date(repo: str, file_path: str, token: str = "") -> str | None:
    """Return the date of the first commit that touched file_path in repo."""
    api_path = file_path.replace("\\", "/")
    headers  = {"User-Agent": "cve-audit-script"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    page   = 1
    oldest = None

    while True:
        url = (
            f"https://api.github.com/repos/{repo}/commits"
            f"?path={api_path}&per_page=100&page={page}"
        )
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                batch = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            print(f"  WARNING: GitHub API {e.code} for {file_path} (page {page})", file=sys.stderr)
            break
        except Exception as e:
            print(f"  WARNING: GitHub API error for {file_path}: {e}", file=sys.stderr)
            break

        if not batch:
            break

        oldest = batch[-1]
        if len(batch) < 100:
            break
        page += 1

    if oldest:
        return oldest["commit"]["committer"]["date"][:10]
    return None


def search_file(path: Path, cve: str) -> str | None:
    """Return the first line in path containing cve, or None."""
    try:
        for line in path.open(encoding="utf-8", errors="replace"):
            if cve in line:
                return line.rstrip()
    except OSError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="CVE prediction audit")
    parser.add_argument("--root",          default=str(Path(__file__).parent))
    parser.add_argument("--journal",       default="")
    parser.add_argument("--out-csv",       default="")
    parser.add_argument("--out-txt",       default="")
    parser.add_argument("--github-dates",  action="store_true",
                        help="Fetch first-commit dates from GitHub API")
    parser.add_argument("--github-token",  default="",
                        help="GitHub personal access token (raises rate limit)")
    parser.add_argument("--github-repo",   default=GITHUB_REPO)
    args = parser.parse_args()

    root        = Path(args.root)
    journal     = Path(args.journal) if args.journal else root / "journal.md"
    out_csv     = Path(args.out_csv) if args.out_csv else root / "audit-results.csv"
    out_txt     = Path(args.out_txt) if args.out_txt else root / "audit-results.txt"

    files = [dict(f) for f in PREDICTION_FILES]   # shallow copy so we can mutate dates

    # ── Optionally fetch GitHub first-commit dates ────────────────────────────
    if args.github_dates:
        print(f"Fetching first-commit dates from github.com/{args.github_repo} ...")
        for f in files:
            date = get_first_commit_date(args.github_repo, f["path"], args.github_token)
            if date:
                f["date"] = date
                print(f"  {f['path']} -> {date}")
            else:
                print(f"  {f['path']} -> could not fetch, keeping estimate ({f['date']})")
        files.sort(key=lambda f: f["date"])
        print()

    # ── Parse journal ─────────────────────────────────────────────────────────
    journal_text = journal.read_text(encoding="utf-8")
    cve_ids      = sorted(set(CVE_RE.findall(journal_text)))
    journal_dates = get_journal_dates(journal)

    print(f"Journal  : {journal}")
    print(f"CVEs     : {len(cve_ids)} unique IDs extracted")
    print()

    # ── Search prediction files ───────────────────────────────────────────────
    results  = []
    not_found = 0

    for cve in cve_ids:
        hit = None
        for f in files:
            full = root / f["path"]
            if not full.exists():
                continue
            line = search_file(full, cve)
            if line is not None:
                hit = {
                    "CVE":              cve,
                    "KEV Date":         journal_dates.get(cve, ""),
                    "Github Timestamp": f["date"],
                    "RunLabel":         f["label"],
                    "File":             f["path"],
                    "Line":             line,
                }
                break

        if hit:
            print(f"  [FOUND]     {cve}  ->  {hit['RunLabel']}")
        else:
            hit = {
                "CVE":              cve,
                "KEV Date":         journal_dates.get(cve, ""),
                "Github Timestamp": "",
                "RunLabel":         "NOT FOUND",
                "File":             "",
                "Line":             "",
            }
            print(f"  [NOT FOUND] {cve}", file=sys.stderr)
            not_found += 1

        results.append(hit)

    found = len(results) - not_found

    # ── CSV output ────────────────────────────────────────────────────────────
    fieldnames = ["CVE", "KEV Date", "Github Timestamp", "RunLabel", "File", "Line"]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\nCSV  -> {out_csv}")

    # ── Plain-text output ─────────────────────────────────────────────────────
    sep        = "-" * 80
    date_source = (
        f"from GitHub commit history ({args.github_repo})"
        if args.github_dates
        else "hardcoded estimates (use --github-dates for authoritative dates)"
    )
    lines = [
        "CVE PREDICTION AUDIT REPORT",
        f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Journal    : {journal}",
        f"Dates      : {date_source}",
        f"Total CVEs : {len(results)}  |  Found: {found}  |  Not found: {not_found}",
        sep,
    ]

    for r in results:
        lines.append("")
        lines.append(f"CVE              : {r['CVE']}")
        lines.append(f"KEV Date         : {r['KEV Date']}")
        if r["RunLabel"] == "NOT FOUND":
            lines.append("Github Timestamp : NOT FOUND in any prediction file")
        else:
            lines.append(f"Github Timestamp : {r['Github Timestamp']}  ({r['RunLabel']})")
            lines.append(f"File             : {r['File']}")
            lines.append(f"Line             : {r['Line']}")

    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Text -> {out_txt}")
    print(f"\nDone. {found} / {len(results)} CVEs matched to a prediction file.")


if __name__ == "__main__":
    main()
