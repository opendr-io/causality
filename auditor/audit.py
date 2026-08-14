"""
CVE Prediction Audit
For each CVE in README.md, finds the earliest prediction file where it was
RATED (not just mentioned) and quotes that exact line.

A CVE is only credited with a prediction date once it has an "actionable"
rating (warm/hot/fire/neutral) -- appearing in a file rated cold, or with a
blank rating, doesn't count as a prediction. Files with no rating column at
all (e.g. reduction.txt) are treated as implicitly actionable, since those
are pre-filtered exports of already-notable CVEs.

Usage:
    python audit.py                          # hardcoded dates
    python audit.py --github-dates           # fetch first-commit dates from GitHub
    python audit.py --github-token ghp_xxx  # same, with auth token
    python audit.py --journal path/to/README.md
    python audit.py --data-root ..                 # prediction data folders
"""

import argparse
import csv
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import json
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
HEAD_DIR = ROOT_DIR / "HEAD"

PREDICTION_FILES = [
    {"date": "2025-01-03", "label": "Jan 3 2025 run (2024 CVEs)",  "path": r"2024\2024-predictions.txt"},
    {"date": "2025-01-07", "label": "Jan 7 2025 run (2024 CVEs)",  "path": r"2024\predictions-jan-7-run.txt"},
    {"date": "2025-01-17", "label": "Jan 17 2025 run (2024 CVEs)", "path": r"2024\2024-predictions-jan-17-run.txt"},
    {"date": "2025-04-08", "label": "April 2025 reduction (2024 CVEs)", "path": r"2024\reduction.txt"},
    {"date": "2026-02-08", "label": "May 24 2025 run (2024 CVEs)", "path": r"2024\2024-output-may-24.txt"},

    {"date": "2025-01-08", "label": "Jan 8 2025 run (2025 CVEs)",  "path": r"2025\output-jan-8.txt"},
    {"date": "2025-01-15", "label": "Jan 15 2025 run",             "path": r"2025\jan-15-run.txt"},
    {"date": "2025-01-17", "label": "Jan 17 2025 run (2025 CVEs)", "path": r"2025\jan-17-run.txt"},
    {"date": "2025-02-17", "label": "Feb 2025 run",                "path": r"2025\feb-15-run.txt"},
    {"date": "2025-05-08", "label": "May 2025 run",                "path": r"2025\may-8-run.txt"},
    {"date": "2025-08-31", "label": "August 2025 run",             "path": r"2025\August\august-2025-combined-ratings.txt"},
    {"date": "2025-12-02", "label": "December 2025 run",           "path": r"2025\November\december-2-ratings.txt"},
    {"date": "2026-01-31", "label": "2025 ratings final (Jan 31 run)", "path": r"2025\Final run Jan 2026\2025-ratings-final.txt"},
    {"date": "2026-02-08", "label": "2025 ratings final",          "path": r"2025\2025-ratings-final.txt"},
    {"date": "2026-03-21", "label": "2025 processed-clean",        "path": r"HEAD\2025-processed-clean.txt"},

    {"date": "2026-04-25", "label": "April 2026 run",              "path": r"2026\2026-april-1-for-sharing.txt"},
    {"date": "2026-06-01", "label": "June 2026 run",             "path": r"2026\2026-june-1.txt"},
    {"date": "2026-08-07", "label": "August 2026 run",           "path": r"HEAD\2026-august.txt"},
]



GITHUB_REPO = "opendr-io/causality"

MONTH_MAP = {
    "january": "01", "february": "02", "march": "03",    "april": "04",
    "may": "05",     "june": "06",     "july": "07",     "august": "08",
    "september": "09","october": "10",  "november": "11", "december": "12",
    "jan": "01", "feb": "02", "mar": "03", "apr": "04",
    "jun": "06", "jul": "07", "aug": "08", "sep": "09",
    "oct": "10", "nov": "11", "dec": "12",
}

CVE_RE   = re.compile(r"\bCVE\s*[-–— ]\s*(\d{4})\s*[-–— ]\s*(\d{3,})\b", re.IGNORECASE)
BARE_CVE_RE = re.compile(r"\b(20\d{2})-(\d{3,})\b")
YEAR_RE  = re.compile(r"^\s*#{0,3}\s*(\d{4})\s*:?\s*$")
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

# Rating-column name aliases used across the pipeline's various export
# schemas, and the token values that count as an actual rating (as opposed
# to header noise or free text that happens to match).
RATING_COLS   = {"rating", "label", "prediction", "predicted_label"}
RATING_VALUES = {"hot", "cold", "warm", "fire", "neutral"}
ACTIONABLE_VALUES = RATING_VALUES - {"cold"}


def extract_cves_from_line(line: str) -> list[str]:
    """Return normalized CVE IDs from canonical and README prose forms."""
    cves = [f"CVE-{m.group(1)}-{m.group(2)}" for m in CVE_RE.finditer(line)]
    if re.search(r"\bCVEs?\b", line, re.IGNORECASE):
        for m in BARE_CVE_RE.finditer(line):
            prefix = line[max(0, m.start() - 10):m.start()].upper()
            if re.search(r"(?:CVE|GHSL)\s*[-–— ]\s*$", prefix, re.IGNORECASE):
                continue
            cves.append(f"CVE-{m.group(1)}-{m.group(2)}")
    return list(dict.fromkeys(cves))


def detect_delimiter(path: Path) -> str:
    """Detect a prediction file's delimiter from its header line only.

    Must not be re-detected per data row: a data row's free-text description
    can contain more literal commas than the row has real tab-delimiters
    (long descriptions routinely do), which would fool a per-line count into
    picking the wrong delimiter. The header has no prose in it, so counting
    there is reliable.
    """
    with path.open(encoding="utf-8", errors="replace") as f:
        header = f.readline()
    return "\t" if header.count("\t") >= header.count(",") else ","


def extract_row_cve(row: list[str]) -> str | None:
    """Return the CVE ID from this row's own ID field only.

    Prediction files are TSV/CSV rows where one field is the CVE ID and
    another is free-text description; that description can incidentally
    mention unrelated CVE IDs (e.g. "see also CVE-2020-6950"). Unlike
    extract_cves_from_line (used for README prose, where scanning the whole
    line is correct), this only accepts a field that IS a CVE ID on its own,
    so incidental mentions elsewhere in the row are ignored.
    """
    for field in row:
        m = CVE_RE.fullmatch((field or "").strip().strip('"'))
        if m:
            return f"CVE-{m.group(1)}-{m.group(2)}"
    return None


def rating_column_indices(header: list[str]) -> list[int]:
    return [i for i, h in enumerate(header) if h and h.strip().lower() in RATING_COLS]


def row_rating(row: list[str], rating_idx: list[int]) -> str | None:
    """Return this row's rating token, or None if it can't be determined.

    Checks the known rating column(s) first; if that comes up empty (a
    handful of rows in the April 2026 file have a broken multi-line
    description that isn't properly CSV-quoted, which throws off column
    alignment for that row specifically -- a source-data defect, not
    something safely auto-repairable here) falls back to scanning every
    field for a literal rating token.
    """
    for idx in rating_idx:
        if idx < len(row):
            v = row[idx].strip().lower()
            if v in RATING_VALUES:
                return v
    for v in row:
        vv = (v or "").strip().lower()
        if vv in RATING_VALUES:
            return vv
    return None


def extract_cves_from_text(text: str) -> list[str]:
    cves = []
    for line in text.splitlines():
        cves.extend(extract_cves_from_line(line))
    return cves


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
            for cve in extract_cves_from_line(line):
                cve_dates[cve] = current_date   # overwrite keeps earliest

    return cve_dates


def _api_error(e: Exception, context: str) -> RuntimeError:
    """Build a RuntimeError for a GitHub API failure, including rate-limit info when available.

    main() checks the resulting message for "remaining=0" to decide whether
    to stop fetching further files after the rate limit is exhausted, rather
    than let every remaining file fail the same way one at a time.
    """
    if isinstance(e, urllib.error.HTTPError):
        remaining = e.headers.get("X-RateLimit-Remaining", "unknown")
        reset = e.headers.get("X-RateLimit-Reset", "unknown")
        detail = e.read().decode("utf-8", errors="replace").strip()
        msg = f"GitHub API {e.code} for {context}; rate-limit remaining={remaining}, reset={reset}."
        if remaining == "0":
            msg += " Rate limit exhausted; retry after reset or pass a --github-token."
        else:
            msg += (
                " Unauthenticated GitHub API use is supported but limited; "
                "retry after reset, omit --github-dates, or optionally pass a token."
            )
        if detail:
            msg += f" response={detail}"
        return RuntimeError(msg)
    return RuntimeError(f"GitHub API error for {context}: {e}")


def _oldest_commit_for_path(repo: str, path: str, headers: dict, delay_seconds: float) -> dict | None:
    """Return the oldest commit touching path, per the GitHub commits API.

    Unlike `git log --follow`, this endpoint stops at the commit that
    introduced the file under this exact path -- it does not walk back
    through renames. Callers that need full history must chain this with
    _renamed_from() (see get_first_commit_date).
    """
    api_path = urllib.parse.quote(path.replace("\\", "/"), safe="/")
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
            raise _api_error(e, f"{path} (page {page})") from e
        except Exception as e:
            raise _api_error(e, path) from e

        if not batch:
            break

        oldest = batch[-1]
        if len(batch) < 100:
            break
        page += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)

    return oldest


def _renamed_from(repo: str, sha: str, path: str, headers: dict) -> str | None:
    """If commit sha renamed path from an older path, return that older path."""
    url = f"https://api.github.com/repos/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            detail = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise _api_error(e, f"commit {sha}") from e
    except Exception as e:
        raise _api_error(e, f"commit {sha}") from e

    norm_path = path.replace("\\", "/")
    for entry in detail.get("files", []):
        if entry.get("filename") == norm_path and entry.get("status") == "renamed":
            return entry.get("previous_filename")
    return None


def get_first_commit_date(repo: str, file_path: str, token: str = "", delay_seconds: float = 1.0) -> str | None:
    """Return the date of the first commit that touched file_path in repo.

    Follows renames back through history (like `git log --follow`): the
    GitHub commits?path= API stops at whichever commit introduced the file
    under its *current* path, so a plain query understates the true
    first-commit date whenever the file was renamed after creation.
    """
    headers = {"User-Agent": "cve-audit-script"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    current_path = file_path
    visited       = set()
    oldest        = None

    while current_path not in visited:
        visited.add(current_path)
        found = _oldest_commit_for_path(repo, current_path, headers, delay_seconds)
        if found is None:
            break
        oldest = found
        if delay_seconds > 0:
            time.sleep(delay_seconds)

        prev_path = _renamed_from(repo, oldest["sha"], current_path, headers)
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        if not prev_path or prev_path in visited:
            break
        current_path = prev_path

    if oldest:
        return oldest["commit"]["committer"]["date"][:10]
    return None


def search_file(path: Path, cve: str) -> str | None:
    """Return the first line in path containing cve, or None."""
    try:
        for line in path.open(encoding="utf-8", errors="replace"):
            if cve in line:
                return line.rstrip()
    except OSError as e:
        raise RuntimeError(f"Could not read prediction data file {path}: {e}") from e
    return None


def main():
    parser = argparse.ArgumentParser(description="CVE prediction audit")
    parser.add_argument("--data-root",     default="",
                        help="Directory containing 2024, 2025, and HEAD data folders; "
                             "defaults to the auditor folder's parent (ROOT_DIR)")
    parser.add_argument("--journal",       default="",
                        help="CVE source file; defaults to README.md beside the data folders")
    parser.add_argument("--out-csv",       default="")
    parser.add_argument("--out-txt",       default="")
    parser.add_argument("--github-dates",  action="store_true",
                        help="Fetch first-commit dates from GitHub API")
    parser.add_argument("--github-token",  default=os.environ.get("GITHUB_TOKEN", ""),
                        help="Optional GitHub token; defaults to GITHUB_TOKEN env var and only avoids unauthenticated rate limits")
    parser.add_argument("--github-repo",   default=GITHUB_REPO)
    parser.add_argument("--github-delay",  type=float, default=1.0,
                        help="Seconds to wait between GitHub API calls")
    args = parser.parse_args()

    data_root   = Path(args.data_root) if args.data_root else ROOT_DIR
    journal     = Path(args.journal) if args.journal else data_root / "README.md"
    out_csv     = Path(args.out_csv) if args.out_csv else BASE_DIR / "audit-results.csv"
    out_txt     = Path(args.out_txt) if args.out_txt else BASE_DIR / "audit-results.txt"

    files = [dict(f) for f in PREDICTION_FILES]   # shallow copy so we can mutate dates
    for f in files:
        f["estimated_date"] = f["date"]   # hardcoded estimate, kept only for ordering below
        f["date_status"]    = ""          # set below when --github-dates is used

    # Optionally fetch GitHub first-commit dates
    if args.github_dates:
        print(f"Fetching first-commit dates from github.com/{args.github_repo} ...")
        print(f"GitHub API delay: {args.github_delay} seconds")
        print(f"GitHub auth: {'token' if args.github_token else 'none'}")
        rate_limited = False
        api_errors   = []
        for f in files:
            if rate_limited:
                # Every further call would fail the same way -- don't burn time
                # re-proving that. Keep whatever we already fetched and mark the
                # rest unverified rather than losing all prior progress.
                f["date"] = ""
                f["date_status"] = "UNVERIFIED (skipped -- rate limit hit earlier this run)"
                continue
            try:
                date = get_first_commit_date(args.github_repo, f["path"], args.github_token, args.github_delay)
            except RuntimeError as e:
                print(f"  {f['path']} -> ERROR: {e}")
                f["date"] = ""
                f["date_status"] = f"UNVERIFIED (GitHub API error: {e})"
                api_errors.append(f["path"])
                if "remaining=0" in str(e):
                    rate_limited = True
                    print("  Rate limit exhausted -- keeping dates already fetched, "
                          "marking remaining files unverified, and finishing the report.")
                continue
            if date:
                f["date"] = date
                f["date_status"] = "verified"
                print(f"  {f['path']} -> {date}")
            else:
                # Not yet pushed to GitHub -- this script exists to show provable,
                # third-party-verifiable dates, so we do NOT fall back to the
                # hardcoded estimate here. Leave it unverified rather than crash.
                f["date"] = ""
                f["date_status"] = "NOT ON GITHUB YET (no provable first-commit date)"
                print(f"  {f['path']} -> NOT ON GITHUB YET (no provable first-commit date)")
            if args.github_delay > 0:
                time.sleep(args.github_delay)
        # Sort by the verified date when we have one; fall back to the hardcoded
        # estimate only to keep unverified files in a sensible position, never as
        # a stand-in for the (unproven) date itself.
        files.sort(key=lambda f: f["date"] or f["estimated_date"])
        if api_errors:
            print(f"\nWARNING: {len(api_errors)} file(s) could not be verified via the GitHub "
                  f"API this run (see ERROR lines above). They're marked UNVERIFIED in the "
                  f"report below -- rerun --github-dates later (after the rate limit resets, "
                  f"or with --github-token) to fill them in.")
        print()

    # Parse CVE source
    journal_text = journal.read_text(encoding="utf-8")
    cve_mentions = extract_cves_from_text(journal_text)
    cve_ids      = sorted(set(cve_mentions))
    journal_dates = get_journal_dates(journal)

    print(f"Source   : {journal}")
    print(f"Data root: {data_root}")
    print(f"CVEs     : {len(cve_mentions)} mentions, {len(cve_ids)} unique IDs extracted")
    print()

    for f in files:
        full = data_root / f["path"]
        if not full.is_file():
            raise SystemExit(f"ERROR: prediction data file not found: {full}")

    # Search prediction files once, in chronological order. Each CVE is
    # attributed to the first file where it has an ACTIONABLE rating
    # (warm/hot/fire/neutral) -- a cold or blank rating doesn't count as a
    # prediction, even though the CVE ID is technically present. We also
    # track the first appearance under any rating, so a CVE that's cold
    # everywhere is still reported (flagged, not silently dropped) rather
    # than vanishing from the audit.
    target = set(cve_ids)
    first_actionable = {}   # cve -> hit dict, used as the primary result
    first_any         = {}  # cve -> hit dict, fallback when never actionable

    for f in files:
        full = data_root / f["path"]
        delimiter = detect_delimiter(full)
        try:
            with full.open(encoding="utf-8", errors="replace", newline="") as fh:
                reader = csv.reader(fh, delimiter=delimiter)
                header = next(reader, None)
                if header is None:
                    continue
                rating_idx = rating_column_indices(header)
                implicit_actionable = not rating_idx  # e.g. reduction.txt
                for row in reader:
                    if not row:
                        continue
                    cve = extract_row_cve(row)
                    if not cve or cve not in target:
                        continue
                    line_text = delimiter.join(row)
                    rating = "n/a (no rating column)" if implicit_actionable else row_rating(row, rating_idx)

                    if cve not in first_any:
                        first_any[cve] = {
                            "CVE": cve, "Rating": rating or "unrated",
                            "Github Timestamp": f["date"], "Date Status": f["date_status"],
                            "RunLabel": f["label"], "File": f["path"], "Line": line_text,
                        }
                    if cve not in first_actionable:
                        is_actionable = implicit_actionable or (rating in ACTIONABLE_VALUES)
                        if is_actionable:
                            first_actionable[cve] = {
                                "CVE": cve, "Rating": rating or "unrated",
                                "Github Timestamp": f["date"], "Date Status": f["date_status"],
                                "RunLabel": f["label"], "File": f["path"], "Line": line_text,
                            }
        except OSError as e:
            raise SystemExit(f"ERROR: could not read prediction data file {full}: {e}") from e

    results = []
    not_found_cves = []
    never_actionable_cves = []
    predicted_after_kev_cves = []

    for cve in cve_ids:
        kev_date = journal_dates.get(cve, "")
        hit = first_actionable.get(cve)
        status = "OK"

        if hit is None:
            hit = first_any.get(cve)
            if hit is not None:
                status = "MISS (never rated non-cold in any tracked file)"
                never_actionable_cves.append(cve)

        if hit is None:
            results.append({
                "CVE": cve, "KEV Date": kev_date, "Rating": "",
                "Github Timestamp": "", "Date Status": "",
                "RunLabel": "NOT FOUND", "File": "", "Line": "", "Status": "NOT FOUND",
            })
            not_found_cves.append(cve)
            continue

        pred_date = hit["Github Timestamp"] or hit["Date Status"]
        if (
            status == "OK"
            and kev_date
            and pred_date
            and re.match(r"^\d{4}-\d{2}-\d{2}$", pred_date)
            and pred_date >= kev_date
        ):
            status = "MISS (rated non-cold only on/after the KEV date -- not a valid lead-time example)"
            predicted_after_kev_cves.append(cve)

        results.append({
            "CVE": cve, "KEV Date": kev_date, "Rating": hit["Rating"],
            "Github Timestamp": hit["Github Timestamp"], "Date Status": hit["Date Status"],
            "RunLabel": hit["RunLabel"], "File": hit["File"], "Line": hit["Line"],
            "Status": status,
        })

    not_found = len(not_found_cves)
    found = len(results) - not_found
    genuine_misses = len(never_actionable_cves) + len(predicted_after_kev_cves)

    print(f"Found: {found:,}  |  Not found: {not_found:,}  |  Flagged as non-predictions: {genuine_misses:,}")
    if not_found_cves:
        print("Not found:", file=sys.stderr)
        for cve in not_found_cves:
            print(f"  {cve}", file=sys.stderr)
    if never_actionable_cves:
        print(f"\nNever rated non-cold ({len(never_actionable_cves)}):", file=sys.stderr)
        for cve in never_actionable_cves:
            print(f"  {cve}", file=sys.stderr)
    if predicted_after_kev_cves:
        print(f"\nRated non-cold only after KEV date ({len(predicted_after_kev_cves)}):", file=sys.stderr)
        for cve in predicted_after_kev_cves:
            print(f"  {cve}", file=sys.stderr)

    # CSV output
    fieldnames = ["CVE", "KEV Date", "Rating", "Github Timestamp", "Date Status", "RunLabel", "File", "Line", "Status"]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\nCSV  -> {out_csv}")

    # Plain-text output
    sep        = "-" * 80
    date_source = (
        f"from GitHub commit history ({args.github_repo})"
        if args.github_dates
        else "hardcoded estimates (use --github-dates for authoritative dates)"
    )
    lines = [
        "CVE PREDICTION AUDIT REPORT",
        f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Source     : {journal}",
        f"Data root  : {data_root}",
        f"Dates      : {date_source}",
        f"Total CVEs : {len(results)}  |  Found: {found}  |  Not found: {not_found}  |  "
        f"Flagged as non-predictions: {genuine_misses}",
        sep,
    ]

    for r in results:
        lines.append("")
        lines.append(f"CVE              : {r['CVE']}")
        lines.append(f"KEV Date         : {r['KEV Date']}")
        if r["RunLabel"] == "NOT FOUND":
            lines.append("Github Timestamp : NOT FOUND in any prediction file")
        else:
            gh_ts = r["Github Timestamp"] or r["Date Status"] or "NOT ON GITHUB YET (no provable first-commit date)"
            lines.append(f"Github Timestamp : {gh_ts}  ({r['RunLabel']})")
            lines.append(f"Rating           : {r['Rating']}")
            lines.append(f"File             : {r['File']}")
            lines.append(f"Line             : {r['Line']}")
            if r["Status"] != "OK":
                lines.append(f"STATUS           : {r['Status']}")

    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Text -> {out_txt}")
    print(f"\nDone. {found} / {len(results)} CVEs matched to a prediction file "
          f"({genuine_misses} flagged as non-predictions, not valid lead-time examples).")


if __name__ == "__main__":
    main()
