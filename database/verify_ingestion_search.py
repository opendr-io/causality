import argparse
import csv
import pathlib
import re
import sqlite3
import sys
from collections import Counter

import pandas as pd


BASE_DIR = pathlib.Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
HEAD_DIR = ROOT_DIR / "HEAD"
DEFAULT_DB = BASE_DIR / "cve.db"

DEFAULT_SOURCES = {
    "2025": HEAD_DIR / "2025-processed-clean.txt",
    "2024": HEAD_DIR / "2024-output-may-24.txt",
    "2026": HEAD_DIR / "2026-august.txt",
}

DEFAULT_RATING_DATES = BASE_DIR / "rating_dates.csv"
DEFAULT_RATING_HISTORY = BASE_DIR / "rating_history.tsv"
DEFAULT_RATING_SUMMARY = BASE_DIR / "rating_summary.tsv"

RATING_DATE_ARTIFACTS = [
    (ROOT_DIR / "2024" / "2024-predictions.txt", "2025-01-04"),
    (ROOT_DIR / "2024" / "predictions-jan-7-run.txt", "2025-01-07"),
    (ROOT_DIR / "2024" / "2024-predictions-jan-17-run.txt", "2025-01-17"),
    (ROOT_DIR / "2024" / "2024-output-may-24.txt", "2026-02-08"),

    (ROOT_DIR / "2025" / "jan-15-run.txt", "2025-01-15"),
    (ROOT_DIR / "2025" / "jan-17-run.txt", "2025-01-18"),
    (ROOT_DIR / "2025" / "feb-15-run.txt", "2025-02-17"),
    (ROOT_DIR / "2025" / "may-8-run.txt", "2025-05-08"),
    (ROOT_DIR / "2025" / "August" / "august-2025-combined-ratings.txt", "2025-08-31"),
    (ROOT_DIR / "2025" / "November" / "december-2-ratings.txt", "2025-12-03"),
    (ROOT_DIR / "2025" / "2025-ratings-final.txt", "2026-03-21"),
    (ROOT_DIR / "HEAD" / "2025-processed-clean.txt", "2026-03-21"),

    (ROOT_DIR / "2026" / "2026-april-1-for-sharing.txt", "2026-04-25"),
    (ROOT_DIR / "2026" / "2026-june-1.txt", "2026-06-02"),
    (ROOT_DIR / "HEAD" / "2026-august.txt", "2026-08-07"),
]
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
LINE_START_CVE_RE = re.compile(r"^(?:\d+[,\t])?(CVE-\d{4}-\d+)(?=[,\t])", re.IGNORECASE)
RATING_VALUES = {"fire", "hot", "warm", "cold", "sunspot"}


def nz(value):
    if value is None:
        return ""
    value = str(value).strip()
    return "" if value.lower() in {"null", "none", "nan"} else value


def get(row, key):
    return nz(row.get(key))


def detect_delimiter(path):
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        sample = f.read(4096)
    return "," if sample.count(",") > sample.count("\t") else "\t"


def dict_rows(path, delimiter=None):
    delimiter = delimiter or detect_delimiter(path)
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        yield from csv.DictReader(f, delimiter=delimiter)


def clean_joined_text(parts):
    text = " ".join(nz(part).strip('"') for part in parts if nz(part))
    return re.sub(r"\s+", " ", text).strip()


def rating_from_fields(fields):
    for field in fields:
        value = nz(field).lower()
        if value in RATING_VALUES:
            return value
    return ""


def iter_2026_tsv_rows(path):
    """Mirror causality.py's 2026 split-line TSV repair closely enough for verification."""
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        next(f, None)
        group = []

        def emit(lines):
            if not lines:
                return None
            parsed = [next(csv.reader([line], delimiter="\t")) for line in lines if line.strip()]
            if not parsed:
                return None
            first = parsed[0]
            if len(first) > 1 and CVE_RE.match(nz(first[1])):
                first = first[1:]
            first = first + [""] * max(0, 11 - len(first))
            cve = nz(first[0]).upper()
            if not CVE_RE.match(cve):
                return None

            desc_parts = [first[3]]
            tail = first[4:] if any(nz(x) for x in first[4:]) else []
            for fields in parsed[1:]:
                if fields:
                    desc_parts.append(fields[0])
                rest = fields[1:]
                if any(nz(x) for x in rest):
                    tail = rest

            tail += [""] * max(0, 7 - len(tail))
            return {
                "cveid": cve,
                "published": nz(first[1]),
                "vulnerabilityname": nz(first[2]),
                "shortdescription": clean_joined_text(desc_parts),
                "vendorproject": nz(tail[0]),
                "product": nz(tail[1]),
                "rating": rating_from_fields(tail[4:]) or nz(tail[4]),
            }

        for line in f:
            fields = line.split("\t", 2)
            first_cell = fields[0].strip()
            second_cell = fields[1].strip() if len(fields) > 1 else ""
            if CVE_RE.match(first_cell) or CVE_RE.match(second_cell):
                row = emit(group)
                if row:
                    yield row
                group = [line]
            else:
                group.append(line)
        row = emit(group)
        if row:
            yield row


def source_cves(year, path):
    counts = Counter()
    if not path.exists():
        raise FileNotFoundError(path)

    if year == "2026" and detect_delimiter(path) == "\t":
        rows = iter_2026_tsv_rows(path)
    else:
        delimiter = "\t" if year == "2024" else detect_delimiter(path)
        rows = dict_rows(path, delimiter=delimiter)

    for row in rows:
        if year == "2024":
            cve = get(row, "cveid") or get(row, "cve")
        elif year == "2026":
            cve = get(row, "cveid") or get(row, "cve")
            if not CVE_RE.match(cve):
                continue
        else:
            cve = get(row, "cveid") or get(row, "cve")
        cve = cve.upper()
        if CVE_RE.match(cve):
            counts[cve] += 1
    return counts


def load_rating_dates(path=DEFAULT_RATING_DATES):
    dates = {}
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.DictReader(f):
            cve = get(row, "cve").upper()
            rating_date = get(row, "rating_date")
            rating = get(row, "rating")
            if cve:
                dates[cve] = {"rating_date": rating_date, "rating": rating}
    return dates


def write_rating_dates(dates: dict, path=DEFAULT_RATING_DATES) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cve", "rating_date", "rating"])
        for cve, info in sorted(dates.items()):
            writer.writerow([cve, info["rating_date"], info["rating"]])


def verify_rating_date_coverage(source_paths=DEFAULT_SOURCES, rating_dates_path=DEFAULT_RATING_DATES):
    dates = load_rating_dates(rating_dates_path)
    missing_by_year = {}
    for year, path in source_paths.items():
        missing = sorted(cve for cve in source_cves(year, path) if not dates.get(cve))
        missing_by_year[year] = missing
    return missing_by_year


def line_start_cve_ratings(path):
    """Yield (cve, rating) for rows whose own ID field is a CVE.

    Uses proper CSV/TSV row parsing (csv.reader), not naive per-physical-line
    splitting -- several source files have unquoted-looking but actually
    quoted multi-line description fields (embedded newlines inside a quoted
    cell), and naive line splitting would only see the row's first physical
    line, missing the rating field that follows the multi-line description.

    Only matches the CVE in its own leading ID field (row[0], or row[1] for
    formats with a leading row-number/index column), not incidental mentions
    elsewhere in the row (e.g. inside a description). rating is "" if the
    row has no recognizable rating field.
    """
    delimiter = detect_delimiter(path)
    hits = []
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        next(reader, None)  # header
        for row in reader:
            if not row:
                continue
            first = row[0].strip().strip('"').lstrip("﻿")
            if CVE_RE.match(first):
                cve = first.upper()
            elif len(row) > 1 and CVE_RE.match(row[1].strip().strip('"')):
                cve = row[1].strip().strip('"').upper()
            else:
                continue
            rating = ""
            for field in row:
                val = field.strip().strip('"').lower()
                if val in RATING_VALUES:
                    rating = val
                    break
            hits.append((cve, rating))
    return hits


def cve_rating_history(artifacts=RATING_DATE_ARTIFACTS):
    """Every (cve, rating, date, file) observation across all artifacts.

    One row per CVE per artifact it appears in -- the full rating history,
    not collapsed to a single value. Sorted by cve then date so each CVE's
    rows read in chronological order. Dump this to a file (e.g.
    history.to_csv("rating_history.tsv", sep="\t", index=False)) for manual
    audits.
    """
    rows = []
    for path, rating_date in artifacts:
        if not path.exists():
            raise FileNotFoundError(path)
        for cve, rating in line_start_cve_ratings(path):
            rows.append({"cve": cve, "rating": rating, "date": rating_date, "file": str(path.relative_to(ROOT_DIR))})
    history = pd.DataFrame(rows, columns=["cve", "rating", "date", "file"])
    history.sort_values(["cve", "date"], kind="stable", inplace=True)
    history.reset_index(drop=True, inplace=True)
    return history


def rating_date_summary(artifacts=RATING_DATE_ARTIFACTS):
    """Per-CVE summary built from cve_rating_history(): rating (most recent
    rating value) and rating_date, for every CVE -- none are excluded.

    If the most recent rating is non-cold, rating_date is the earliest date
    it was rated non-cold (the date of the prediction that held up). If the
    most recent rating is cold, rating_date is the date of that most recent
    (cold) rating instead -- the date it was last confirmed cold. Blank ("")
    ratings (row present but no recognizable rating field) don't count as
    non-cold for this purpose. downgraded_to_cold is True if it was non-cold
    at some point but its final rating is cold, letting you split "went
    cold" from "stayed hot/warm/fire" with a single boolean filter.
    """
    history = cve_rating_history(artifacts)

    last = history.groupby("cve", sort=False).last()
    rating = last["rating"].rename("rating")
    final_date = last["date"].rename("final_date")

    non_cold = history[~history["rating"].isin(["cold", ""])]
    first_non_cold_date = non_cold.groupby("cve", sort=False)["date"].min().rename("first_non_cold_date")

    summary = pd.concat([rating, final_date, first_non_cold_date], axis=1).reset_index()
    summary["downgraded_to_cold"] = summary["first_non_cold_date"].notna() & (summary["rating"] == "cold")
    summary["rating_date"] = summary["first_non_cold_date"].where(
        summary["rating"] != "cold", summary["final_date"]
    ).fillna("")
    return summary[["cve", "rating", "rating_date", "downgraded_to_cold"]]


def expected_rating_dates_from_artifacts(artifacts=RATING_DATE_ARTIFACTS):
    """Rating and date for every CVE seen in any dated artifact -- none are
    excluded.

    rating is the CVE's most recent rating. rating_date is the earliest
    date it was rated non-cold if its rating is non-cold (the date of the
    prediction that held up), or the date of its most recent (cold) rating
    if its rating is cold (the date it was last confirmed cold).
    """
    summary = rating_date_summary(artifacts)
    return {
        cve: {"rating_date": rating_date, "rating": rating}
        for cve, rating_date, rating in zip(summary["cve"], summary["rating_date"], summary["rating"])
        if rating_date
    }


def generated_rating_dates(
    source_paths=DEFAULT_SOURCES,
    artifacts=RATING_DATE_ARTIFACTS,
):
    """Rating and date for the database build, plus genuine data gaps.

    Every CVE seen in any RATING_DATE_ARTIFACTS file gets a rating and a
    rating_date -- none are excluded (see expected_rating_dates_from_artifacts).
    never_seen_in_artifacts lists CVEs that appear in a HEAD source file but
    were never rated in any artifact at all -- a genuine data gap.
    """
    summary = rating_date_summary(artifacts)
    dates = {
        cve: {"rating_date": rating_date, "rating": rating}
        for cve, rating_date, rating in zip(summary["cve"], summary["rating_date"], summary["rating"])
        if rating_date
    }
    seen_cves = set(summary["cve"])

    never_seen_in_artifacts = {}
    never_rated_in_artifacts = {}
    for year, path in source_paths.items():
        source_set = set(source_cves(year, path))
        never_seen = sorted(cve for cve in source_set if cve not in seen_cves)
        if never_seen:
            never_seen_in_artifacts[year] = never_seen
        never_rated = sorted(cve for cve in source_set if cve in seen_cves and cve not in dates)
        if never_rated:
            never_rated_in_artifacts[year] = never_rated
    return {
        "dates": dates,
        "artifact_count": len(dates),
        "never_seen_in_artifacts": never_seen_in_artifacts,
        "never_rated_in_artifacts": never_rated_in_artifacts,
    }


def verify_rating_date_accuracy(rating_dates_path=DEFAULT_RATING_DATES, artifacts=RATING_DATE_ARTIFACTS):
    dates = load_rating_dates(rating_dates_path)
    expected = expected_rating_dates_from_artifacts(artifacts)
    mismatches = {
        cve: {"expected": expected_info, "actual": dates.get(cve, {})}
        for cve, expected_info in sorted(expected.items())
        if dates.get(cve, {}) != expected_info
    }
    return {"checked": len(expected), "mismatches": mismatches}


def db_cves(con, table):
    return Counter(
        cve.upper()
        for (cve,) in con.execute(f"SELECT cve FROM {table}")
        if cve
    )


def verify_dataset(con, year, table, path):
    expected = source_cves(year, path)
    actual = db_cves(con, table)
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    row_count = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    expected_rows = sum(expected.values())
    return {
        "year": year,
        "table": table,
        "source": str(path),
        "expected_rows": expected_rows,
        "db_rows": row_count,
        "expected_unique": len(expected),
        "db_unique": len(actual),
        "missing": missing,
        "extra": extra,
    }


def exact_search_hits(con, cve):
    sql = """
    SELECT '2026' AS year FROM preds2026 WHERE cve = ?
    UNION ALL
    SELECT '2025' AS year FROM preds2025 WHERE cve = ?
    UNION ALL
    SELECT '2024' AS year FROM preds2024 WHERE cve = ?
    """
    return [row[0] for row in con.execute(sql, (cve, cve, cve)).fetchall()]


def verify_exact_search(con, expected_by_year):
    missing = []
    all_cves = sorted(
        cve
        for cve in set().union(*(set(cves) for cves in expected_by_year.values()))
        if CVE_RE.match(cve)
    )
    for cve in all_cves:
        hits = exact_search_hits(con, cve)
        if not hits:
            missing.append(cve)
    return {"checked": len(all_cves), "missing": missing}


def verify_rating_dates(con):
    total_dates = con.execute("SELECT COUNT(*) FROM rating_dates").fetchone()[0]
    joined_2026 = con.execute(
        "SELECT COUNT(*) FROM preds2026 p JOIN rating_dates pd ON pd.cve = p.cve"
    ).fetchone()[0]
    return {"total_dates": total_dates, "joined_2026": joined_2026}


def main():
    parser = argparse.ArgumentParser(description="Verify CAUSALITY source ingestion and exact-CVE search coverage.")
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument(
        "--generate-rating-dates",
        action="store_true",
        help=f"Generate rating dates from RATING_DATE_ARTIFACTS and write them to "
             f"--rating-dates (default: {DEFAULT_RATING_DATES}), then exit without touching --db.",
    )
    parser.add_argument("--rating-dates", type=pathlib.Path, default=DEFAULT_RATING_DATES)
    parser.add_argument(
        "--dump-rating-history",
        action="store_true",
        help="Write the full per-CVE rating history and per-CVE rating summary to "
             "--rating-history-out / --rating-summary-out (TSV), for manual audits, "
             "then exit without touching --db.",
    )
    parser.add_argument("--rating-history-out", type=pathlib.Path, default=DEFAULT_RATING_HISTORY)
    parser.add_argument("--rating-summary-out", type=pathlib.Path, default=DEFAULT_RATING_SUMMARY)
    args = parser.parse_args()

    if args.generate_rating_dates:
        generated = generated_rating_dates(source_paths=DEFAULT_SOURCES)
        write_rating_dates(generated["dates"], args.rating_dates)
        print(f"wrote {len(generated['dates']):,} rating dates -> {args.rating_dates}")
        if generated["never_seen_in_artifacts"]:
            for year, missing in generated["never_seen_in_artifacts"].items():
                print(f"  WARNING: {year}: {len(missing):,} CVE(s) never seen in any artifact", file=sys.stderr)
        if generated["never_rated_in_artifacts"]:
            for year, missing in generated["never_rated_in_artifacts"].items():
                print(f"  WARNING: {year}: {len(missing):,} CVE(s) seen but never rated: {', '.join(missing)}", file=sys.stderr)
        return 0

    if args.dump_rating_history:
        history = cve_rating_history()
        summary = rating_date_summary()
        history.to_csv(args.rating_history_out, sep="\t", index=False)
        summary.to_csv(args.rating_summary_out, sep="\t", index=False)
        print(f"wrote {len(history):,} rating history rows -> {args.rating_history_out}")
        print(f"wrote {len(summary):,} rating summary rows -> {args.rating_summary_out}")
        print(f"  downgraded_to_cold: {int(summary['downgraded_to_cold'].sum()):,}")
        return 0

    if not args.db.exists():
        print(f"ERROR: DB not found: {args.db}", file=sys.stderr)
        return 2

    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    checks = [
        ("2025", "preds2025", DEFAULT_SOURCES["2025"]),
        ("2024", "preds2024", DEFAULT_SOURCES["2024"]),
        ("2026", "preds2026", DEFAULT_SOURCES["2026"]),
    ]

    failures = []
    expected_by_year = {}
    for year, table, path in checks:
        result = verify_dataset(con, year, table, path)
        expected_by_year[year] = source_cves(year, path)
        print(
            f"{year}: rows source={result['expected_rows']:,} db={result['db_rows']:,}; "
            f"unique source={result['expected_unique']:,} db={result['db_unique']:,}; "
            f"missing={len(result['missing']):,}; extra={len(result['extra']):,}"
        )
        if result["missing"] or result["expected_rows"] != result["db_rows"]:
            failures.append(result)
            if args.fail_fast:
                break

    search_result = verify_exact_search(con, expected_by_year)
    print(f"exact search: checked={search_result['checked']:,}; missing={len(search_result['missing']):,}")
    if search_result["missing"]:
        failures.append({"year": "search", "missing": search_result["missing"], "extra": []})

    date_result = verify_rating_dates(con)
    print(
        f"rating dates: total={date_result['total_dates']:,}; "
        f"joined_2026={date_result['joined_2026']:,}"
    )
    if date_result["total_dates"] <= 0 or date_result["joined_2026"] <= 0:
        failures.append({"year": "rating_dates", "missing": ["2026 rating_dates join"], "extra": []})

    con.close()

    for failure in failures:
        missing = failure.get("missing", [])
        if missing:
            print(f"ERROR: {failure['year']} missing examples: {', '.join(missing[:20])}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
