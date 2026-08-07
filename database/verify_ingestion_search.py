import argparse
import csv
import pathlib
import re
import sqlite3
import sys
from collections import Counter


BASE_DIR = pathlib.Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
HEAD_DIR = ROOT_DIR / "HEAD"
DEFAULT_DB = BASE_DIR / "cve.db"

DEFAULT_SOURCES = {
    "2025": HEAD_DIR / "2025-processed-clean.txt",
    "2024": HEAD_DIR / "2024-output-may-24.txt",
    "2026": HEAD_DIR / "2026-august.txt",
}

DEFAULT_PRED_DATES = BASE_DIR / "pred_dates.csv"

PREDICTION_DATE_ARTIFACTS = [
    (ROOT_DIR / "2024" / "2024-predictions.txt", "2025-01-04"),
    (ROOT_DIR / "2024" / "predictions-jan-7-run.txt", "2025-01-07"),
    (ROOT_DIR / "2024" / "2024-predictions-jan-17-run.txt", "2025-01-17"),
    (ROOT_DIR / "2024" / "2024-output-may-24.txt", "2026-02-08"),
    (ROOT_DIR / "2025" / "jan-15-run.txt", "2025-01-15"),
    (ROOT_DIR / "2025" / "jan-17-run.txt", "2025-01-17"),
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


def load_prediction_dates(path=DEFAULT_PRED_DATES):
    dates = {}
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.DictReader(f):
            cve = get(row, "cve").upper()
            pred_date = get(row, "pred_date")
            if cve:
                dates[cve] = pred_date
    return dates


def write_prediction_dates(dates: dict, path=DEFAULT_PRED_DATES) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cve", "pred_date"])
        for cve, pred_date in sorted(dates.items()):
            writer.writerow([cve, pred_date])


def verify_prediction_date_coverage(source_paths=DEFAULT_SOURCES, pred_dates_path=DEFAULT_PRED_DATES):
    dates = load_prediction_dates(pred_dates_path)
    missing_by_year = {}
    for year, path in source_paths.items():
        missing = sorted(cve for cve in source_cves(year, path) if not dates.get(cve))
        missing_by_year[year] = missing
    return missing_by_year


def line_start_cves(path):
    cves = set()
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for line in f:
            match = LINE_START_CVE_RE.search(line.lstrip("\ufeff").strip())
            if match:
                cves.add(match.group(1).upper())
    return cves


def expected_prediction_dates_from_artifacts(artifacts=PREDICTION_DATE_ARTIFACTS):
    expected = {}
    for path, pred_date in artifacts:
        if not path.exists():
            raise FileNotFoundError(path)
        for cve in line_start_cves(path):
            if cve not in expected or pred_date < expected[cve]:
                expected[cve] = pred_date
    return expected


def generated_prediction_dates(
    source_paths=DEFAULT_SOURCES,
    artifacts=PREDICTION_DATE_ARTIFACTS,
):
    artifact_dates = expected_prediction_dates_from_artifacts(artifacts)
    dates = dict(artifact_dates)
    missing_without_fallback = {}
    for year, path in source_paths.items():
        missing = sorted(cve for cve in source_cves(year, path) if not dates.get(cve))
        if missing:
            missing_without_fallback[year] = missing
    return {
        "dates": dates,
        "artifact_count": len(artifact_dates),
        "missing_without_fallback": missing_without_fallback,
    }


def verify_prediction_date_accuracy(pred_dates_path=DEFAULT_PRED_DATES, artifacts=PREDICTION_DATE_ARTIFACTS):
    dates = load_prediction_dates(pred_dates_path)
    expected = expected_prediction_dates_from_artifacts(artifacts)
    mismatches = {
        cve: {"expected": expected_date, "actual": dates.get(cve, "")}
        for cve, expected_date in sorted(expected.items())
        if dates.get(cve, "") != expected_date
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


def verify_prediction_dates(con):
    total_dates = con.execute("SELECT COUNT(*) FROM pred_dates").fetchone()[0]
    joined_2026 = con.execute(
        "SELECT COUNT(*) FROM preds2026 p JOIN pred_dates pd ON pd.cve = p.cve"
    ).fetchone()[0]
    return {"total_dates": total_dates, "joined_2026": joined_2026}


def main():
    parser = argparse.ArgumentParser(description="Verify CAUSALITY source ingestion and exact-CVE search coverage.")
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument(
        "--generate-pred-dates",
        action="store_true",
        help=f"Generate prediction dates from PREDICTION_DATE_ARTIFACTS and write them to "
             f"--pred-dates (default: {DEFAULT_PRED_DATES}), then exit without touching --db.",
    )
    parser.add_argument("--pred-dates", type=pathlib.Path, default=DEFAULT_PRED_DATES)
    args = parser.parse_args()

    if args.generate_pred_dates:
        generated = generated_prediction_dates(source_paths=DEFAULT_SOURCES)
        write_prediction_dates(generated["dates"], args.pred_dates)
        print(f"wrote {len(generated['dates']):,} prediction dates -> {args.pred_dates}")
        if generated["missing_without_fallback"]:
            for year, missing in generated["missing_without_fallback"].items():
                print(f"  WARNING: {year}: {len(missing):,} CVE(s) with no artifact-derived date", file=sys.stderr)
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

    date_result = verify_prediction_dates(con)
    print(
        f"prediction dates: total={date_result['total_dates']:,}; "
        f"joined_2026={date_result['joined_2026']:,}"
    )
    if date_result["total_dates"] <= 0 or date_result["joined_2026"] <= 0:
        failures.append({"year": "prediction_dates", "missing": ["2026 pred_dates join"], "extra": []})

    con.close()

    for failure in failures:
        missing = failure.get("missing", [])
        if missing:
            print(f"ERROR: {failure['year']} missing examples: {', '.join(missing[:20])}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
