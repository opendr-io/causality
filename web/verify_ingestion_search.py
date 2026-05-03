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
DEFAULT_DB = ROOT_DIR / "var" / "causality" / "cve.db"

DEFAULT_SOURCES = {
    "2025": HEAD_DIR / "2025-processed-clean.txt",
    "2024": HEAD_DIR / "2024-output-may-24.txt",
    "2026": HEAD_DIR / "2026-april-1-for-sharing.txt",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
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
            first = parsed[0] + [""] * max(0, 11 - len(parsed[0]))
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
            first_cell = line.split("\t", 1)[0].strip()
            if CVE_RE.match(first_cell):
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
            cve = get(row, "cveID") or get(row, "cve")
            if cve.lower() == "cveid":
                continue
        elif year == "2026":
            cve = get(row, "cveid") or get(row, "cve") or get(row, "cveID")
            if not CVE_RE.match(cve):
                continue
        else:
            cve = get(row, "cve") or get(row, "cveID") or get(row, "cveid")
        if cve:
            counts[cve.upper()] += 1
    return counts


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
    SELECT '2025' AS year FROM cves WHERE cve = ?
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
    args = parser.parse_args()

    if not args.db.exists():
        print(f"ERROR: DB not found: {args.db}", file=sys.stderr)
        return 2

    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    checks = [
        ("2025", "cves", DEFAULT_SOURCES["2025"]),
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
