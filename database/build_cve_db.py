import argparse
import csv
import hashlib
import pathlib
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Iterable, List, Tuple

import verify_ingestion_search as verify_ingestion


BASE_DIR = pathlib.Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DEFAULT_HEAD_DIR = "../HEAD"
DEFAULT_RATING_DATES = "rating_dates.csv"   # full-coverage snapshot written by verify_ingestion_search.py --generate-rating-dates
DEFAULT_AUDIT_PY = "../auditor/audit-results.csv"   # provable subset only (CVEs mentioned in the journal)
DEFAULT_DB = "cve.db"
BATCH_SIZE = 5000
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


@dataclass(frozen=True)
class SourceFile:
    year: str
    path: pathlib.Path
    delimiter: str
    row_number_key: str | None = None


def nz(value):
    if value is None:
        return ""
    value = str(value).strip()
    return "" if value.lower() in {"null", "none", "nan"} else value


def get(row, key):
    return nz(row.get(key))


def resolve_input_path(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    return path if path.is_absolute() else BASE_DIR / path


def sha256_file(path: pathlib.Path) -> str:
    if not path.exists() or not path.is_file():
        return "MISSING:" + str(path.resolve())
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_signature(paths: Iterable[pathlib.Path]) -> str:
    return "|".join(sha256_file(path) for path in paths)


def detect_delimiter(path: pathlib.Path) -> str:
    with path.open(encoding="utf-8", errors="ignore", newline="") as f:
        sample = f.read(4096)
    return "," if sample.count(",") > sample.count("\t") else "\t"


def normalized_fieldnames(fieldnames: Iterable[str] | None) -> List[str]:
    return [nz(name).lstrip("\ufeff") for name in (fieldnames or [])]


def source_sort_key(source: SourceFile) -> Tuple[str, str]:
    return source.year, source.path.name.lower()


def preview(value, limit: int = 160) -> str:
    text = nz(value).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def row_cve(row: dict) -> str:
    return get(row, "cveid") or get(row, "\ufeffcveid") or get(row, "cve") or get(row, "\ufeffcve")


def cve_year(cve: str) -> str:
    match = CVE_RE.match(cve)
    return cve[4:8] if match else ""


def normalize_indexed_2026_row(row: dict, row_number_key: str | None) -> dict:
    if row_number_key is not None:
        row = dict(row)
        row.pop(row_number_key, None)
    return row


def infer_source_file(path: pathlib.Path) -> Tuple[SourceFile | None, List[str]]:
    errors = []
    delimiter = detect_delimiter(path)
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        fields = normalized_fieldnames(reader.fieldnames)
        row_number_key = reader.fieldnames[0] if reader.fieldnames and not nz(reader.fieldnames[0]) else None
        first_cve = ""
        for row in reader:
            row = normalize_indexed_2026_row(row, row_number_key)
            first_cve = row_cve(row)
            if first_cve:
                break

    year = cve_year(first_cve)
    if not year:
        stem = path.name.lower()
        for candidate in ("2024", "2025", "2026"):
            if candidate in stem:
                year = candidate
                break

    if year not in {"2024", "2025", "2026"}:
        errors.append(
            f"HEAD {path}: could not infer supported CVE year from header={fields} first_cve={preview(first_cve)}"
        )
        return None, errors

    if not ({"cveid", "rating"} <= set(fields)):
        errors.append(f"HEAD {path}: missing required cveid/rating columns: {fields}")
    elif year != "2024" and "kev" not in fields:
        errors.append(f"HEAD {path}: inferred {year} but missing required kev column: {fields}")
    elif year == "2024" and not ({"vendorproject", "product", "shortdescription"} <= set(fields)):
        errors.append(f"HEAD {path}: inferred 2024 but header does not match 2024 prediction format: {fields}")
    elif year == "2025" and not ({"cveid", "published", "vulnerabilityname"} <= set(fields)):
        errors.append(f"HEAD {path}: inferred 2025 but header does not match 2025 CVE format: {fields}")
    elif year == "2026" and not ({"cveid", "published", "vulnerabilityname", "rating"} <= set(fields)):
        errors.append(f"HEAD {path}: inferred 2026 but header does not match 2026 CVE format: {fields}")

    return SourceFile(year=year, path=path, delimiter=delimiter, row_number_key=row_number_key), errors


def discover_head_sources(head_dir: pathlib.Path) -> Tuple[List[SourceFile], List[str]]:
    if not head_dir.exists() or not head_dir.is_dir():
        return [], [f"HEAD directory not found: {head_dir}"]
    sources = []
    errors = []
    for path in sorted((p for p in head_dir.iterdir() if p.is_file()), key=lambda p: p.name.lower()):
        source, source_errors = infer_source_file(path)
        errors.extend(source_errors)
        if source is not None:
            sources.append(source)
    if not sources:
        errors.append(f"HEAD {head_dir}: no supported source files found")
    return sorted(sources, key=source_sort_key), errors


def validate_rows(
    name: str,
    path: pathlib.Path,
    delimiter: str,
    row_number_key: str | None = None,
    require_rating: bool = True,
    require_kev: bool = False,
    require_rating_date: bool = False,
) -> List[str]:
    errors = []
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for record_number, row in enumerate(reader, start=2):
            row = normalize_indexed_2026_row(row, row_number_key)
            cve = row_cve(row)
            if row.get(None):
                errors.append(
                    f"{name} {path} record {record_number}: extra fields after header columns; "
                    f"cve={preview(cve)} extra={preview('; '.join(map(str, row[None])))}"
                )
            if not CVE_RE.match(cve):
                errors.append(
                    f"{name} {path} record {record_number}: invalid or blank cveid: {preview(cve)}"
                )
            if require_rating and not get(row, "rating"):
                errors.append(f"{name} {path} record {record_number}: missing rating for cveid={preview(cve)}")
            if require_kev and not get(row, "kev"):
                errors.append(f"{name} {path} record {record_number}: missing kev for cveid={preview(cve)}")
            if require_rating_date and not get(row, "rating_date"):
                errors.append(
                    f"{name} {path} record {record_number}: missing rating_date for cve={preview(cve)}"
                )
    return errors


def preflight_sources(sources: List[SourceFile], rating_dates_path: pathlib.Path) -> List[str]:
    errors = []
    for source in sources:
        errors.extend(
            validate_rows(
                source.year,
                source.path,
                source.delimiter,
                row_number_key=source.row_number_key,
                require_kev=source.year != "2024",
            )
        )
    errors.extend(validate_rows("rating_dates", rating_dates_path, ",", require_rating=True, require_rating_date=True))
    return errors


def validate_audit_py(path: pathlib.Path) -> List[str]:
    required = {"CVE", "Github Timestamp", "RunLabel", "File", "Line"}
    errors = []
    seen = set()
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        missing_fields = sorted(required - fields)
        if missing_fields:
            return [f"audit_py {path}: missing required columns: {missing_fields}"]
        for record_number, row in enumerate(reader, start=2):
            cve = get(row, "CVE").upper()
            if not CVE_RE.match(cve):
                errors.append(f"audit_py {path} record {record_number}: invalid CVE: {preview(cve)}")
            elif cve in seen:
                errors.append(f"audit_py {path} record {record_number}: duplicate CVE: {cve}")
            seen.add(cve)
            # Github Timestamp is allowed to be blank -- it means the file that CVE was
            # found in hasn't been pushed to GitHub yet, not a data error (see audit.py).
            for field in ("RunLabel", "File", "Line"):
                if not get(row, field):
                    errors.append(f"audit_py {path} record {record_number}: missing {field} for cve={preview(cve)}")
    return errors


def null_field_profile(source: SourceFile) -> Tuple[int, List[Tuple[str, int, float]]]:
    counts = {}
    rows = 0
    with source.path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=source.delimiter)
        fieldnames = normalized_fieldnames(reader.fieldnames)
        for field in fieldnames:
            if field:
                counts[field] = 0
        for row in reader:
            row = normalize_indexed_2026_row(row, source.row_number_key)
            rows += 1
            for raw_name in reader.fieldnames or []:
                field = nz(raw_name).lstrip("\ufeff")
                if not field:
                    continue
                if not get(row, raw_name):
                    counts[field] += 1
    profile = [
        (field, count, (count / rows * 100.0) if rows else 0.0)
        for field, count in counts.items()
    ]
    return rows, profile


def verify_rating_dates_before_insert(
    sources: List[SourceFile],
    rating_dates_path: pathlib.Path,
) -> Tuple[List[str], dict, dict]:
    errors = []
    generated = verify_ingestion.generated_rating_dates(
        source_paths={source.year: source.path for source in sources}
    )
    generated_dates = generated["dates"]
    never_seen_in_artifacts = generated["never_seen_in_artifacts"]
    never_rated_in_artifacts = generated["never_rated_in_artifacts"]
    stats = {
        "coverage_checked": 0,
        "generated": len(generated_dates),
        "artifact_generated": generated["artifact_count"],
        "csv_checked": 0,
        "cold_final": 0,
        "never_seen": 0,
        "never_rated": [],
        "csv_mismatches": 0,
    }

    for source in sources:
        source_counts = verify_ingestion.source_cves(source.year, source.path)
        stats["coverage_checked"] += len(source_counts)
        stats["cold_final"] += sum(
            1 for cve in source_counts
            if generated_dates.get(cve, {}).get("rating") == "cold"
        )
        never_seen = never_seen_in_artifacts.get(source.year, [])
        stats["never_seen"] += len(never_seen)
        for cve in never_seen:
            errors.append(
                f"rating dates artifacts: {cve} from {source.path} was never rated "
                f"in any RATING_DATE_ARTIFACTS file"
            )
        # seen in an artifact but with no recognizable rating at all -- a real
        # gap, but not fatal; just report the CVE ids.
        stats["never_rated"].extend(never_rated_in_artifacts.get(source.year, []))

    if rating_dates_path.exists():
        csv_dates = verify_ingestion.load_rating_dates(rating_dates_path)
        stats["csv_checked"] = len(generated_dates)
        mismatches = {
            cve: {"expected": info, "actual": csv_dates.get(cve, {})}
            for cve, info in sorted(generated_dates.items())
            if csv_dates.get(cve, {}) != info
        }
        stats["csv_mismatches"] = len(mismatches)
        for cve, mismatch in mismatches.items():
            errors.append(
                f"rating dates {rating_dates_path}: {cve} expected={mismatch['expected']} actual={mismatch['actual']}"
            )

    return errors, stats, generated_dates


def exec_schema(cur: sqlite3.Cursor) -> None:
    cur.executescript(
        """
        DROP TABLE IF EXISTS preds2025;
        DROP TABLE IF EXISTS preds2025_fts;
        DROP TABLE IF EXISTS cves2025;
        DROP TABLE IF EXISTS cves2025_fts;
        DROP TABLE IF EXISTS cves;
        DROP TABLE IF EXISTS cve_fts;

        DROP TABLE IF EXISTS preds2024;
        DROP TABLE IF EXISTS preds2024_fts;

        DROP TABLE IF EXISTS preds2026;
        DROP TABLE IF EXISTS preds2026_fts;

        DROP TABLE IF EXISTS rating_dates;
        DROP TABLE IF EXISTS audit_py;

        VACUUM;

        CREATE TABLE preds2025 (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,
          assigner TEXT,
          published TEXT,
          title TEXT,
          description TEXT,
          vendor TEXT,
          product TEXT,
          affected_versions TEXT,
          kev TEXT,
          rating TEXT
        );

        CREATE VIRTUAL TABLE preds2025_fts USING fts5(
          title, description, vendor, product, affected_versions,
          content='preds2025', content_rowid='id',
          tokenize='porter unicode61',
          prefix='2 3'
        );

        CREATE INDEX IF NOT EXISTS idx_preds2025_cve ON preds2025(cve);
        CREATE INDEX IF NOT EXISTS idx_preds2025_vendor ON preds2025(vendor);
        CREATE INDEX IF NOT EXISTS idx_preds2025_product ON preds2025(product);
        CREATE INDEX IF NOT EXISTS idx_preds2025_published ON preds2025(published);
        CREATE INDEX IF NOT EXISTS idx_preds2025_kev ON preds2025(kev);
        CREATE INDEX IF NOT EXISTS idx_preds2025_rating ON preds2025(rating);

        CREATE TABLE preds2024 (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,
          predicted_label TEXT,
          vendor TEXT,
          product TEXT,
          description TEXT
        );

        CREATE VIRTUAL TABLE preds2024_fts USING fts5(
          description, vendor, product,
          content='preds2024', content_rowid='id',
          tokenize='porter unicode61',
          prefix='2 3'
        );

        CREATE INDEX IF NOT EXISTS idx_p24_cve ON preds2024(cve);
        CREATE INDEX IF NOT EXISTS idx_p24_vendor ON preds2024(vendor);
        CREATE INDEX IF NOT EXISTS idx_p24_product ON preds2024(product);

        CREATE TABLE preds2026 (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,
          assigner TEXT,
          published TEXT,
          title TEXT,
          description TEXT,
          vendor TEXT,
          product TEXT,
          kev TEXT,
          rating TEXT
        );

        CREATE VIRTUAL TABLE preds2026_fts USING fts5(
          title, description, vendor, product,
          content='preds2026', content_rowid='id',
          tokenize='porter unicode61',
          prefix='2 3'
        );

        CREATE INDEX IF NOT EXISTS idx_p26_cve ON preds2026(cve);
        CREATE INDEX IF NOT EXISTS idx_p26_vendor ON preds2026(vendor);
        CREATE INDEX IF NOT EXISTS idx_p26_product ON preds2026(product);
        CREATE INDEX IF NOT EXISTS idx_p26_kev ON preds2026(kev);
        CREATE INDEX IF NOT EXISTS idx_p26_rating ON preds2026(rating);

        CREATE TABLE rating_dates (
          cve TEXT PRIMARY KEY,
          rating_date TEXT,
          rating TEXT
        );

        CREATE TABLE audit_py (
          cve TEXT PRIMARY KEY,
          kev_date TEXT,
          github_timestamp TEXT NOT NULL,
          run_label TEXT NOT NULL,
          source_file TEXT NOT NULL,
          source_line TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_py_cve ON audit_py(cve);
        """
    )


def insert_batches(
    cur: sqlite3.Cursor,
    sql: str,
    rows: Iterable[Tuple],
    batch_size: int = BATCH_SIZE,
) -> int:
    total = 0
    batch: List[Tuple] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= batch_size:
            cur.executemany(sql, batch)
            total += len(batch)
            batch.clear()
    if batch:
        cur.executemany(sql, batch)
        total += len(batch)
    return total


def iter_primary_rows(source: SourceFile):
    with source.path.open(newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f, delimiter=source.delimiter):
            cve = row_cve(row)
            if not CVE_RE.match(cve):
                raise ValueError(f"{source.path}: invalid 2025 CVE id: {preview(cve)}")
            if not get(row, "rating"):
                raise ValueError(f"{source.path}: missing 2025 rating for CVE id: {preview(cve)}")
            yield (
                cve,
                get(row, "assigner"),
                get(row, "published")[:10],
                get(row, "title") or get(row, "vulnerabilityName") or get(row, "vulnerabilityname"),
                get(row, "description") or get(row, "shortDescription") or get(row, "shortdescription"),
                get(row, "vendor") or get(row, "vendorProject") or get(row, "vendorproject"),
                get(row, "product"),
                get(row, "affected versions") or get(row, "affected_versions"),
                get(row, "kev"),
                get(row, "rating"),
            )


def iter_2024_rows(source: SourceFile):
    with source.path.open(newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f, delimiter=source.delimiter):
            cve = row_cve(row)
            if not CVE_RE.match(cve):
                raise ValueError(f"{source.path}: invalid 2024 CVE id: {preview(cve)}")
            rating = get(row, "rating")
            if not rating:
                raise ValueError(f"{source.path}: missing 2024 rating for CVE id: {preview(cve)}")
            yield (
                cve,
                rating,
                get(row, "vendorproject") or get(row, "vendor"),
                get(row, "product"),
                get(row, "shortdescription") or get(row, "description"),
            )


def iter_2026_rows(source: SourceFile):
    with source.path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=source.delimiter)
        for row in reader:
            row = normalize_indexed_2026_row(row, source.row_number_key)
            cve = row_cve(row)
            if not CVE_RE.match(cve):
                raise ValueError(f"{source.path}: invalid 2026 CVE id: {preview(cve)}")
            if not get(row, "rating"):
                raise ValueError(f"{source.path}: missing 2026 rating for CVE id: {preview(cve)}")
            published = get(row, "published")
            yield (
                cve,
                get(row, "assigner"),
                published[:10] if published else "",
                get(row, "vulnerabilityname") or get(row, "title"),
                get(row, "shortdescription") or get(row, "description"),
                get(row, "vendorproject") or get(row, "vendor"),
                get(row, "product"),
                get(row, "kev"),
                get(row, "rating"),
            )


def iter_rating_date_rows(path: pathlib.Path):
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            cve = row_cve(row)
            rating_date = get(row, "rating_date")
            rating = get(row, "rating")
            if not CVE_RE.match(cve):
                raise ValueError(f"{path}: invalid rating_dates CVE id: {preview(cve)}")
            if not rating_date:
                raise ValueError(f"{path}: missing rating_date for CVE id: {preview(cve)}")
            yield cve, rating_date, rating


def iter_generated_rating_date_rows(generated_dates: dict):
    for cve, info in sorted(generated_dates.items()):
        if not CVE_RE.match(cve):
            raise ValueError(f"generated rating dates: invalid CVE id: {preview(cve)}")
        if not info["rating_date"]:
            raise ValueError(f"generated rating dates: missing rating_date for CVE id: {preview(cve)}")
        yield cve, info["rating_date"], info["rating"]


def iter_audit_py_rows(path: pathlib.Path):
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            cve = get(row, "CVE").upper()
            if not CVE_RE.match(cve):
                raise ValueError(f"{path}: invalid audit_py CVE: {preview(cve)}")
            yield (
                cve,
                get(row, "KEV Date"),
                get(row, "Github Timestamp"),
                get(row, "RunLabel"),
                get(row, "File"),
                get(row, "Line"),
            )


def rows_for_year(sources: List[SourceFile], year: str):
    for source in sources:
        if source.year != year:
            continue
        if year == "2024":
            yield from iter_2024_rows(source)
        elif year == "2025":
            yield from iter_primary_rows(source)
        elif year == "2026":
            yield from iter_2026_rows(source)
        else:
            raise ValueError(f"unsupported source year: {year}")


def build_database(
    sources: List[SourceFile],
    generated_dates: dict,
    audit_py_path: pathlib.Path,
    db_path: pathlib.Path,
    force: bool = False,
) -> Tuple[bool, dict]:
    input_paths = [source.path for source in sources] + [path for path, _ in verify_ingestion.RATING_DATE_ARTIFACTS] + [audit_py_path]
    sig = source_signature(input_paths) + "|generated_rating_dates=" + str(len(generated_dates))
    sig_path = pathlib.Path(str(db_path) + ".sig")
    if not force and db_path.exists() and sig_path.exists() and sig_path.read_text() == sig:
        return False, count_tables(db_path)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA temp_store=MEMORY;")
    cur.execute("PRAGMA cache_size=-200000;")

    exec_schema(cur)

    counts = {}
    counts["preds2025"] = insert_batches(
        cur,
        """
        INSERT INTO preds2025
        (cve,assigner,published,title,description,vendor,product,affected_versions,kev,rating)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        rows_for_year(sources, "2025"),
    )
    cur.execute("INSERT INTO preds2025_fts(preds2025_fts) VALUES('rebuild');")

    counts["preds2024"] = insert_batches(
        cur,
        """
        INSERT INTO preds2024
        (cve,predicted_label,vendor,product,description)
        VALUES (?,?,?,?,?)
        """,
        rows_for_year(sources, "2024"),
    )
    cur.execute("INSERT INTO preds2024_fts(preds2024_fts) VALUES('rebuild');")

    counts["preds2026"] = insert_batches(
        cur,
        """
        INSERT INTO preds2026
        (cve,assigner,published,title,description,vendor,product,kev,rating)
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        rows_for_year(sources, "2026"),
    )
    cur.execute("INSERT INTO preds2026_fts(preds2026_fts) VALUES('rebuild');")

    counts["rating_dates"] = insert_batches(
        cur,
        "INSERT OR REPLACE INTO rating_dates (cve, rating_date, rating) VALUES (?,?,?)",
        iter_generated_rating_date_rows(generated_dates),
    )

    counts["audit_py"] = insert_batches(
        cur,
        """
        INSERT INTO audit_py
        (cve,kev_date,github_timestamp,run_label,source_file,source_line)
        VALUES (?,?,?,?,?,?)
        """,
        iter_audit_py_rows(audit_py_path),
    )

    con.commit()
    con.close()
    sig_path.write_text(sig, encoding="utf-8")
    return True, counts


def count_tables(db_path: pathlib.Path) -> dict:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return {
            "preds2025": con.execute("SELECT COUNT(*) FROM preds2025").fetchone()[0],
            "preds2024": con.execute("SELECT COUNT(*) FROM preds2024").fetchone()[0],
            "preds2026": con.execute("SELECT COUNT(*) FROM preds2026").fetchone()[0],
            "rating_dates": con.execute("SELECT COUNT(*) FROM rating_dates").fetchone()[0],
            "audit_py": con.execute("SELECT COUNT(*) FROM audit_py").fetchone()[0],
        }
    finally:
        con.close()


def database_null_field_profile(db_path: pathlib.Path) -> dict:
    tables = ("preds2025", "preds2024", "preds2026", "rating_dates", "audit_py")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        profiles = {}
        for table in tables:
            columns = [row[1] for row in con.execute(f"PRAGMA table_info({table})")]
            row_count = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            table_profile = []
            for column in columns:
                null_count = con.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {column} IS NULL OR TRIM(CAST({column} AS TEXT)) = ''"
                ).fetchone()[0]
                pct = (null_count / row_count * 100.0) if row_count else 0.0
                table_profile.append((column, null_count, pct))
            profiles[table] = {"rows": row_count, "fields": table_profile}
        return profiles
    finally:
        con.close()


def validate_database(db_path: pathlib.Path) -> dict:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        target = con.execute(
            """
            SELECT p.cve, p.rating, pd.rating_date
            FROM preds2026 p
            LEFT JOIN rating_dates pd ON pd.cve = p.cve
            WHERE p.cve = 'CVE-2026-9198'
            """
        ).fetchone()
        joined_2026 = con.execute(
            "SELECT COUNT(*) FROM preds2026 p JOIN rating_dates pd ON pd.cve = p.cve"
        ).fetchone()[0]
        audit_joined = con.execute(
            """
            SELECT COUNT(*)
            FROM audit_py a
            WHERE EXISTS (SELECT 1 FROM preds2025 p25 WHERE p25.cve = a.cve)
               OR EXISTS (SELECT 1 FROM preds2024 p24 WHERE p24.cve = a.cve)
               OR EXISTS (SELECT 1 FROM preds2026 p26 WHERE p26.cve = a.cve)
            """
        ).fetchone()[0]
        return {
            "integrity": integrity,
            "joined_2026": joined_2026,
            "audit_joined": audit_joined,
            "cve_2026_9198": target,
        }
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the CAUSALITY SQLite FTS database without Streamlit.")
    parser.add_argument("--head-dir", default=DEFAULT_HEAD_DIR, help="directory containing HEAD source files")
    parser.add_argument("--rating-dates", default=DEFAULT_RATING_DATES, help="CVE rating-date CSV path")
    parser.add_argument("--audit-py", default=DEFAULT_AUDIT_PY, help="Python auditor CSV path")
    parser.add_argument("--db", default=DEFAULT_DB, help="output SQLite database path")
    parser.add_argument("--force", action="store_true", help="rebuild even if source signatures match")
    parser.add_argument("--validate", action="store_true", help="run integrity and rating-date join checks")
    args = parser.parse_args()

    head_dir = resolve_input_path(args.head_dir)
    rating_dates_path = resolve_input_path(args.rating_dates)
    audit_py_path = resolve_input_path(args.audit_py)
    db_path = resolve_input_path(args.db)

    if not audit_py_path.exists():
        print(f"ERROR: source not found: {audit_py_path}")
        return 2

    sources, discovery_errors = discover_head_sources(head_dir)
    if discovery_errors:
        for error in discovery_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"ERROR: refusing to build database; {len(discovery_errors)} HEAD discovery error(s) found", file=sys.stderr)
        return 1

    source_errors = []
    for source in sources:
        source_errors.extend(
            validate_rows(
                source.year,
                source.path,
                source.delimiter,
                row_number_key=source.row_number_key,
                require_kev=source.year != "2024",
            )
        )
    if rating_dates_path.exists():
        source_errors.extend(validate_rows("rating_dates", rating_dates_path, ",", require_rating=True, require_rating_date=True))

    rating_date_errors, rating_date_stats, generated_dates = verify_rating_dates_before_insert(sources, rating_dates_path)
    print(
        "rating-date verification: "
        f"coverage_checked={rating_date_stats['coverage_checked']:,}; "
        f"artifact_generated={rating_date_stats['artifact_generated']:,}; "
        f"generated={rating_date_stats['generated']:,}; "
        f"cold_final={rating_date_stats['cold_final']:,}; "
        f"never_seen={rating_date_stats['never_seen']:,}; "
        f"never_rated={len(rating_date_stats['never_rated']):,}; "
        f"csv_checked={rating_date_stats['csv_checked']:,}; "
        f"csv_mismatches={rating_date_stats['csv_mismatches']:,}"
    )
    if rating_date_stats["never_rated"]:
        print(
            f"WARNING: {len(rating_date_stats['never_rated']):,} CVE(s) seen in an artifact but never rated "
            f"(no rating_date entry): {', '.join(rating_date_stats['never_rated'])}",
            file=sys.stderr,
        )
    if rating_date_errors:
        for error in rating_date_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"ERROR: refusing to build database; {len(rating_date_errors)} rating-date error(s) found",
            file=sys.stderr,
        )
    if source_errors:
        for error in source_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"ERROR: refusing to build database; {len(source_errors)} source error(s) found", file=sys.stderr)
    if source_errors or rating_date_errors:
        return 1

    audit_errors = validate_audit_py(audit_py_path)
    if audit_errors:
        for error in audit_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"ERROR: refusing to build database; {len(audit_errors)} audit_py error(s) found", file=sys.stderr)
        return 1

    rebuilt, counts = build_database(
        sources,
        generated_dates,
        audit_py_path,
        db_path,
        force=args.force,
    )
    action = "rebuilt" if rebuilt else "up to date"
    print(f"database {action}: {db_path}")
    print(
        "rows: "
        f"2025={counts['preds2025']:,}; "
        f"2024={counts['preds2024']:,}; "
        f"2026={counts['preds2026']:,}; "
        f"rating_dates={counts['rating_dates']:,}; "
        f"audit_py={counts['audit_py']:,}"
    )
    print("database null fields:")
    for table, profile in database_null_field_profile(db_path).items():
        print(f"  {table}: rows={profile['rows']:,}")
        for field, count, pct in profile["fields"]:
            print(f"    {field}: {count:,} ({pct:.2f}%)")

    if args.validate:
        result = validate_database(db_path)
        target = result["cve_2026_9198"]
        print(f"integrity: {result['integrity']}")
        print(f"rating-date joins for 2026: {result['joined_2026']:,}")
        print(f"audit_py CVEs joined to CVE tables: {result['audit_joined']:,}")
        if target:
            print(f"CVE-2026-9198: rating={target[1]} rating_date={target[2]}")
        else:
            print("CVE-2026-9198: not found")
        return 0 if result["integrity"] == "ok" else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
