import sqlite3
import sys
import shutil
import uuid
from pathlib import Path


WEB_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = WEB_DIR.parent
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

import verify_ingestion_search as verify  # noqa: E402


def local_tmp_dir():
    path = ROOT_DIR / "var" / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path


def test_2026_tsv_parser_repairs_multiline_records():
    work_dir = local_tmp_dir()
    try:
        path = work_dir / "2026-fixture.txt"
        path.write_text(
            "cveid\tpublished\tvulnerabilityname\tshortdescription\tvendorproject\tproduct\tunused1\tunused2\tunused3\trating\n"
            "CVE-2026-0001\t2026-01-01\tNormal vuln\tShort desc\tVendorA\tProductA\t\t\t\tfire\n"
            "CVE-2026-0002\t2026-01-02\tWrapped vuln\tFirst line of desc\n"
            "second line of desc\tVendorB\tProductB\t\t\t\twarm\n",
            encoding="utf-8",
        )

        rows = list(verify.iter_2026_tsv_rows(path))

        assert [row["cveid"] for row in rows] == ["CVE-2026-0001", "CVE-2026-0002"]
        assert rows[0]["rating"] == "fire"
        assert rows[1]["shortdescription"] == "First line of desc second line of desc"
        assert rows[1]["vendorproject"] == "VendorB"
        assert rows[1]["product"] == "ProductB"
        assert rows[1]["rating"] == "warm"
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def test_verify_exact_search_checks_only_cve_formatted_ids():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE preds2026 (cve TEXT)")
    con.execute("CREATE TABLE cves (cve TEXT)")
    con.execute("CREATE TABLE preds2024 (cve TEXT)")
    con.execute("INSERT INTO preds2026 VALUES ('CVE-2026-0001')")
    con.execute("INSERT INTO cves VALUES ('CVE-2025-0002')")
    con.execute("INSERT INTO preds2024 VALUES ('CVE-2024-0003')")

    result = verify.verify_exact_search(
        con,
        {
            "2026": {"CVE-2026-0001": 1, "NOT-A-CVE": 1},
            "2025": {"CVE-2025-0002": 1},
            "2024": {"CVE-2024-0003": 1, "HTTPS://EXAMPLE.COM/ADVISORY": 1},
        },
    )

    assert result == {"checked": 3, "missing": []}
    con.close()


def test_verify_prediction_dates_requires_2026_join():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE preds2026 (cve TEXT)")
    con.execute("CREATE TABLE pred_dates (cve TEXT, pred_date TEXT)")
    con.execute("INSERT INTO preds2026 VALUES ('CVE-2026-0001')")
    con.execute("INSERT INTO pred_dates VALUES ('CVE-2026-0001', '2026-03-11')")

    assert verify.verify_prediction_dates(con) == {"total_dates": 1, "joined_2026": 1}
    con.close()
