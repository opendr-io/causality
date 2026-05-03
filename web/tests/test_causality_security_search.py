import ast
import pathlib
import re
import shutil
import sqlite3
import sys
import types
import uuid
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
WEB_DIR = ROOT_DIR / "web"
CAUSALITY_PATH = WEB_DIR / "causality.py"


def local_tmp_dir():
    path = ROOT_DIR / "var" / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path


def load_causality_helpers(*names):
    source = CAUSALITY_PATH.read_text(encoding="utf-8")
    module = ast.parse(source)
    selected = []
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            selected.append(node)
    helper_module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(helper_module)
    ns = {
        "pathlib": pathlib,
        "_re": re,
        "sqlite3": sqlite3,
        "BASE_DIR": WEB_DIR,
        "_ALLOWED_DATA_ROOTS": (WEB_DIR, ROOT_DIR / "HEAD"),
    }
    exec(compile(helper_module, str(CAUSALITY_PATH), "exec"), ns)
    return types.SimpleNamespace(**{name: ns[name] for name in names})


def test_resolve_safe_path_allows_app_and_head_but_rejects_escape():
    helpers = load_causality_helpers("_resolve_safe_path")
    work_dir = local_tmp_dir()
    try:
        app_file = WEB_DIR / "prompt.txt"
        head_file = ROOT_DIR / "HEAD" / "2025-processed-clean.txt"
        outside_file = work_dir / "outside.txt"
        outside_file.write_text("x", encoding="utf-8")

        assert helpers._resolve_safe_path("prompt.txt") == str(app_file.resolve())
        assert helpers._resolve_safe_path("../HEAD/2025-processed-clean.txt") == str(head_file.resolve())
        try:
            helpers._resolve_safe_path(str(outside_file))
        except ValueError as exc:
            assert "outside the allowed directories" in str(exc)
        else:
            raise AssertionError("outside path was not rejected")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def test_logo_loader_ignores_svg_and_loads_raster():
    helpers = load_causality_helpers("_load_logo_bytes")
    work_dir = local_tmp_dir()
    try:
        svg = work_dir / "logo.svg"
        png = work_dir / "logo.png"
        svg.write_text("<svg><script>alert(1)</script></svg>", encoding="utf-8")
        png.write_bytes(b"\x89PNG\r\n\x1a\n")

        assert helpers._load_logo_bytes(str(svg), "sig") == (None, None)
        assert helpers._load_logo_bytes(str(png), "sig") == (b"\x89PNG\r\n\x1a\n", ".png")
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def test_prompt_write_is_fixed_to_default_prompt_path():
    source = CAUSALITY_PATH.read_text(encoding="utf-8")

    assert 'prompt_file = st.text_input("Prompt file"' not in source
    assert "_resolve_safe_path(prompt_file" not in source
    assert "prompt_path = DEFAULT_PROMPT_PATH" in source
    assert "pathlib.Path(prompt_path).write_text(edited_prompt" in source


def test_2026_prediction_date_is_rendered_in_header_and_copy_text():
    source = CAUSALITY_PATH.read_text(encoding="utf-8")

    assert "def _predicted_label" in source
    assert "def _predicted_value" in source
    assert "predicted_text = _predicted_value(r)" in source
    assert 'st.markdown(f"**Predicted:** {_md_escape(predicted_text)}")' in source
    assert 'lines.append(f"Predicted: {pred}")' in source


def test_missing_requested_cves_reports_only_absent_ids():
    helpers = load_causality_helpers("_missing_requested_cves")
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE cves (cve TEXT)")
    con.execute("CREATE TABLE preds2024 (cve TEXT)")
    con.execute("CREATE TABLE preds2026 (cve TEXT)")
    con.execute("INSERT INTO cves VALUES ('CVE-2025-0001')")
    con.execute("INSERT INTO preds2024 VALUES ('CVE-2024-0002')")
    con.execute("INSERT INTO preds2026 VALUES ('CVE-2026-0003')")

    missing = helpers._missing_requested_cves(
        con,
        ["CVE-2025-0001", "CVE-2024-0002", "CVE-2026-0003", "CVE-2099-9999", "CVE-2099-9999"],
    )

    assert missing == ["CVE-2099-9999"]
    con.close()


def test_search_smoke_exact_fts_vendor_and_product_filters():
    helpers = load_causality_helpers("_fts5_escape", "scope_query")
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        CREATE TABLE cves (
            id INTEGER PRIMARY KEY,
            cve TEXT NOT NULL,
            published TEXT,
            title TEXT,
            description TEXT,
            vendor TEXT,
            product TEXT,
            affected_versions TEXT,
            rating TEXT
        );
        CREATE VIRTUAL TABLE cve_fts USING fts5(
            title, description, vendor, product, affected_versions,
            content='cves', content_rowid='id',
            tokenize='porter unicode61',
            prefix='2 3'
        );
        """
    )
    rows = [
        ("CVE-2026-0001", "2026-01-01", "Remote code execution", "Apache widget RCE", "apache", "httpd", "", "fire"),
        ("CVE-2026-0002", "2026-01-02", "Local denial of service", "Other product", "other", "agent", "", "cold"),
    ]
    con.executemany(
        """
        INSERT INTO cves
        (cve, published, title, description, vendor, product, affected_versions, rating)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    con.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")

    exact = con.execute("SELECT cve FROM cves WHERE cve IN (?)", ("CVE-2026-0001",)).fetchall()
    assert [row["cve"] for row in exact] == ["CVE-2026-0001"]

    fts_query = helpers.scope_query('"remote code execution"', "vendor", "product")
    fts = con.execute(
        """
        SELECT c.cve
        FROM cve_fts f
        JOIN cves c ON c.id = f.rowid
        WHERE cve_fts MATCH ?
        """,
        (fts_query,),
    ).fetchall()
    assert [row["cve"] for row in fts] == ["CVE-2026-0001"]

    filtered = con.execute(
        """
        SELECT c.cve
        FROM cve_fts f
        JOIN cves c ON c.id = f.rowid
        WHERE cve_fts MATCH ? AND c.vendor LIKE ? AND c.product LIKE ?
        """,
        (helpers.scope_query("apache", "vendor", "product"), "apache%", "httpd%"),
    ).fetchall()
    assert [row["cve"] for row in filtered] == ["CVE-2026-0001"]

    hyphenated = helpers.scope_query("CVE-2026-0001", "vendor", "product")
    assert hyphenated == '"CVE-2026-0001"'
    con.close()
