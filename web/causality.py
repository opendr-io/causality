# streamlit_app.py — Dual-source CVE search (SQLite FTS5), RAM-served
# Search inputs live in the LEFT SIDEBAR; results render in the main page.
# No auto-results until a query; fixed logo from file; no pagination; show all fields.
#
# Primary TSV (cves.tsv) headers (nulls allowed):
#   cve, assigner, published, title, description, vendor, product, "affected versions", rating
#
# Secondary TSV (2024.tsv) headers (nulls allowed):
#   cveID, Predicted_Label, vendorProject, product, description

import csv
import hashlib
import pathlib
import sqlite3
from typing import List, Tuple
import urllib.parse
import streamlit as st

# -------- Config --------env
DEFAULT_TSV_PRIMARY  = "2025.tsv"   # primary dataset
DEFAULT_TSV_PRED2024 = "2024.tsv"   # secondary dataset
DB_PATH = "cve.db"                  # on-disk cache (rebuilt only if sources change)
RESULT_LIMIT_PRIMARY  = 100         # top-N to display from primary
RESULT_LIMIT_PRED2024 = 100         # top-N to display from 2024
DEFAULT_LOGO = "logo.png"           # fixed logo path (PNG/JPG/WEBP/SVG)

st.set_page_config(page_title="CVE Search", layout="wide")

# -------- Utilities --------
def _nz(x):
    if x is None:
        return ""
    x = str(x).strip()
    return "" if x.lower() in {"null", "none", "nan"} else x

def _get(row, k):
    return _nz(row.get(k))

def _sha256_file(path: str) -> str:
    p = pathlib.Path(path)
    if not p.exists() or not p.is_file():
        return "MISSING:" + str(p.resolve())
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

@st.cache_resource(show_spinner=False)
def _load_logo_bytes(path: str):
    p = pathlib.Path(path)
    if not p.exists() or not p.is_file():
        return None, None
    data = p.read_bytes()
    return data, p.suffix.lower()

def _render_logo(logo_bytes: bytes, ext: str):
    if not logo_bytes:
        return
    if ext == ".svg":
        svg_text = logo_bytes.decode("utf-8", errors="ignore")
        data_uri = "data:image/svg+xml;charset=utf-8," + urllib.parse.quote(svg_text)
        st.markdown(f"<img src='{data_uri}' alt='logo' style='height:64px;'>", unsafe_allow_html=True)
    else:
        st.image(logo_bytes, caption=None, use_container_width=False)

# -------- Build/refresh on-disk DB if any TSV changed --------
@st.cache_resource(show_spinner=False)
def build_or_open_disk(tsv_primary: str, tsv_pred2024: str, db_path: str) -> str:
    # Combined signature: either file change triggers rebuild
    sig = _sha256_file(tsv_primary) + "|" + _sha256_file(tsv_pred2024)
    sig_file = pathlib.Path(db_path + ".sig")
    need_build = True
    if pathlib.Path(db_path).exists() and sig_file.exists():
        need_build = (sig_file.read_text() != sig)

    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA temp_store=MEMORY;")
    cur.execute("PRAGMA cache_size=-200000;")

    if need_build:
        cur.executescript("""
        DROP TABLE IF EXISTS cves;
        DROP TABLE IF EXISTS cve_fts;

        DROP TABLE IF EXISTS preds2024;
        DROP TABLE IF EXISTS preds2024_fts;

        VACUUM;

        -- Primary dataset
        CREATE TABLE cves (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,
          assigner TEXT,
          published TEXT,               -- YYYY-MM-DD if present
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

        CREATE INDEX IF NOT EXISTS idx_cves_cve        ON cves(cve);
        CREATE INDEX IF NOT EXISTS idx_cves_vendor     ON cves(vendor);
        CREATE INDEX IF NOT EXISTS idx_cves_product    ON cves(product);
        CREATE INDEX IF NOT EXISTS idx_cves_published  ON cves(published);
        CREATE INDEX IF NOT EXISTS idx_cves_rating     ON cves(rating);

        -- Secondary dataset (2024.tsv)
        CREATE TABLE preds2024 (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,              -- from cveID
          predicted_label TEXT,           -- from Predicted_Label
          vendor TEXT,                    -- from vendorProject
          product TEXT,
          description TEXT
        );

        CREATE VIRTUAL TABLE preds2024_fts USING fts5(
          description, vendor, product,
          content='preds2024', content_rowid='id',
          tokenize='porter unicode61',
          prefix='2 3'
        );

        CREATE INDEX IF NOT EXISTS idx_p24_cve     ON preds2024(cve);
        CREATE INDEX IF NOT EXISTS idx_p24_vendor  ON preds2024(vendor);
        CREATE INDEX IF NOT EXISTS idx_p24_product ON preds2024(product);
        """)

        # Load primary TSV
        p = pathlib.Path(tsv_primary)
        if p.exists() and p.is_file():
            with open(tsv_primary, newline="", encoding="utf-8", errors="ignore") as f:
                rdr = csv.DictReader(f, delimiter="\t")
                batch: List[Tuple] = []
                for r in rdr:
                    batch.append((
                        _get(r, "cve"),
                        _get(r, "assigner"),
                        _get(r, "published")[:10],
                        _get(r, "title"),
                        _get(r, "description"),
                        _get(r, "vendor"),
                        _get(r, "product"),
                        (_get(r, "affected versions") or _get(r, "affected_versions")),
                        _get(r, "rating"),
                    ))
                    if len(batch) >= 5000:
                        cur.executemany(
                            """INSERT INTO cves
                               (cve,assigner,published,title,description,vendor,product,affected_versions,rating)
                               VALUES (?,?,?,?,?,?,?,?,?)""",
                            batch
                        )
                        batch.clear()
                if batch:
                    cur.executemany(
                        """INSERT INTO cves
                           (cve,assigner,published,title,description,vendor,product,affected_versions,rating)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        batch
                    )
            cur.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild');")

        # Load 2024 TSV
        p2 = pathlib.Path(tsv_pred2024)
        if p2.exists() and p2.is_file():
            with open(tsv_pred2024, newline="", encoding="utf-8", errors="ignore") as f:
                rdr = csv.DictReader(f, delimiter="\t")
                batch2: List[Tuple] = []
                for r in rdr:
                    batch2.append((
                        _get(r, "cveID"),
                        _get(r, "Predicted_Label"),
                        _get(r, "vendorProject"),
                        _get(r, "product"),
                        _get(r, "description"),
                    ))
                    if len(batch2) >= 5000:
                        cur.executemany(
                            """INSERT INTO preds2024
                               (cve,predicted_label,vendor,product,description)
                               VALUES (?,?,?,?,?)""",
                            batch2
                        )
                        batch2.clear()
                if batch2:
                    cur.executemany(
                        """INSERT INTO preds2024
                           (cve,predicted_label,vendor,product,description)
                           VALUES (?,?,?,?,?)""",
                        batch2
                    )
            cur.execute("INSERT INTO preds2024_fts(preds2024_fts) VALUES('rebuild');")

        con.commit()
        sig_file.write_text(sig)

    con.close()
    return db_path

# -------- Serve entirely from RAM --------
@st.cache_resource(show_spinner=False)
def serve_from_memory(db_path: str) -> sqlite3.Connection:
    disk = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    disk.row_factory = sqlite3.Row
    mem = sqlite3.connect(":memory:", check_same_thread=False)
    mem.row_factory = sqlite3.Row
    disk.backup(mem)  # copy entire DB to RAM
    disk.close()

    mem.execute("PRAGMA temp_store=MEMORY;")
    mem.execute("PRAGMA cache_size=-400000;")
    return mem

# -------- Header (fixed logo + title + description) --------
logo_bytes, logo_ext = _load_logo_bytes(DEFAULT_LOGO)
if logo_bytes:
    _render_logo(logo_bytes, logo_ext)
st.title("🔎 CVE Rating Search")
st.caption("Ratings are available for 2024 and January - August 2025. The RAM-backed SQLite FTS5 will take a few moments to load. Enter a query to begin. A null result means a CVE has not been rated hot or warm.")

# -------- Sidebar: paths, maintenance, and SEARCH INPUTS --------
with st.sidebar:
    st.subheader("Data sources")
    tsv_primary  = st.text_input("Primary TSV path", value=DEFAULT_TSV_PRIMARY)
    tsv_pred2024 = st.text_input("2024 TSV path", value=DEFAULT_TSV_PRED2024)

    col1, col2 = st.columns(2)
    with col1:
        force_rebuild = st.button("Force rebuild index")
    with col2:
        explain = st.checkbox("Explain query plan", value=False)

    st.markdown("---")
    st.subheader("Search")
    q = st.text_input(
        "Full-text query",
        #placeholder='log4j*  |  "remote code execution"  |  vendor: apache  product: httpd'
    )
    exact_cve = st.text_input("Exact CVE (use UPPERCASE)" )
    vendor = st.text_input("Vendor (prefix)", "")
    product = st.text_input("Product (prefix)", "")

if force_rebuild:
    try:
        pathlib.Path(DB_PATH).unlink(missing_ok=True)
        pathlib.Path(DB_PATH + ".sig").unlink(missing_ok=True)
        st.toast("Index will rebuild and be reloaded into RAM.", icon="⚡")
        build_or_open_disk.clear()
        serve_from_memory.clear()
        _load_logo_bytes.clear()
    except Exception as e:
        st.warning(f"Could not delete DB: {e}")

disk_db_path = build_or_open_disk(tsv_primary, tsv_pred2024, DB_PATH)
con = serve_from_memory(disk_db_path)

# -------- Don't run a search until there's some input --------
has_input = any(s.strip() for s in (q, exact_cve, vendor, product))
if not has_input:
    st.info("Enter a query (full-text, exact CVE, vendor, or product) in the left sidebar to see results.")
    st.stop()

# -------- Filter builders (prefix-only for speed) --------
def build_filters_primary():
    where, params = [], []
    if exact_cve.strip():
        where.append("c.cve = ?")
        params.append(exact_cve.strip())
    if vendor.strip():
        where.append("c.vendor LIKE ?")
        params.append(vendor.strip() + "%")
    if product.strip():
        where.append("c.product LIKE ?")
        params.append(product.strip() + "%")
    return where, params

def build_filters_p2024():
    where, params = [], []
    if exact_cve.strip():
        where.append("p.cve = ?")
        params.append(exact_cve.strip())
    if vendor.strip():
        where.append("p.vendor LIKE ?")
        params.append(vendor.strip() + "%")
    if product.strip():
        where.append("p.product LIKE ?")
        params.append(product.strip() + "%")
    return where, params

where_c, params_c = build_filters_primary()
where_p, params_p = build_filters_p2024()

# -------- Two-phase FTS for each dataset (no pagination) --------
def scope_query(qs: str, vendor_key: str, product_key: str):
    return (qs.replace("vendor:", f"{vendor_key} ")
              .replace("product:", f"{product_key} "))

HIT_CAP_PRIMARY  = max(RESULT_LIMIT_PRIMARY  * 5, 500)
HIT_CAP_PRED2024 = max(RESULT_LIMIT_PRED2024 * 5, 500)

# --- Primary
fts_params_c = []
if q.strip():
    fts_params_c = [scope_query(q, "vendor", "product")]

if fts_params_c:
    where_sql_c = ("WHERE " + " AND ".join(where_c)) if where_c else ""
    count_sql_c = f"""
    WITH hits AS (
      SELECT rowid, bm25(cve_fts) AS rank
      FROM cve_fts
      WHERE cve_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRIMARY}
    )
    SELECT COUNT(*) FROM hits
    """
    search_sql_c = f"""
    WITH hits AS (
      SELECT rowid, bm25(cve_fts) AS rank
      FROM cve_fts
      WHERE cve_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRIMARY}
    )
    SELECT h.rank, c.*
    FROM hits h
    JOIN cves c ON c.id = h.rowid
    {where_sql_c}
    ORDER BY h.rank, c.published DESC, c.cve
    LIMIT {RESULT_LIMIT_PRIMARY}
    """
    count_params_c = fts_params_c
    search_params_c = fts_params_c + params_c
else:
    where_sql_c = ("WHERE " + " AND ".join(where_c)) if where_c else ""
    count_sql_c = f"SELECT COUNT(*) FROM cves c {where_sql_c}"
    search_sql_c = f"""
    SELECT c.*
    FROM cves c
    {where_sql_c}
    ORDER BY c.published DESC, c.cve
    LIMIT {RESULT_LIMIT_PRIMARY}
    """
    count_params_c = params_c
    search_params_c = params_c

# --- 2024 predictions
fts_params_p = []
if q.strip():
    fts_params_p = [scope_query(q, "vendor", "product")]  # same keys in preds2024_fts

if fts_params_p:
    where_sql_p = ("WHERE " + " AND ".join(where_p)) if where_p else ""
    count_sql_p = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2024_fts) AS rank
      FROM preds2024_fts
      WHERE preds2024_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRED2024}
    )
    SELECT COUNT(*) FROM hits
    """
    search_sql_p = f"""
    WITH hits AS (
      SELECT rowid, bm5(preds2024_fts) AS rank
      FROM preds2024_fts
      WHERE preds2024_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRED2024}
    )
    SELECT h.rank, p.*
    FROM hits h
    JOIN preds2024 p ON p.id = h.rowid
    {where_sql_p}
    ORDER BY h.rank, p.cve
    LIMIT {RESULT_LIMIT_PRED2024}
    """
    # NOTE: bm5 -> typo? Replace with bm25 in final version
    # Fixing the typo:
    search_sql_p = search_sql_p.replace("bm5(", "bm25(")

    count_params_p = fts_params_p
    search_params_p = fts_params_p + params_p
else:
    where_sql_p = ("WHERE " + " AND ".join(where_p)) if where_p else ""
    count_sql_p = f"SELECT COUNT(*) FROM preds2024 p {where_sql_p}"
    search_sql_p = f"""
    SELECT p.*
    FROM preds2024 p
    {where_sql_p}
    ORDER BY p.cve
    LIMIT {RESULT_LIMIT_PRED2024}
    """
    count_params_p = params_p
    search_params_p = params_p

# Optional: EXPLAIN plans
if explain:
    for label, sql, params in [
        ("PRIMARY count", count_sql_c, count_params_c),
        ("PRIMARY search", search_sql_c, search_params_c),
        ("PRED2024 count", count_sql_p, count_params_p),
        ("PRED2024 search", search_sql_p, search_params_p),
    ]:
        st.subheader(label)
        st.code(sql.strip())
        st.write("params:", params)
        plan = con.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
        st.write(plan)

# -------- Execute --------
total_c = con.execute(count_sql_c, count_params_c).fetchone()[0]
rows_c  = con.execute(search_sql_c,  search_params_c).fetchall()

total_p = con.execute(count_sql_p, count_params_p).fetchone()[0]
rows_p  = con.execute(search_sql_p,  search_params_p).fetchall()

# -------- Render helpers --------
def show_field(label: str, val: str):
    v = (val or "").strip()
    st.markdown(f"**{label}:** {v if v else '—'}")

# -------- Render: Primary section --------
st.write(f"### 2025 Ratings — showing {min(total_c, RESULT_LIMIT_PRIMARY):,} of {total_c:,} results")
for r in rows_c:
    with st.container(border=True):
        sev = (r["rating"] or "UNKNOWN").upper()
        pub = r["published"] or "—"
        st.markdown(f"**{r['cve']}**  —  {sev} • {pub}")
        if r["title"]:
            st.markdown(f"_{r['title'].strip()}_")
        cols = st.columns(2)
        with cols[0]:
            show_field("Vendor", r["vendor"])
            show_field("Product", r["product"])
            show_field("Affected Versions", r["affected_versions"])
            show_field("Assigner", r["assigner"])
        with cols[1]:
            show_field("Published", r["published"])
            show_field("Rating", r["rating"])
        st.markdown("**Description:**")
        st.write((r["description"] or "").strip() or "—")

st.divider()

# -------- Render: 2024 predictions section --------
st.write(f"### 2024 Ratings — showing {min(total_p, RESULT_LIMIT_PRED2024):,} of {total_p:,} results")
for r in rows_p:
    with st.container(border=True):
        st.markdown(f"**{r['cve']}**  —  {(r['predicted_label'] or 'UNKNOWN').upper()}")
        cols = st.columns(2)
        with cols[0]:
            show_field("Vendor", r["vendor"])
            show_field("Product", r["product"])
        with cols[1]:
            show_field("Predicted Label", r["predicted_label"])
        st.markdown("**Description:**")
        st.write((r["description"] or "").strip() or "—")

# -------- Tips --------
with st.expander("Search syntax tips"):
    st.markdown(
        """
- Phrases: `"remote code execution"`
- Prefix: `log4j*`
- Field scoping: `vendor: apache  product: httpd`
- Exact CVE (fastest): use the **Exact CVE** box (`CVE-2024-12345`)
"""
    )
