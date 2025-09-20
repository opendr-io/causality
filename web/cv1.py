# streamlit_app.py — CVE search (SQLite FTS5), RAM-served, show all fields, no auto-results on load,
# fixed result limit (no pagination controls), and logo loaded from a fixed file path.
#
# Expected TSV headers (nulls allowed):
#   cve, assigner, published, title, description, vendor, product, "affected versions", rating

import csv
import hashlib
import pathlib
import sqlite3
from typing import List, Tuple
import urllib.parse

import streamlit as st

# -------- Config --------
DEFAULT_TSV = "2025.tsv"     # path to your TSV
DB_PATH = "cve.db"           # small on-disk DB (only for build/persistence)
RESULT_LIMIT = 100           # number of results to show (no pagination)
DEFAULT_LOGO = "IMG/causality.PNG"    # <- set this to your logo file (PNG/JPG/WEBP/SVG)

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

# -------- Build/refresh on-disk DB if TSV changed --------
@st.cache_resource(show_spinner=False)
def build_or_open_disk(tsv_path: str, db_path: str) -> str:
    sig = _sha256_file(tsv_path)
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
        VACUUM;

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
          prefix='2 3'                  -- faster prefix queries like "log4*"
        );

        CREATE INDEX IF NOT EXISTS idx_cves_cve        ON cves(cve);
        CREATE INDEX IF NOT EXISTS idx_cves_vendor     ON cves(vendor);
        CREATE INDEX IF NOT EXISTS idx_cves_product    ON cves(product);
        CREATE INDEX IF NOT EXISTS idx_cves_published  ON cves(published);
        CREATE INDEX IF NOT EXISTS idx_cves_rating     ON cves(rating);
        """)

        with open(tsv_path, newline="", encoding="utf-8", errors="ignore") as f:
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
    disk.backup(mem)  # copy whole DB to RAM once
    disk.close()

    mem.execute("PRAGMA temp_store=MEMORY;")
    mem.execute("PRAGMA cache_size=-400000;")  # ~400MB if available
    return mem

# -------- Sidebar (TSV + maintenance) --------
with st.sidebar:
    tsv_path = st.text_input("TSV path", value=DEFAULT_TSV)
    col1, col2 = st.columns(2)
    with col1:
        force_rebuild = st.button("Force rebuild index")
    with col2:
        explain = st.checkbox("Explain query plan", value=False)

# Load and render logo at top (no sidebar input)
logo_bytes, logo_ext = _load_logo_bytes(DEFAULT_LOGO)
if logo_bytes:
    _render_logo(logo_bytes, logo_ext)

st.title("🔎 CVE Search (RAM-backed SQLite FTS5)")

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

disk_db_path = build_or_open_disk(tsv_path, DB_PATH)
con = serve_from_memory(disk_db_path)

# -------- Inputs (no pagination controls) --------
q = st.text_input(
    "Full-text query",
    placeholder='log4j*  |  "remote code execution"  |  vendor: apache  product: httpd  affected: 1.2.3'
)
exact_cve = st.text_input("Exact CVE (fast)", placeholder="CVE-2024-12345")
vendor = st.text_input("Vendor (prefix)", "")
product = st.text_input("Product (prefix)", "")

# Don't run a search until there's some input
has_input = any(s.strip() for s in (q, exact_cve, vendor, product))
if not has_input:
    st.info("Enter a query (full-text, exact CVE, vendor, or product) to see results.")
    st.stop()

# -------- Build filters (prefix-only to keep indexes hot) --------
def build_filters():
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

where_clauses, params = build_filters()

# -------- Two-phase FTS: top-N, then join (no pagination) --------
HIT_CAP = max(RESULT_LIMIT * 5, 500)  # collect a bit more than we plan to display

fts_param: List[str] = []
if q.strip():
    qx = (q.replace("vendor:", "vendor ")
            .replace("product:", "product ")
            .replace("affected:", "affected_versions "))
    fts_param = [qx]

if fts_param:
    hits_cte = f"""
    WITH hits AS (
      SELECT rowid, bm25(cve_fts) AS rank
      FROM cve_fts
      WHERE cve_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP}
    )
    """
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    count_sql = hits_cte + "SELECT COUNT(*) FROM hits"
    search_sql = hits_cte + f"""
    SELECT h.rank, c.*
    FROM hits h
    JOIN cves c ON c.id = h.rowid
    {where_sql}
    ORDER BY h.rank, c.published DESC, c.cve
    LIMIT {RESULT_LIMIT}
    """
    count_params = fts_param
    search_params = fts_param + params  # LIMIT is literal
else:
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    count_sql = f"SELECT COUNT(*) FROM cves c {where_sql}"
    search_sql = f"""
    SELECT c.*
    FROM cves c
    {where_sql}
    ORDER BY c.published DESC, c.cve
    LIMIT {RESULT_LIMIT}
    """
    count_params = params
    search_params = params

if explain:
    st.code(count_sql.strip())
    st.write("count params:", count_params)
    st.code(search_sql.strip())
    st.write("search params:", search_params)
    plan = con.execute("EXPLAIN QUERY PLAN " + search_sql, search_params).fetchall()
    st.write(plan)

# -------- Execute --------
total = con.execute(count_sql, count_params).fetchone()[0]
rows = con.execute(search_sql, search_params).fetchall()

# -------- Render (show ALL columns) --------
st.write(f"**Showing {min(total, RESULT_LIMIT):,} of {total:,} results**")

def show_field(label: str, val: str):
    v = (val or "").strip()
    st.markdown(f"**{label}:** {v if v else '—'}")

for r in rows:
    with st.container(border=True):
        sev = (r["rating"] or "UNKNOWN").upper()
        pub = r["published"] or "—"
        st.markdown(f"### {r['cve']}  —  {sev} • {pub}")

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
        desc = (r["description"] or "").strip()
        st.write(desc if desc else "—")

# -------- Tips --------
with st.expander("Search syntax tips"):
    st.markdown(
        """
- Phrases: `"remote code execution"`
- Prefix: `log4j*`
- Field scoping (lightweight): `vendor: apache  product: httpd  affected: 1.2.3`
- Exact CVE (fastest): use the **Exact CVE** box (`CVE-2024-12345`)
"""
    )
