# streamlit_app.py — Dual-source CVE search (SQLite FTS5), RAM-served
# A search page for the CAUSALITY ratings data
# Search inputs should live in the LEFT SIDEBAR; results should render in the main page.
#
# 2025 TSV (2025.tsv) headers (nulls allowed):
#   cve, assigner, published, title, description, vendor, product, "affected versions", rating
#
# 2024 TSV (2024.tsv) headers (nulls allowed):
#   cveID, Predicted_Label, vendorProject, product, description

import csv
import hashlib
import logging
import pathlib
import sqlite3
from collections import Counter
from typing import List, Tuple
import urllib.parse
import requests
import streamlit as st

# -------- Config --------env
BASE_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_TSV_PRIMARY  = "../HEAD/2025-processed-clean.txt"  # primary dataset
DEFAULT_TSV_PRED2024 = "../HEAD/2024-output-may-24.txt"    # secondary dataset
DEFAULT_CSV_2026     = "../HEAD/2026-april-run.csv"        # 2026 dataset (optional, CSV)
DEFAULT_PRED_DATES   = "pred_dates.csv"            # CVE -> earliest prediction date
DB_PATH = str(BASE_DIR / "cve.db")  # on-disk cache (rebuilt only if sources change)
LOG_PATH = str(BASE_DIR / "log.log")  # app log output
RESULT_LIMIT_PRIMARY  = 100         # top-N to display from primary
RESULT_LIMIT_PRED2024 = 100         # top-N to display from 2024
RESULT_LIMIT_2026     = 100         # top-N to display from 2026
DEFAULT_LOGO = str(BASE_DIR / "img/causality-3.png")   # fixed logo path (PNG/JPG/WEBP/SVG)
DEFAULT_PROMPT_FILE = "prompt.txt"                     # AI prompt template
OPENROUTER_MODELS = [
    "anthropic/claude-opus-4",
    "anthropic/claude-sonnet-4-5",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "google/gemini-2.0-flash-001",
    "meta-llama/llama-3.3-70b-instruct",
    "mistralai/mistral-large-2411",
    "deepseek/deepseek-chat-v3-0324",
]

st.set_page_config(page_title="CVE Search", layout="wide")

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("causality")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.propagate = False
    return logger

LOGGER = _get_logger()
LOGGER.info("App startup: cwd=%s", pathlib.Path.cwd())

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
def _load_logo_bytes(path: str, logo_sig: str):
    _ = logo_sig  # include content signature in cache key
    p = pathlib.Path(path)
    if not p.exists() or not p.is_file():
        return None, None
    data = p.read_bytes()
    return data, p.suffix.lower()

def _source_signature(tsv_primary: str, tsv_pred2024: str, csv_2026: str, pred_dates: str) -> str:
    # Use content hashes so cache invalidates when any source file changes.
    return (_sha256_file(tsv_primary) + "|" + _sha256_file(tsv_pred2024) +
            "|" + _sha256_file(csv_2026) + "|" + _sha256_file(pred_dates))

def _resolve_input_path(path_text: str) -> str:
    p = pathlib.Path(path_text)
    return str(p if p.is_absolute() else (BASE_DIR / p))

def _render_logo(logo_bytes: bytes, ext: str, width_px: int = 180):
    if not logo_bytes:
        return
    if ext == ".svg":
        svg_text = logo_bytes.decode("utf-8", errors="ignore")
        data_uri = "data:image/svg+xml;charset=utf-8," + urllib.parse.quote(svg_text)
        st.markdown(
            f"<img src='{data_uri}' alt='logo' style='width:{width_px}px;height:auto;max-width:100%;'>",
            unsafe_allow_html=True,
        )
    else:
        st.image(logo_bytes, caption=None, width=width_px)

# -------- AI helpers --------
def _load_prompt(path: str) -> str:
    p = pathlib.Path(path)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8").strip()
    return "Give a summary of how to reason about exposure to this CVE and how to patch or mitigate it."

def _build_ai_context(data: dict) -> str:
    lines = [
        f"CVE ID: {data['cve']}",
        f"Year: {data['year']}",
        f"Rating: {data['rating']}",
    ]
    if data.get("title"):
        lines.append(f"Title: {data['title']}")
    if data.get("vendor"):
        lines.append(f"Vendor: {data['vendor']}")
    if data.get("product"):
        lines.append(f"Product: {data['product']}")
    if data.get("description"):
        lines.append(f"Description: {data['description']}")
    return "\n".join(lines)

def _ask_perplexity(api_key: str, model: str, prompt: str, cve_data: dict) -> str:
    context = _build_ai_context(cve_data)
    full_prompt = f"{prompt}\n\n---\n{context}"
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": model, "messages": [{"role": "user", "content": full_prompt}]},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


# -------- Build/refresh on-disk DB if any TSV changed --------
@st.cache_resource(show_spinner=False)
def build_or_open_disk(tsv_primary: str, tsv_pred2024: str, csv_2026: str, pred_dates: str, db_path: str, source_sig: str) -> Tuple[str, List[str]]:
    sig = source_sig
    sig_file = pathlib.Path(db_path + ".sig")
    load_errors: List[str] = []
    need_build = True
    if pathlib.Path(db_path).exists() and sig_file.exists():
        need_build = (sig_file.read_text() != sig)
    LOGGER.info(
        "DB check: primary=%s secondary=%s db=%s rebuild=%s",
        tsv_primary, tsv_pred2024, db_path, need_build
    )

    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA temp_store=MEMORY;")
    cur.execute("PRAGMA cache_size=-200000;")

    if need_build:
        LOGGER.info("Rebuilding SQLite index from source files")
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

        -- 2026 dataset (optional CSV)
        DROP TABLE IF EXISTS preds2026;
        DROP TABLE IF EXISTS preds2026_fts;

        CREATE TABLE preds2026 (
          id INTEGER PRIMARY KEY,
          cve TEXT NOT NULL,
          assigner TEXT,
          published TEXT,
          title TEXT,
          description TEXT,
          vendor TEXT,
          product TEXT,
          rating TEXT
        );

        CREATE VIRTUAL TABLE preds2026_fts USING fts5(
          title, description, vendor, product,
          content='preds2026', content_rowid='id',
          tokenize='porter unicode61',
          prefix='2 3'
        );

        CREATE INDEX IF NOT EXISTS idx_p26_cve     ON preds2026(cve);
        CREATE INDEX IF NOT EXISTS idx_p26_vendor  ON preds2026(vendor);
        CREATE INDEX IF NOT EXISTS idx_p26_product ON preds2026(product);
        CREATE INDEX IF NOT EXISTS idx_p26_rating  ON preds2026(rating);

        -- Prediction dates lookup (CVE -> earliest pred date)
        DROP TABLE IF EXISTS pred_dates;
        CREATE TABLE pred_dates (
          cve TEXT PRIMARY KEY,
          pred_date TEXT        -- YYYY-MM-DD
        );
        """)

        # Load primary TSV
        p = pathlib.Path(tsv_primary)
        primary_loaded = 0
        if p.exists() and p.is_file():
            try:
                with open(tsv_primary, newline="", encoding="utf-8", errors="ignore") as f:
                    sample = f.read(4096)
                    f.seek(0)
                    delim = "," if sample.count(",") > sample.count("\t") else "\t"
                    rdr = csv.DictReader(f, delimiter=delim)
                    batch: List[Tuple] = []
                    for r in rdr:
                        cve = _get(r, "cve") or _get(r, "cveID") or _get(r, "cveid")
                        if not cve:
                            continue
                        batch.append((
                            cve,
                            _get(r, "assigner"),
                            _get(r, "published")[:10],
                            (_get(r, "title") or _get(r, "vulnerabilityName") or _get(r, "vulnerabilityname")),
                            (_get(r, "description") or _get(r, "shortDescription") or _get(r, "shortdescription")),
                            (_get(r, "vendor") or _get(r, "vendorProject") or _get(r, "vendorproject")),
                            _get(r, "product"),
                            (_get(r, "affected versions") or _get(r, "affected_versions")),
                            _get(r, "rating"),
                        ))
                        if len(batch) >= 5000:
                            primary_loaded += len(batch)
                            cur.executemany(
                                """INSERT INTO cves
                                   (cve,assigner,published,title,description,vendor,product,affected_versions,rating)
                                   VALUES (?,?,?,?,?,?,?,?,?)""",
                                batch
                            )
                            batch.clear()
                    if batch:
                        primary_loaded += len(batch)
                        cur.executemany(
                            """INSERT INTO cves
                               (cve,assigner,published,title,description,vendor,product,affected_versions,rating)
                               VALUES (?,?,?,?,?,?,?,?,?)""",
                            batch
                        )
                cur.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild');")
                LOGGER.info("Primary dataset loaded: rows=%s file=%s", primary_loaded, tsv_primary)
            except Exception as e:
                msg = f"Error reading primary file {tsv_primary}: {e}"
                LOGGER.error(msg)
                load_errors.append(msg)
        else:
            msg = f"Primary file not found: {tsv_primary}"
            LOGGER.warning(msg)
            load_errors.append(msg)

        # Load 2024 TSV
        p2 = pathlib.Path(tsv_pred2024)
        pred_loaded = 0
        if p2.exists() and p2.is_file():
            try:
                with open(tsv_pred2024, newline="", encoding="utf-8", errors="ignore") as f:
                    rdr = csv.DictReader(f, delimiter="\t")
                    batch2: List[Tuple] = []
                    for r in rdr:
                        cve = _get(r, "cveID") or _get(r, "cve")
                        if not cve or cve.lower() == "cveid":
                            continue
                        batch2.append((
                            cve,
                            (_get(r, "Predicted_Label") or _get(r, "rating")),
                            (_get(r, "vendorProject") or _get(r, "vendor")),
                            _get(r, "product"),
                            (_get(r, "description") or _get(r, "shortDescription")),
                        ))
                        if len(batch2) >= 5000:
                            pred_loaded += len(batch2)
                            cur.executemany(
                                """INSERT INTO preds2024
                                   (cve,predicted_label,vendor,product,description)
                                   VALUES (?,?,?,?,?)""",
                                batch2
                            )
                            batch2.clear()
                    if batch2:
                        pred_loaded += len(batch2)
                        cur.executemany(
                            """INSERT INTO preds2024
                               (cve,predicted_label,vendor,product,description)
                               VALUES (?,?,?,?,?)""",
                            batch2
                        )
                cur.execute("INSERT INTO preds2024_fts(preds2024_fts) VALUES('rebuild');")
                LOGGER.info("2024 dataset loaded: rows=%s file=%s", pred_loaded, tsv_pred2024)
            except Exception as e:
                msg = f"Error reading 2024 file {tsv_pred2024}: {e}"
                LOGGER.error(msg)
                load_errors.append(msg)
        else:
            msg = f"2024 file not found: {tsv_pred2024}"
            LOGGER.warning(msg)
            load_errors.append(msg)

        # Load 2026 CSV (optional, comma-delimited)
        p3 = pathlib.Path(csv_2026)
        pred2026_loaded = 0
        if p3.exists() and p3.is_file():
            try:
                with open(csv_2026, newline="", encoding="utf-8", errors="ignore") as f:
                    rdr = csv.DictReader(f, delimiter=",")
                    batch3: List[Tuple] = []
                    for r in rdr:
                        cve = _get(r, "cveid") or _get(r, "cve") or _get(r, "cveID")
                        if not cve:
                            continue
                        pub = _get(r, "published")
                        batch3.append((
                            cve,
                            _get(r, "assigner"),
                            pub[:10] if pub else "",
                            (_get(r, "vulnerabilityname") or _get(r, "title")),
                            (_get(r, "shortdescription") or _get(r, "description")),
                            (_get(r, "vendorproject") or _get(r, "vendor")),
                            _get(r, "product"),
                            _get(r, "rating"),
                        ))
                        if len(batch3) >= 5000:
                            pred2026_loaded += len(batch3)
                            cur.executemany(
                                """INSERT INTO preds2026
                                   (cve,assigner,published,title,description,vendor,product,rating)
                                   VALUES (?,?,?,?,?,?,?,?)""",
                                batch3
                            )
                            batch3.clear()
                    if batch3:
                        pred2026_loaded += len(batch3)
                        cur.executemany(
                            """INSERT INTO preds2026
                               (cve,assigner,published,title,description,vendor,product,rating)
                               VALUES (?,?,?,?,?,?,?,?)""",
                            batch3
                        )
                cur.execute("INSERT INTO preds2026_fts(preds2026_fts) VALUES('rebuild');")
                LOGGER.info("2026 dataset loaded: rows=%s file=%s", pred2026_loaded, csv_2026)
            except Exception as e:
                msg = f"Error reading 2026 file {csv_2026}: {e}"
                LOGGER.error(msg)
                load_errors.append(msg)
        else:
            LOGGER.info("2026 dataset not present, skipping: file=%s", csv_2026)

        # Load pred_dates CSV
        p4 = pathlib.Path(pred_dates)
        pred_dates_loaded = 0
        if p4.exists() and p4.is_file():
            try:
                with open(pred_dates, newline="", encoding="utf-8", errors="ignore") as f:
                    rdr = csv.DictReader(f)
                    batch4: List[Tuple] = []
                    for r in rdr:
                        cve = _get(r, "cve")
                        pd = _get(r, "pred_date")
                        if not cve or not pd:
                            continue
                        batch4.append((cve, pd))
                        if len(batch4) >= 5000:
                            pred_dates_loaded += len(batch4)
                            cur.executemany("INSERT OR REPLACE INTO pred_dates (cve, pred_date) VALUES (?,?)", batch4)
                            batch4.clear()
                    if batch4:
                        pred_dates_loaded += len(batch4)
                        cur.executemany("INSERT OR REPLACE INTO pred_dates (cve, pred_date) VALUES (?,?)", batch4)
                LOGGER.info("pred_dates loaded: rows=%s file=%s", pred_dates_loaded, pred_dates)
            except Exception as e:
                msg = f"Error reading pred_dates file {pred_dates}: {e}"
                LOGGER.error(msg)
                load_errors.append(msg)
        else:
            msg = f"pred_dates file not found: {pred_dates}"
            LOGGER.warning(msg)
            load_errors.append(msg)

        con.commit()
        sig_file.write_text(sig)
        LOGGER.info("DB rebuild complete: db=%s sig_file=%s", db_path, sig_file)

    con.close()
    return db_path, load_errors

# -------- Serve entirely from RAM --------
@st.cache_resource(show_spinner=False)
def serve_from_memory(db_path: str, source_sig: str) -> sqlite3.Connection:
    _ = source_sig  # part of cache key to force RAM refresh when TSV content changes
    disk = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
    disk.row_factory = sqlite3.Row
    mem = sqlite3.connect(":memory:", check_same_thread=False)
    mem.row_factory = sqlite3.Row
    disk.backup(mem)  # copy entire DB to RAM
    disk.close()

    mem.execute("PRAGMA temp_store=MEMORY;")
    mem.execute("PRAGMA cache_size=-400000;")
    LOGGER.info("Loaded database into RAM: db=%s", db_path)
    return mem

# -------- Header (fixed logo + title + description) --------
logo_sig = _sha256_file(DEFAULT_LOGO)
logo_bytes, logo_ext = _load_logo_bytes(DEFAULT_LOGO, logo_sig)
st.markdown(
    """
<style>
section.main > div.block-container {
    padding-top: 4rem;
}
</style>
""",
    unsafe_allow_html=True,
)
st.markdown(
    "<h3 style='margin:0.05rem 0 0.2rem 0;'>CAUSALITY Ratings Search</h3>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='margin:0;font-size:0.9rem;color:var(--text-color);'>Ratings are available for 2024 - 2026.</p>",
    unsafe_allow_html=True,
)

# -------- Sidebar: paths, maintenance, and SEARCH INPUTS --------
if "cve_id" in st.query_params and not st.session_state.get("exact_cve"):
    st.session_state["exact_cve"] = st.query_params["cve_id"]

if st.session_state.pop("_clear_search_pending", False):
    for k in ("q", "exact_cve", "vendor", "product"):
        st.session_state[k] = ""
    st.query_params.clear()

with st.sidebar:
    if logo_bytes:
        _render_logo(logo_bytes, logo_ext, width_px=230)
    search_tab, data_tab, ai_tab = st.tabs(["Search", "Data/Index", "AI"])

    with search_tab:
        q = st.text_input(
            "Full-text query",
            key="q",
            #placeholder='log4j*  |  "remote code execution"  |  vendor: apache  product: httpd'
        )
        exact_cve = st.text_area(
            "Exact CVE(s) — one per line or comma-separated",
            key="exact_cve",
            height=80,
            placeholder="CVE-2025-1234\nCVE-2025-5678",
        )
        vendor = st.text_input("Vendor (prefix)", "", key="vendor")
        product = st.text_input("Product (prefix)", "", key="product")
        clear_search = st.button("Clear search options")

    with data_tab:
        st.subheader("Data sources")
        tsv_primary  = st.text_input("Primary TSV path", value=DEFAULT_TSV_PRIMARY)
        tsv_pred2024 = st.text_input("2024 TSV path", value=DEFAULT_TSV_PRED2024)
        csv_2026     = st.text_input("2026 CSV path", value=DEFAULT_CSV_2026)
        counts_placeholder = st.empty()

        col1, col2 = st.columns(2)
        with col1:
            force_rebuild = st.button("Force rebuild index")
        with col2:
            explain = st.checkbox("Explain query plan", value=False)
        errors_placeholder = st.empty()

    with ai_tab:
        st.subheader("AI Settings")
        openrouter_api_key = st.text_input("OpenRouter API key", type="password", key="openrouter_api_key")
        ai_model = st.selectbox("Model", options=OPENROUTER_MODELS, key="ai_model")
        ai_custom_model = st.text_input("Or enter a custom model ID", key="ai_custom_model")
        prompt_file = st.text_input("Prompt file", value=DEFAULT_PROMPT_FILE, key="prompt_file")

if clear_search:
    st.session_state["_clear_search_pending"] = True
    st.rerun()

tsv_primary_path = _resolve_input_path(tsv_primary)
tsv_pred2024_path = _resolve_input_path(tsv_pred2024)
csv_2026_path = _resolve_input_path(csv_2026)

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

_active_model = ai_custom_model.strip() if ai_custom_model.strip() else ai_model
prompt_text = _load_prompt(_resolve_input_path(prompt_file))

pred_dates_path = _resolve_input_path(DEFAULT_PRED_DATES)
source_sig = _source_signature(tsv_primary_path, tsv_pred2024_path, csv_2026_path, pred_dates_path)
disk_db_path, load_errors = build_or_open_disk(tsv_primary_path, tsv_pred2024_path, csv_2026_path, pred_dates_path, DB_PATH, source_sig)
con = serve_from_memory(disk_db_path, source_sig)

_n2025 = con.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
_n2024 = con.execute("SELECT COUNT(*) FROM preds2024").fetchone()[0]
_n2026 = con.execute("SELECT COUNT(*) FROM preds2026").fetchone()[0]
counts_placeholder.markdown(
    f"**CVEs indexed**  \n"
    f"2025: {_n2025:,}  \n"
    f"2024: {_n2024:,}  \n"
    f"2026: {_n2026:,}"
)
if load_errors:
    errors_placeholder.error("\n\n".join(load_errors))
else:
    errors_placeholder.empty()

# -------- Don't run a search until there's some input --------
has_input = any(s.strip() for s in (q, exact_cve, vendor, product))
if not has_input:
    st.stop()


# -------- Filter builders (prefix-only for speed) --------
import re as _re

_CVE_RE = _re.compile(r'^CVE-\d{4}-\d+$', _re.IGNORECASE)
_CVE_FIND_RE = _re.compile(r'CVE-\d{4}-\d+', _re.IGNORECASE)

def _effective_cves() -> List[str]:
    """Return CVE IDs to match exactly — extracted from the dedicated field,
    or from q if it looks like a single CVE ID."""
    if exact_cve.strip():
        return [m.upper() for m in _CVE_FIND_RE.findall(exact_cve)]
    if _CVE_RE.match(q.strip()):
        return [q.strip().upper()]
    return []

def _cve_filter(alias: str, cves: List[str]) -> Tuple[List[str], List]:
    if not cves:
        return [], []
    placeholders = ",".join("?" * len(cves))
    return [f"{alias}.cve IN ({placeholders})"], list(cves)

def build_filters_primary():
    where, params = [], []
    cves = _effective_cves()
    w, p = _cve_filter("c", cves)
    where += w; params += p
    if vendor.strip():
        where.append("c.vendor LIKE ?")
        params.append(vendor.strip() + "%")
    if product.strip():
        where.append("c.product LIKE ?")
        params.append(product.strip() + "%")
    return where, params

def build_filters_p2024():
    where, params = [], []
    cves = _effective_cves()
    w, p = _cve_filter("p", cves)
    where += w; params += p
    if vendor.strip():
        where.append("p.vendor LIKE ?")
        params.append(vendor.strip() + "%")
    if product.strip():
        where.append("p.product LIKE ?")
        params.append(product.strip() + "%")
    return where, params

def build_filters_p2026():
    where, params = [], []
    cves = _effective_cves()
    w, p = _cve_filter("p", cves)
    where += w; params += p
    if vendor.strip():
        where.append("p.vendor LIKE ?")
        params.append(vendor.strip() + "%")
    if product.strip():
        where.append("p.product LIKE ?")
        params.append(product.strip() + "%")
    return where, params

where_c, params_c = build_filters_primary()
where_p, params_p = build_filters_p2024()
where_26, params_26 = build_filters_p2026()

# -------- Two-phase FTS for each dataset (no pagination) --------
def _fts5_escape(token: str) -> str:
    """Wrap an FTS5 token in double-quotes if it contains hyphens.
    Handles column-filter tokens like vendor:term so the prefix is preserved."""
    col_prefix, term = "", token
    if ":" in token:
        col, _, rest = token.partition(":")
        if col.isalpha() and rest:          # looks like a column filter
            col_prefix, term = col + ":", rest
    if _re.search(r"[-]", term):
        return col_prefix + '"' + term.replace('"', '""') + '"'
    return col_prefix + term

def scope_query(qs: str, vendor_key: str, product_key: str):
    # Normalise "vendor: term" (user-friendly) → "vendor:term" (FTS5 column filter)
    qs = _re.sub(rf"{_re.escape(vendor_key)}:\s*", f"{vendor_key}:", qs)
    qs = _re.sub(rf"{_re.escape(product_key)}:\s*", f"{product_key}:", qs)
    # Escape individual tokens so hyphens (FTS5 NOT operator) don't break CVE IDs
    tokens = qs.split()
    return " ".join(_fts5_escape(t) for t in tokens)

HIT_CAP_PRIMARY  = max(RESULT_LIMIT_PRIMARY  * 5, 500)
HIT_CAP_PRED2024 = max(RESULT_LIMIT_PRED2024 * 5, 500)

# --- Primary
fts_params_c = []
if q.strip() and not _CVE_RE.match(q.strip()):
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
    SELECT h.rank, c.*, pd.pred_date
    FROM hits h
    JOIN cves c ON c.id = h.rowid
    LEFT JOIN pred_dates pd ON pd.cve = c.cve
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
    SELECT c.*, pd.pred_date
    FROM cves c
    LEFT JOIN pred_dates pd ON pd.cve = c.cve
    {where_sql_c}
    ORDER BY c.published DESC, c.cve
    LIMIT {RESULT_LIMIT_PRIMARY}
    """
    count_params_c = params_c
    search_params_c = params_c

# --- 2024 predictions
fts_params_p = []
if q.strip() and not _CVE_RE.match(q.strip()):
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
      SELECT rowid, bm25(preds2024_fts) AS rank
      FROM preds2024_fts
      WHERE preds2024_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRED2024}
    )
    SELECT h.rank, p.*, pd.pred_date
    FROM hits h
    JOIN preds2024 p ON p.id = h.rowid
    LEFT JOIN pred_dates pd ON pd.cve = p.cve
    {where_sql_p}
    ORDER BY h.rank, p.cve
    LIMIT {RESULT_LIMIT_PRED2024}
    """

    count_params_p = fts_params_p
    search_params_p = fts_params_p + params_p
else:
    where_sql_p = ("WHERE " + " AND ".join(where_p)) if where_p else ""
    count_sql_p = f"SELECT COUNT(*) FROM preds2024 p {where_sql_p}"
    search_sql_p = f"""
    SELECT p.*, pd.pred_date
    FROM preds2024 p
    LEFT JOIN pred_dates pd ON pd.cve = p.cve
    {where_sql_p}
    ORDER BY p.cve
    LIMIT {RESULT_LIMIT_PRED2024}
    """
    count_params_p = params_p
    search_params_p = params_p

# --- 2026
HIT_CAP_2026 = max(RESULT_LIMIT_2026 * 5, 500)
fts_params_26 = []
if q.strip() and not _CVE_RE.match(q.strip()):
    fts_params_26 = [scope_query(q, "vendor", "product")]

if fts_params_26:
    where_sql_26 = ("WHERE " + " AND ".join(where_26)) if where_26 else ""
    count_sql_26 = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2026_fts) AS rank
      FROM preds2026_fts
      WHERE preds2026_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_2026}
    )
    SELECT COUNT(*) FROM hits
    """
    search_sql_26 = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2026_fts) AS rank
      FROM preds2026_fts
      WHERE preds2026_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_2026}
    )
    SELECT h.rank, p.*, pd.pred_date
    FROM hits h
    JOIN preds2026 p ON p.id = h.rowid
    LEFT JOIN pred_dates pd ON pd.cve = p.cve
    {where_sql_26}
    ORDER BY h.rank, p.cve
    LIMIT {RESULT_LIMIT_2026}
    """
    count_params_26 = fts_params_26
    search_params_26 = fts_params_26 + params_26
else:
    where_sql_26 = ("WHERE " + " AND ".join(where_26)) if where_26 else ""
    count_sql_26 = f"SELECT COUNT(*) FROM preds2026 p {where_sql_26}"
    search_sql_26 = f"""
    SELECT p.*, pd.pred_date
    FROM preds2026 p
    LEFT JOIN pred_dates pd ON pd.cve = p.cve
    {where_sql_26}
    ORDER BY p.cve
    LIMIT {RESULT_LIMIT_2026}
    """
    count_params_26 = params_26
    search_params_26 = params_26

# --- Rating distribution SQL
if fts_params_c:
    rating_sql_c = f"""
    WITH hits AS (
      SELECT rowid, bm25(cve_fts) AS rank
      FROM cve_fts
      WHERE cve_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRIMARY}
    )
    SELECT COALESCE(NULLIF(TRIM(c.rating), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM hits h
    JOIN cves c ON c.id = h.rowid
    {where_sql_c}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_c = fts_params_c + params_c
else:
    rating_sql_c = f"""
    SELECT COALESCE(NULLIF(TRIM(c.rating), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM cves c
    {where_sql_c}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_c = params_c

if fts_params_p:
    rating_sql_p = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2024_fts) AS rank
      FROM preds2024_fts
      WHERE preds2024_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRED2024}
    )
    SELECT COALESCE(NULLIF(TRIM(p.predicted_label), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM hits h
    JOIN preds2024 p ON p.id = h.rowid
    {where_sql_p}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_p = fts_params_p + params_p
else:
    rating_sql_p = f"""
    SELECT COALESCE(NULLIF(TRIM(p.predicted_label), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM preds2024 p
    {where_sql_p}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_p = params_p

# --- Distinct product values (for current query scope)
if fts_params_c:
    product_sql_c = f"""
    WITH hits AS (
      SELECT rowid, bm25(cve_fts) AS rank
      FROM cve_fts
      WHERE cve_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRIMARY}
    )
    SELECT DISTINCT TRIM(c.product) AS product_value
    FROM hits h
    JOIN cves c ON c.id = h.rowid
    {where_sql_c}
    """
    product_params_c = fts_params_c + params_c
else:
    product_sql_c = f"""
    SELECT DISTINCT TRIM(c.product) AS product_value
    FROM cves c
    {where_sql_c}
    """
    product_params_c = params_c

if fts_params_p:
    product_sql_p = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2024_fts) AS rank
      FROM preds2024_fts
      WHERE preds2024_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_PRED2024}
    )
    SELECT DISTINCT TRIM(p.product) AS product_value
    FROM hits h
    JOIN preds2024 p ON p.id = h.rowid
    {where_sql_p}
    """
    product_params_p = fts_params_p + params_p
else:
    product_sql_p = f"""
    SELECT DISTINCT TRIM(p.product) AS product_value
    FROM preds2024 p
    {where_sql_p}
    """
    product_params_p = params_p

if fts_params_26:
    rating_sql_26 = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2026_fts) AS rank
      FROM preds2026_fts
      WHERE preds2026_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_2026}
    )
    SELECT COALESCE(NULLIF(TRIM(p.rating), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM hits h
    JOIN preds2026 p ON p.id = h.rowid
    {where_sql_26}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_26 = fts_params_26 + params_26
else:
    rating_sql_26 = f"""
    SELECT COALESCE(NULLIF(TRIM(p.rating), ''), 'UNKNOWN') AS rating_value, COUNT(*) AS cnt
    FROM preds2026 p
    {where_sql_26}
    GROUP BY rating_value
    ORDER BY cnt DESC, rating_value
    """
    rating_params_26 = params_26

if fts_params_26:
    product_sql_26 = f"""
    WITH hits AS (
      SELECT rowid, bm25(preds2026_fts) AS rank
      FROM preds2026_fts
      WHERE preds2026_fts MATCH ?
      ORDER BY rank
      LIMIT {HIT_CAP_2026}
    )
    SELECT DISTINCT TRIM(p.product) AS product_value
    FROM hits h
    JOIN preds2026 p ON p.id = h.rowid
    {where_sql_26}
    """
    product_params_26 = fts_params_26 + params_26
else:
    product_sql_26 = f"""
    SELECT DISTINCT TRIM(p.product) AS product_value
    FROM preds2026 p
    {where_sql_26}
    """
    product_params_26 = params_26

# Optional: EXPLAIN plans
if explain:
    for label, sql, params in [
        ("PRIMARY count", count_sql_c, count_params_c),
        ("PRIMARY search", search_sql_c, search_params_c),
        ("PRIMARY ratings", rating_sql_c, rating_params_c),
        ("PRIMARY products", product_sql_c, product_params_c),
        ("PRED2024 count", count_sql_p, count_params_p),
        ("PRED2024 search", search_sql_p, search_params_p),
        ("PRED2024 ratings", rating_sql_p, rating_params_p),
        ("PRED2024 products", product_sql_p, product_params_p),
        ("PRED2026 count", count_sql_26, count_params_26),
        ("PRED2026 search", search_sql_26, search_params_26),
        ("PRED2026 ratings", rating_sql_26, rating_params_26),
        ("PRED2026 products", product_sql_26, product_params_26),
    ]:
        st.subheader(label)
        st.code(sql.strip())
        st.write("params:", params)
        plan = con.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
        st.write(plan)

# -------- Execute --------
try:
    total_c_raw = con.execute(count_sql_c, count_params_c).fetchone()[0]
    rows_c  = con.execute(search_sql_c,  search_params_c).fetchall()
    rating_rows_c = con.execute(rating_sql_c, rating_params_c).fetchall()
    product_rows_c = con.execute(product_sql_c, product_params_c).fetchall()

    total_p_raw = con.execute(count_sql_p, count_params_p).fetchone()[0]
    rows_p  = con.execute(search_sql_p,  search_params_p).fetchall()
    rating_rows_p = con.execute(rating_sql_p, rating_params_p).fetchall()
    product_rows_p = con.execute(product_sql_p, product_params_p).fetchall()

    total_26_raw = con.execute(count_sql_26, count_params_26).fetchone()[0]
    rows_26  = con.execute(search_sql_26,  search_params_26).fetchall()
    rating_rows_26 = con.execute(rating_sql_26, rating_params_26).fetchall()
    product_rows_26 = con.execute(product_sql_26, product_params_26).fetchall()
except sqlite3.OperationalError as e:
    st.error(f"Search query error — check your query syntax: {e}")
    st.stop()

rating_counter = Counter()
for rr in rating_rows_c:
    rating_counter[(rr["rating_value"] or "UNKNOWN").upper()] += int(rr["cnt"])
for rr in rating_rows_p:
    rating_counter[(rr["rating_value"] or "UNKNOWN").upper()] += int(rr["cnt"])
for rr in rating_rows_26:
    rating_counter[(rr["rating_value"] or "UNKNOWN").upper()] += int(rr["cnt"])
rating_options = [k for k, _ in sorted(rating_counter.items(), key=lambda x: (-x[1], x[0]))]
# Key changes whenever the available option set changes, so the widget resets to
# all-selected instead of silently retaining stale session state from a previous
# search (which would leave nothing selected and hide all results).
_rating_key = "rating_filter_" + "_".join(rating_options)
selected_ratings = st.multiselect(
    "Results by Rating",
    options=rating_options,
    default=rating_options,
    format_func=lambda k: f"{k}: {rating_counter[k]:,}",
    key=_rating_key,
)
selected_rating_set = set(selected_ratings)

def _norm_rating(val: str) -> str:
    return ((val or "").strip().upper() or "UNKNOWN")

rows_c  = [r for r in rows_c  if _norm_rating(r["rating"]) in selected_rating_set]
rows_p  = [r for r in rows_p  if _norm_rating(r["predicted_label"]) in selected_rating_set]
rows_26 = [r for r in rows_26 if _norm_rating(r["rating"]) in selected_rating_set]

total_c = sum(
    int(rr["cnt"])
    for rr in rating_rows_c
    if _norm_rating(rr["rating_value"]) in selected_rating_set
)
total_p = sum(
    int(rr["cnt"])
    for rr in rating_rows_p
    if _norm_rating(rr["rating_value"]) in selected_rating_set
)
total_26 = sum(
    int(rr["cnt"])
    for rr in rating_rows_26
    if _norm_rating(rr["rating_value"]) in selected_rating_set
)
product_values = {
    (r["product_value"] or "").strip()
    for r in list(product_rows_c) + list(product_rows_p) + list(product_rows_26)
    if (r["product_value"] or "").strip()
}
product_value_count = len(product_values)
LOGGER.info(
    "Search executed: q=%r exact_cve=%r vendor=%r product=%r total_2025=%s total_2024=%s total_2026=%s filtered_2025=%s filtered_2024=%s filtered_2026=%s shown_2025=%s shown_2024=%s shown_2026=%s",
    q, exact_cve, vendor, product, total_c_raw, total_p_raw, total_26_raw, total_c, total_p, total_26, len(rows_c), len(rows_p), len(rows_26)
)

# -------- Render helpers --------
def show_field(label: str, val: str):
    v = (val or "").strip()
    st.markdown(f"**{label}:** {v if v else '—'}")

def _compact_card_body(r, rating_field: str):
    """Render card fields in two columns (left: vendor/product, right: rating/predicted) then description."""
    left, right = [], []
    for label, key in [("Vendor", "vendor"), ("Product", "product")]:
        v = (r[key] or "").strip() if key in r.keys() else ""
        if v:
            left.append(f"**{label}:** {v}")
    rating_val = (r[rating_field] or "").strip() if rating_field in r.keys() else ""
    if rating_val:
        right.append(f"**Rating:** {rating_val}")
    pred = (r["pred_date"] or "").strip() if "pred_date" in r.keys() else ""
    if pred:
        right.append(f"**Predicted:** {pred}")
    cols = st.columns(2)
    with cols[0]:
        st.markdown("  \n".join(left) or "—")
    with cols[1]:
        st.markdown("  \n".join(right) or "—")
    desc = (r["description"] or "").strip() if "description" in r.keys() else ""
    if desc:
        st.markdown(f"**Description:** {desc}")

def _ai_data(r, rating_field: str, year: str) -> dict:
    d = {
        "cve": r["cve"],
        "year": year,
        "rating": (r[rating_field] or "").strip(),
        "vendor": (r["vendor"] or "").strip(),
        "product": (r["product"] or "").strip(),
        "description": (r["description"] or "").strip(),
    }
    if "title" in r.keys() and r["title"]:
        d["title"] = r["title"].strip()
    return d

def _card_text(r, rating_field: str, year: str) -> str:
    lines = [f"{r['cve']} [{year}]", f"Rating: {(r[rating_field] or 'UNKNOWN').upper()}"]
    for k, label in [("title","Title"),("vendor","Vendor"),("product","Product"),("description","Description")]:
        v = (r[k] or "").strip() if k in r.keys() else ""
        if v:
            lines.append(f"{label}: {v}")
    return "\n".join(lines)

def _rows_to_text(rows, rating_field, year):
    lines = []
    keys = rows[0].keys() if rows else []
    for r in rows:
        lines.append(f"[{year}] {r['cve']} — {(r[rating_field] or 'UNKNOWN').upper()}")
        if "title" in keys and r["title"]: lines.append(f"  {r['title']}")
        if "vendor" in keys and r["vendor"]: lines.append(f"  Vendor: {r['vendor']}")
        if "product" in keys and r["product"]: lines.append(f"  Product: {r['product']}")
        if "description" in keys and r["description"]: lines.append(f"  {r['description']}")
        lines.append("")
    return "\n".join(lines)


_ai_request = None  # legacy; buttons now go through session_state["ai_running"]

# -------- Main tabs --------
ai_label = "🤖 AI Analysis" + (" ✦" if st.session_state.get("ai_result") else "")
history = st.session_state.get("ai_history", [])
history_label = f"📋 History ({len(history)})" if history else "📋 History"
tab_results, tab_ai, tab_history = st.tabs([
    f"Results — {(total_c + total_p + total_26):,} ({product_value_count:,} products)",
    ai_label,
    history_label,
])

with tab_results:
    _results_txt = (
        _rows_to_text(rows_26, "rating", "2026") +
        _rows_to_text(rows_c, "rating", "2025") +
        _rows_to_text(rows_p, "predicted_label", "2024")
    ).strip()
    _exp_col, _y26_col, _y25_col, _y24_col = st.columns([3, 1, 1, 1])
    with _exp_col:
        st.download_button("⬇ Export results (TXT)", data=_results_txt, file_name="cve_results.txt", mime="text/plain")
    with _y26_col:
        show_2026 = st.checkbox("2026", value=True)
    with _y25_col:
        show_2025 = st.checkbox("2025", value=True)
    with _y24_col:
        show_2024 = st.checkbox("2024", value=True)

    # -------- Render: 2026 section --------
    if show_2026 and total_26_raw > 0:
        st.markdown(
            f"<p style='font-size:0.95rem; margin: 0.1rem 0 0.5rem 0;'><strong>2026 Ratings</strong> — showing {min(total_26, RESULT_LIMIT_2026):,} of {total_26:,} results</p>",
            unsafe_allow_html=True,
        )
        for r in rows_26:
            with st.container(border=True):
                sev = (r["rating"] or "UNKNOWN").upper()
                hcol1, hcol2 = st.columns([12, 1])
                with hcol1:
                    title_line = f"  \n_{r['title'].strip()}_" if r["title"] else ""
                    st.markdown(f"**{r['cve']}**  —  {sev}{title_line}")
                with hcol2:
                    if st.button("🤖", key=f"ai_26_{r['id']}", help="Ask AI about this CVE"):
                        st.session_state["ai_running"] = _ai_data(r, "rating", "2026")
                        st.rerun()
                _compact_card_body(r, "rating")
                with st.expander("📋 copy"):
                    st.code(_card_text(r, "rating", "2026"), language=None)
        st.divider()

    # -------- Render: 2025 section --------
    if show_2025:
        st.markdown(
            f"<p style='font-size:0.95rem; margin: 0.1rem 0 0.5rem 0;'><strong>2025 Ratings</strong> — showing {min(total_c, RESULT_LIMIT_PRIMARY):,} of {total_c:,} results</p>",
            unsafe_allow_html=True,
        )
        for r in rows_c:
            with st.container(border=True):
                sev = (r["rating"] or "UNKNOWN").upper()
                hcol1, hcol2 = st.columns([12, 1])
                with hcol1:
                    title_line = f"  \n_{r['title'].strip()}_" if r["title"] else ""
                    st.markdown(f"**{r['cve']}**  —  {sev}{title_line}")
                with hcol2:
                    if st.button("🤖", key=f"ai_c_{r['id']}", help="Ask AI about this CVE"):
                        st.session_state["ai_running"] = _ai_data(r, "rating", "2025")
                        st.rerun()
                _compact_card_body(r, "rating")
                with st.expander("📋 copy"):
                    st.code(_card_text(r, "rating", "2025"), language=None)
        st.divider()

    # -------- Render: 2024 section --------
    if show_2024:
        st.markdown(
            f"<p style='font-size:0.95rem; margin: 0.1rem 0 0.5rem 0;'><strong>2024 Ratings</strong> — showing {min(total_p, RESULT_LIMIT_PRED2024):,} of {total_p:,} results</p>",
            unsafe_allow_html=True,
        )
        for r in rows_p:
            with st.container(border=True):
                rating_p = (r["predicted_label"] or "UNKNOWN").upper()
                hcol1, hcol2 = st.columns([12, 1])
                with hcol1:
                    st.markdown(f"**{r['cve']}**  —  {rating_p}")
                with hcol2:
                    if st.button("🤖", key=f"ai_p_{r['id']}", help="Ask AI about this CVE"):
                        st.session_state["ai_running"] = _ai_data(r, "predicted_label", "2024")
                        st.rerun()
                _compact_card_body(r, "predicted_label")
                with st.expander("📋 copy"):
                    st.code(_card_text(r, "predicted_label", "2024"), language=None)

    with st.expander("Search syntax tips"):
        st.markdown(
            """
- Phrases: `"remote code execution"`
- Prefix: `log4j*`
- Field scoping: `vendor: apache  product: httpd`
- Exact CVE (fastest): use the **Exact CVE** box (`CVE-2024-12345`)
"""
        )

    with st.expander("📋 copy results as text"):
        st.code(_results_txt, language=None)

with tab_ai:
    _running = st.session_state.get("ai_running")
    ar = st.session_state.get("ai_result")
    if _running:
        st.info(f"Running AI analysis for **{_running['cve']}**…")
    elif not ar:
        st.info("Click 🤖 on any CVE result to generate an AI analysis.")
    else:
        tcol1, tcol2 = st.columns([10, 1])
        with tcol1:
            st.markdown(f"**{ar['cve']}** &nbsp;<span style='font-size:0.8rem;color:#888;'>{ar['model']}</span>", unsafe_allow_html=True)
        with tcol2:
            if st.button("✕", key="ai_dismiss", help="Clear"):
                del st.session_state["ai_result"]
                st.rerun()
        if ar.get("error"):
            st.error(ar["error"])
            if ar.get("detail"):
                with st.expander("Error detail"):
                    st.code(ar["detail"])
        else:
            with st.expander("Prompt used"):
                st.text(ar["prompt"])
            st.markdown(ar["response"])
            with st.expander("📋 copy"):
                st.code(ar["response"], language=None)

    st.divider()
    st.markdown("**Edit prompt**")
    edited_prompt = st.text_area(
        "Prompt template",
        value=prompt_text,
        height=180,
        label_visibility="collapsed",
        key="prompt_editor",
    )
    if st.button("💾 Save prompt"):
        prompt_path = _resolve_input_path(prompt_file)
        pathlib.Path(prompt_path).write_text(edited_prompt, encoding="utf-8")
        prompt_text = edited_prompt
        st.toast("Prompt saved.", icon="✓")

with tab_history:
    if not history:
        st.info("No AI queries yet. Use the 🤖 button on any CVE result.")
    else:
        hcol1, hcol2 = st.columns([1, 1])
        with hcol1:
            if st.button("Clear history"):
                st.session_state["ai_history"] = []
                st.rerun()
        with hcol2:
            def _build_history_txt(history) -> str:
                sep = "=" * 60
                parts = []
                for hr in history:
                    lines = [f"CVE: {hr['cve']}", f"Model: {hr['model']}", ""]
                    if hr.get("error"):
                        lines += [f"ERROR: {hr['error']}", ""]
                        if hr.get("detail"):
                            lines += [hr["detail"], ""]
                    else:
                        lines += ["Prompt:", hr.get("prompt", ""), "", "Response:", hr.get("response", ""), ""]
                    parts.append("\n".join(lines))
                return f"\n{sep}\n\n".join(parts)
            st.download_button(
                "⬇ Export history (TXT)",
                data=_build_history_txt(history),
                file_name="ai_history.txt",
                mime="text/plain",
            )
        for i, hr in enumerate(reversed(history)):
            label = f"{hr['cve']}  —  {hr['model']}"
            if hr.get("error"):
                label += "  ⚠️"
            with st.expander(label):
                if hr.get("error"):
                    st.error(hr["error"])
                    if hr.get("detail"):
                        st.code(hr["detail"])
                else:
                    with st.expander("Prompt", expanded=False):
                        st.text(hr["prompt"])
                    st.markdown(hr["response"])

# -------- AI request handler --------
if st.session_state.get("ai_running"):
    pending = st.session_state.pop("ai_running")
    if not openrouter_api_key:
        st.warning("Enter your OpenRouter API key in the **AI** sidebar tab to use AI analysis.")
    else:
        with st.spinner(f"Asking AI about {pending['cve']}…"):
            try:
                ai_response = _ask_perplexity(openrouter_api_key, _active_model, prompt_text, pending)
                result = {
                    "cve": pending["cve"],
                    "model": _active_model,
                    "prompt": prompt_text,
                    "response": ai_response,
                }
                LOGGER.info("AI query: cve=%s model=%s", pending["cve"], _active_model)
            except Exception as e:
                import traceback
                result = {
                    "cve": pending["cve"],
                    "model": _active_model,
                    "prompt": prompt_text,
                    "error": str(e),
                    "detail": traceback.format_exc(),
                }
                LOGGER.error("AI request failed: cve=%s error=%s", pending.get("cve"), e)
        st.session_state["ai_result"] = result
        st.session_state.setdefault("ai_history", []).append(result)
        st.rerun()

