import streamlit as st
from pathlib import Path
from io import StringIO
import tempfile
import shutil
import os
import re

# Set page config (minimal for speed)
st.set_page_config(
    page_title="CVE Search",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Minimal styling for performance
st.markdown("""
<style>
    .main .block-container { padding-top: 1rem; padding-bottom: 1rem; }
</style>
""", unsafe_allow_html=True)

DATA_PATH = Path(__file__).parent / "2025/September/2025-ratings-sep-14.txt"

# Build TSV bytes from rows and optional header

def rows_to_tsv_bytes(rows, header=None):
    out = StringIO()
    if header:
        out.write("\t".join(header) + "\n")
    for r in rows:
        out.write("\t".join(r) + "\n")
    return out.getvalue().encode('utf-8')

# Single-pass search that returns header, results, and optional error.
# Supports exact match on CVE column if requested.

def search_tsv_with_header(path: Path, query: str, case_sensitive: bool, limit: int, cve_only: bool, exact_cve: bool):
    if not query:
        return [], [], None
    results = []
    header = []
    err = None

    # Normalize query by mode
    q = query if case_sensitive else query.lower()

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            first = f.readline()
            header = [c.strip() for c in first.rstrip('\n\r').split('\t')] if first else []

            # Determine CVE column index from header if possible
            cve_idx = None
            if header:
                lowered = [h.lower() for h in header]
                if 'cve' in lowered:
                    cve_idx = lowered.index('cve')

            # Fallback: many files have an index then CVE as second column
            if cve_idx is None:
                cve_idx = 1

            for line in f:
                line_stripped = line.rstrip('\n\r')

                if cve_only or exact_cve:
                    parts = line_stripped.split('\t')
                    field = parts[cve_idx] if len(parts) > cve_idx else ""
                    hay = field if case_sensitive else field.lower()
                else:
                    hay = line_stripped if case_sensitive else line_stripped.lower()

                if (exact_cve and hay == q) or (not exact_cve and q in hay):
                    row = [c.strip() for c in line_stripped.split('\t')]
                    results.append(row)
                    if len(results) >= limit:
                        break
    except FileNotFoundError:
        err = f"File not found: {path}"
    except Exception as e:
        err = f"Search error: {e}"

    return header, results, err

# Ensure a fast local copy for searching (use session_state to avoid repeated copies)

def ensure_local_copy(src: Path, enable_cache: bool) -> Path:
    if not enable_cache:
        return src
    try:
        stat = src.stat()
    except FileNotFoundError:
        return src
    # Session cache key
    key_path = "cached_path"
    key_mtime = "cached_src_mtime"
    key_size = "cached_src_size"

    # If we already cached and mtime/size match, reuse
    if (
        key_path in st.session_state and
        key_mtime in st.session_state and
        key_size in st.session_state and
        st.session_state[key_mtime] == stat.st_mtime and
 
        st.session_state[key_size] == stat.st_size and
        Path(st.session_state[key_path]).exists()
    ):
        return Path(st.session_state[key_path])

    # Copy to temp dir
    tmp_dir = Path(tempfile.gettempdir()) / "cve_search_cache"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    dst = tmp_dir / f"{src.stem}-{int(stat.st_mtime)}-{stat.st_size}.tsv"
    if not dst.exists():
        try:
            with open(src, 'rb') as rf, open(dst, 'wb') as wf:
                shutil.copyfileobj(rf, wf, length=1024 * 1024)  # 1MB buffer
        except Exception:
            return src  # fallback
    # Save cache info
    st.session_state[key_path] = str(dst)
    st.session_state[key_mtime] = stat.st_mtime
    st.session_state[key_size] = stat.st_size
    return dst


def main():
    st.title("🔍 CVE Search (No DataFrame)")
    st.caption("Type a query and search the TSV file directly. No file access occurs until you click Search.")

    # Options
    st.sidebar.header("Options")
    use_local_cache = st.sidebar.checkbox("Speed up searches by caching a local copy", value=True)

    # Debug info
    with st.sidebar.expander("Debug", expanded=False):
        exists = DATA_PATH.exists()
        size = DATA_PATH.stat().st_size if exists else 0
        st.write({
            "data_path": str(DATA_PATH),
            "exists": exists,
            "size_bytes": size,
        })

    # Search controls
    with st.form("search_form"):
        query = st.text_input("Search string", placeholder="e.g., CVE-2025-0101 or vendor name", value="")
        case_sensitive = st.checkbox("Case sensitive", value=False)
        cve_only = st.checkbox("Search only CVE ID column (fast)", value=False)
        limit = st.number_input("Max results", min_value=1, max_value=5000, value=200, step=50)
        submitted = st.form_submit_button("Search")

    # Auto-detect exact CVE pattern for fast exact match
    exact_cve = False
    if query:
        if re.fullmatch(r"(?i)cve-\d{4}-\d{4,7}", query.strip(), flags=0):
            exact_cve = True
            # exact match ignores cve_only toggle and uses the CVE column
            cve_only = True
            if not case_sensitive:
                query = query.lower()

    # Early validation
    if submitted and not query.strip():
        st.warning("Please enter a search string.")

    header, rows, err = [], [], None
    if submitted and query.strip():
        target = ensure_local_copy(DATA_PATH, enable_cache=use_local_cache)
        with st.spinner(f"Searching {'local cache' if target != DATA_PATH else 'file'}..."):
            header, rows, err = search_tsv_with_header(target, query.strip(), case_sensitive, int(limit), cve_only, exact_cve)
        if err:
            st.error(err)
        else:
            mode = "CVE-only exact" if exact_cve else ("CVE-only" if cve_only else "Full-row contains")
            st.write(f"Mode: {mode}. Found {len(rows)} matching row(s). Showing up to {min(len(rows), int(limit))}.")

    # Preview table
    st.subheader("Results Preview")
    preview = rows[:5]
    if header and preview:
        mapped = [ {header[i] if i < len(header) else f"col_{i+1}": (r[i] if i < len(r) else "") for i in range(max(len(header), len(r)))} for r in preview ]
        st.table(mapped)
    elif preview:
        max_len = max(len(r) for r in preview)
        gen_cols = [f"col_{i+1}" for i in range(max_len)]
        mapped = [ {gen_cols[i]: (r[i] if i < len(r) else "") for i in range(max_len)} for r in preview ]
        st.table(mapped)
    elif submitted and not err:
        st.info("No matches found.")

    # Download all matched rows
    st.sidebar.download_button(
        label="Download Matched Rows (TSV)",
        data=rows_to_tsv_bytes(rows, header=header if header else None),
        file_name="cve_search_results.tsv",
        mime="text/tab-separated-values",
        disabled=(len(rows) == 0),
    )

if __name__ == "__main__":
    main()
