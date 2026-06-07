"""
Smoke tests for the Streamlit app pages.

Catches NameError / AttributeError bugs at runtime without a browser.

Run from the web/ directory:
    python -m pytest test_smoke.py -v
"""
import contextlib
import importlib.util
import pathlib
import sys
import unittest
from datetime import date
from unittest.mock import MagicMock, patch

import pandas as pd

HERE = pathlib.Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Streamlit stub
# ---------------------------------------------------------------------------

class _CacheDataStub:
    """Mimics st.cache_data: usable as @st.cache_data(...) decorator and has .clear()."""
    def __call__(self, **kw):
        return lambda fn: fn
    def clear(self):
        pass


def _make_st_stub():
    st = MagicMock()
    # cache_data must be a decorator factory AND have .clear()
    st.cache_data = _CacheDataStub()
    # buttons return False so conditional branches that call st.cache_data.clear() are skipped
    st.button = MagicMock(return_value=False)
    # expander must use nullcontext so exceptions inside `with st.expander(...)`
    # are NOT suppressed (MagicMock.__exit__ is truthy, which suppresses them)
    st.expander = lambda *a, **kw: contextlib.nullcontext()
    # columns(n) must return an unpackable tuple of n mocks
    st.columns = lambda spec, **kw: tuple(
        MagicMock() for _ in range(spec if isinstance(spec, int) else len(spec))
    )
    return st


# ---------------------------------------------------------------------------
# HTML fixture — minimal valid Vulmon page structure
# ---------------------------------------------------------------------------

# parse_activity uses: datasets:\s*\[(.+?)\]\s*\n  (DOTALL, lazy)
# The outer ] must end the line so the lazy match reaches it.
_ACT = ",".join(["5"] * 22)
VULMON_HTML = (
    "<html><body>\n"
    '<table class="ui small table">\n'
    "  <tr>\n"
    '    <td><a href="/vulnerabilities/CVE-2026-99999">CVE-2026-99999</a></td>\n'
    "    <td>Smoke-test CVE description</td>\n"
    "  </tr>\n"
    "</table>\n"
    "<script>\n"
    f"datasets: [{{ label: 'CVE-2026-99999', data:[{_ACT}] }}]\n"
    "</script>\n"
    "</body></html>"
)


# ---------------------------------------------------------------------------
# cross_reference stubs (avoid filesystem / DB access)
# ---------------------------------------------------------------------------

_TODAY = date.today()
_XREF_ATTRS = dict(
    rows_2024_seen=0, matches_2024=0,
    rows_2025_seen=0, matches_2025=0,
    rows_2026_seen=1, matches_2026=1,
)


def _xref_with_match(df_cves, df_activity):
    df = pd.DataFrame([{
        "cve_id": "CVE-2026-99999",
        "rating": "hot",
        "match_source": "smoke:test",
        "first_active": _TODAY,
        "peak_date": _TODAY,
        "last_active": _TODAY,
        "total_activity": 5,
    }])
    df.attrs.update(_XREF_ATTRS)
    return df


def _xref_all_unmatched(df_cves, df_activity):
    """All CVEs unmatched — exercises the `unmatched` variable path."""
    df = pd.DataFrame([{
        "cve_id": "CVE-2026-99999",
        "rating": None,
        "match_source": "",
        "first_active": None,
        "peak_date": None,
        "last_active": None,
        "total_activity": None,
    }])
    df.attrs.update(_XREF_ATTRS | {"rows_2026_seen": 0, "matches_2026": 0})
    return df


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestVulmonTrendsSmoke(unittest.TestCase):
    """Smoke-test vulmon_trends.render()."""

    def _load(self):
        """Import vulmon_trends fresh with the Streamlit stub installed."""
        stub = _make_st_stub()
        sys.modules["streamlit"] = stub
        for key in list(sys.modules):
            if "vulmon_trends" in key:
                del sys.modules[key]
        spec = importlib.util.spec_from_file_location(
            "vulmon_trends", HERE / "pages" / "vulmon_trends.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_render_with_matches(self):
        vt = self._load()
        with (
            patch.object(vt, "fetch_vulmon_html", return_value=VULMON_HTML),
            patch.object(vt, "cross_reference", side_effect=_xref_with_match),
        ):
            vt.render()

    def test_render_all_unmatched(self):
        """render() must not raise when no CVEs are rated."""
        vt = self._load()
        with (
            patch.object(vt, "fetch_vulmon_html", return_value=VULMON_HTML),
            patch.object(vt, "cross_reference", side_effect=_xref_all_unmatched),
        ):
            vt.render()


if __name__ == "__main__":
    unittest.main()
