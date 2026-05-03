import sqlite3
import sys
import shutil
import types
import uuid
from datetime import date
from pathlib import Path

import pandas as pd


WEB_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = WEB_DIR.parent
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

plotly_module = types.ModuleType("plotly")
graph_objects_module = types.ModuleType("plotly.graph_objects")
subplots_module = types.ModuleType("plotly.subplots")
graph_objects_module.Bar = object
graph_objects_module.Scatter = object
subplots_module.make_subplots = lambda *args, **kwargs: None
sys.modules.setdefault("plotly", plotly_module)
sys.modules.setdefault("plotly.graph_objects", graph_objects_module)
sys.modules.setdefault("plotly.subplots", subplots_module)

from pages import vulmon_trends as vt  # noqa: E402


def write_text(path: Path, text: str):
    path.write_text(text, encoding="utf-8")


def local_tmp_dir():
    path = ROOT_DIR / "var" / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path


def test_parse_cves_escapes_descriptions_and_keeps_urls():
    html = """
    <table class="ui small table">
      <tr>
        <td><a href="/cve/CVE-2026-0001">CVE-2026-0001</a></td>
        <td>Vendor &amp; product issue</td>
      </tr>
      <tr>
        <td>CVE-2025-0002</td>
        <td>No link</td>
      </tr>
    </table>
    """

    df = vt.parse_cves(html)

    assert df["cve_id"].tolist() == ["CVE-2026-0001", "CVE-2025-0002"]
    assert df.loc[0, "description"] == "Vendor & product issue"
    assert df.loc[0, "url"] == "https://vulmon.com/cve/CVE-2026-0001"
    assert pd.isna(df.loc[1, "url"])


def test_parse_cves_finds_cve_table_without_specific_classes():
    html = """
    <table class="layout"><tr><td>Other</td></tr></table>
    <table class="changed">
      <tr>
        <td><a href="/cve/CVE-2026-1111">CVE-2026-1111</a></td>
        <td>Changed markup</td>
      </tr>
    </table>
    """

    df = vt.parse_cves(html)

    assert df[["cve_id", "description"]].to_dict("records") == [
        {"cve_id": "CVE-2026-1111", "description": "Changed markup"}
    ]


def test_parse_cves_returns_expected_empty_columns_when_no_table():
    df = vt.parse_cves("<html><body>No trend table today</body></html>")

    assert df.empty
    assert df.columns.tolist() == ["cve_id", "description", "url"]


def test_cloudflare_challenge_detection():
    html = """
    <html><body>
    Just a moment... Performing security verification.
    This website uses a security service to protect against malicious bots.
    Performance and Security by Cloudflare.
    </body></html>
    """

    assert vt._looks_like_cloudflare_challenge(html)
    assert not vt._looks_like_cloudflare_challenge("<table><tr><td>CVE-2026-1111</td><td>x</td></tr></table>")


def test_vulmon_html_cache_skips_challenge_and_saves_parseable_html(monkeypatch):
    work_dir = local_tmp_dir()
    try:
        cache_path = work_dir / "vulmon_trends.html"
        monkeypatch.setattr(vt, "APP_STATE_DIR", work_dir)
        monkeypatch.setattr(vt, "VULMON_HTML_CACHE", cache_path)

        vt._save_cached_vulmon_html("Cloudflare security verification verify you are not a bot")
        assert not cache_path.exists()

        html = """
        <table>
          <tr><td><a href="/cve/CVE-2026-2222">CVE-2026-2222</a></td><td>Cached row</td></tr>
        </table>
        """
        vt._save_cached_vulmon_html(html)

        assert vt._load_cached_vulmon_html() == html
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def test_fetch_vulmon_html_accepts_interactive_cache_key():
    assert vt.fetch_vulmon_html.__wrapped__.__defaults__ == (False,)


def test_render_defines_unmatched_before_diagnostics():
    source = (WEB_DIR / "pages" / "vulmon_trends.py").read_text(encoding="utf-8")

    assert source.index('unmatched = df_xref[df_xref["rating"].isna()]') < source.index("if not unmatched.empty:")


def test_parse_activity_extracts_chart_datasets():
    html = """
    <script>
    var cfg = {
      datasets: [
        { label: 'CVE-2026-0001', data:[0, 1, 2] },
        { label: 'CVE-2025-0002', data:[5, 0, 0] }
      ]
    }
    </script>
    """

    df = vt.parse_activity(html)

    assert set(df["cve_id"]) == {"CVE-2026-0001", "CVE-2025-0002"}
    assert df[df["cve_id"] == "CVE-2026-0001"]["activity"].tolist() == [0, 1, 2]
    assert df["date"].is_monotonic_increasing is False
    assert df[df["cve_id"] == "CVE-2026-0001"]["date"].tolist() == df["date"].drop_duplicates().tolist()


def test_cross_reference_prefers_2026_then_2025_then_2024_and_tracks_sources(monkeypatch):
    work_dir = local_tmp_dir()
    try:
        head = work_dir / "HEAD"
        state = work_dir / "var" / "causality"
        head.mkdir()
        state.mkdir(parents=True)

        write_text(
            head / "2026-fixture.txt",
            "cveid\tpublished\tvulnerabilityname\tshortdescription\tvendorproject\tproduct\tunused1\tunused2\tunused3\trating\n"
            "CVE-2026-0001\t2026-01-01\tName\tDesc\tVendor\tProduct\t\t\t\tfire\n"
            "CVE-2025-0002\t2026-01-02\tName\tDesc\tVendor\tProduct\t\t\t\thot\n",
        )
        write_text(
            head / "2025-processed-clean.txt",
            "cve,published,title,description,vendor,product,rating\n"
            "CVE-2025-0002,2025-01-01,Title,Desc,Vendor,Product,warm\n"
            "CVE-2024-0003,2025-01-02,Title,Desc,Vendor,Product,cold\n",
        )
        write_text(
            head / "2024-output-may-24.txt",
            "cveID\tPredicted_Label\tvendorProject\tproduct\tdescription\n"
            "CVE-2024-0003\tsunspot\tVendor\tProduct\tDesc\n",
        )

        con = sqlite3.connect(state / "cve.db")
        con.execute("CREATE TABLE preds2026 (cve TEXT, rating TEXT)")
        con.execute("INSERT INTO preds2026 VALUES (?, ?)", ("CVE-2026-9999", "warm"))
        con.commit()
        con.close()

        monkeypatch.setattr(vt, "HEAD_DIR", head)
        monkeypatch.setattr(vt, "DB_PATH", state / "cve.db")

        df_cves = pd.DataFrame(
            {
                "cve_id": ["cve-2026-0001", "CVE-2025-0002", "CVE-2024-0003", "CVE-2026-9999", "CVE-2030-0000"],
                "description": [""] * 5,
                "url": [None] * 5,
            }
        )
        df_activity = pd.DataFrame(
            {
                "cve_id": ["CVE-2026-0001", "CVE-2025-0002", "CVE-2024-0003", "CVE-2026-9999"],
                "date": [date.today()] * 4,
                "activity": [4, 3, 2, 1],
            }
        )

        result = vt.cross_reference(df_cves, df_activity).set_index("cve_id")

        assert result.loc["CVE-2026-0001", "rating"] == "fire"
        assert result.loc["CVE-2026-0001", "match_source"] == "2026:2026-fixture.txt"
        assert result.loc["CVE-2025-0002", "rating"] == "hot"
        assert result.loc["CVE-2025-0002", "match_source"] == "2026:2026-fixture.txt"
        assert result.loc["CVE-2024-0003", "rating"] == "cold"
        assert result.loc["CVE-2024-0003", "match_source"] == "2025:2025-processed-clean.txt"
        assert result.loc["CVE-2026-9999", "rating"] == "warm"
        assert result.loc["CVE-2026-9999", "match_source"] == "2026:cve.db"
        assert pd.isna(result.loc["CVE-2030-0000", "rating"])
        assert result.attrs["matches_2026"] == 3
        assert result.attrs["matches_2025"] == 2
        assert result.attrs["matches_2024"] == 1
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
