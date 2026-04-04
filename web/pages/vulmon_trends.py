import asyncio
import csv
import os
import pathlib
import re
from datetime import date, timedelta
from html import unescape

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from bs4 import BeautifulSoup
from plotly.subplots import make_subplots

HEAD_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "HEAD"

RATING_COLOR = {"fire": "#ff0000", "hot": "#ff0000", "warm": "#ffd700", "cold": "#1f77b4", "sunspot": "#36454f"}
LINE_COLORS = [
    "#e6194b", "#3cb44b", "#4363d8", "#f58231", "#911eb4",
    "#42d4f4", "#f032e6", "#bfef45", "#fabed4", "#469990",
]


def _get_event_loop():
    """Set up a ProactorEventLoop with nest_asyncio — deferred to first call."""
    import nest_asyncio
    from playwright.async_api import async_playwright  # noqa: F401 — ensure installed

    if not isinstance(asyncio.get_event_loop_policy(), asyncio.WindowsProactorEventLoopPolicy):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    nest_asyncio.apply(loop)
    return loop


@st.cache_data(show_spinner="Fetching Vulmon trends...")
def fetch_vulmon_html():
    from playwright.async_api import async_playwright

    loop = _get_event_loop()

    async def _fetch():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=False)
            page = await browser.new_page()
            await page.goto("https://vulmon.com/trends", wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_selector("table", timeout=20000)
            html = await page.content()
            await browser.close()
            return html

    return loop.run_until_complete(_fetch())


def parse_cves(html):
    soup = BeautifulSoup(html, "html.parser")
    cve_table = soup.find("table", class_="ui small table")
    if not cve_table:
        return pd.DataFrame()
    cve_records = []
    for row in cve_table.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) < 2:
            continue
        link_tag = cols[0].find("a")
        cve_id = link_tag.get_text(strip=True) if link_tag else cols[0].get_text(strip=True)
        url = "https://vulmon.com" + link_tag["href"] if link_tag and link_tag.get("href") else None
        description = unescape(cols[1].get_text(strip=True))
        cve_records.append({"cve_id": cve_id, "description": description, "url": url})
    return pd.DataFrame(cve_records)


def parse_activity(html):
    today = date.today()
    NUM_DAYS = 22
    dates = [today - timedelta(days=NUM_DAYS - 1 - i) for i in range(NUM_DAYS)]
    datasets_match = re.search(r"datasets:\s*\[(.+?)\]\s*\n", html, re.DOTALL)
    records = []
    if datasets_match:
        raw = datasets_match.group(1)
        for m in re.finditer(r"\{\s*label:\s*'([^']+)',\s*data:\[([^\]]+)\]", raw):
            cve_id = m.group(1)
            values = [int(x.strip()) for x in m.group(2).split(",")]
            for d, val in zip(dates, values):
                records.append({"cve_id": cve_id, "date": d, "activity": val})
    return pd.DataFrame(records)


def cross_reference(df_cves, df_activity):
    cve_ids = set(df_cves["cve_id"])

    clean_2025 = {}
    path_2025 = HEAD_DIR / "2025-processed-clean.txt"
    if path_2025.exists():
        with open(path_2025, encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                if row and row[0] in cve_ids:
                    rating = row[-3].strip() if len(row) >= 3 else None
                    clean_2025[row[0]] = rating if rating in ("hot", "warm", "cold", "fire", "sunspot") else "found"

    csvs_2026 = {}
    for csv_path in sorted(HEAD_DIR.glob("2026-*.csv")):
        with open(csv_path, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                if row.get("cveid") in cve_ids:
                    csvs_2026[row["cveid"]] = row.get("rating", "found")

    results = []
    for cve_id in df_cves["cve_id"]:
        rating = clean_2025.get(cve_id) or csvs_2026.get(cve_id)
        results.append({"cve_id": cve_id, "rating": rating})

    df_xref = pd.DataFrame(results)

    if not df_activity.empty:
        matched_ids = df_xref.loc[df_xref["rating"].notna(), "cve_id"]
        activity_stats = (
            df_activity[df_activity["cve_id"].isin(matched_ids)]
            .groupby("cve_id")
            .apply(lambda g: pd.Series({
                "first_active":   g.loc[g["activity"] > 0, "date"].min() if (g["activity"] > 0).any() else None,
                "peak_date":      g.loc[g["activity"].idxmax(), "date"],
                "last_active":    g.loc[g["activity"] > 0, "date"].max() if (g["activity"] > 0).any() else None,
                "total_activity": g["activity"].sum(),
            }), include_groups=False)
            .reset_index()
        )
        df_xref = df_xref.merge(activity_stats, on="cve_id", how="left")

    # Ensure date/activity columns always exist even if no activity data was merged
    for col in ("first_active", "peak_date", "last_active", "total_activity"):
        if col not in df_xref.columns:
            df_xref[col] = None

    today = date.today()
    in_matched = df_xref["rating"].notna()
    for col in ("first_active", "peak_date", "last_active"):
        df_xref.loc[in_matched & df_xref[col].isna(), col] = today
    df_xref.loc[in_matched & df_xref["total_activity"].isna(), "total_activity"] = 1

    return df_xref


def build_chart(df_xref, df_activity):
    matched = df_xref[df_xref["rating"].notna()]
    matched_ids = matched["cve_id"].tolist()
    activity_matched = df_activity[df_activity["cve_id"].isin(matched_ids)]

    fig = make_subplots(
        rows=2, cols=1,
        row_heights=[0.4, 0.6],
        subplot_titles=["Total Activity Count, CVE Rating", "CVE Activity by Date"],
        vertical_spacing=0.2,
    )

    bar_df = matched.sort_values("total_activity")
    fig.add_trace(
        go.Bar(
            x=bar_df["total_activity"],
            y=bar_df["cve_id"],
            orientation="h",
            marker_color=[RATING_COLOR.get(r, "#aaa") for r in bar_df["rating"]],
            text=bar_df["rating"],
            textposition="outside",
            textfont=dict(size=18),
            hovertemplate="%{y}<br>Activity: %{x}<br>Rating: %{text}<extra></extra>",
            showlegend=False,
        ),
        row=1, col=1,
    )

    for i, cve_id in enumerate(matched_ids):
        cve_data = activity_matched[activity_matched["cve_id"] == cve_id]
        if cve_data.empty:
            continue
        fig.add_trace(
            go.Scatter(
                x=cve_data["date"],
                y=cve_data["activity"],
                mode="lines+markers",
                name=cve_id,
                line=dict(color=LINE_COLORS[i % len(LINE_COLORS)], width=2),
                hovertemplate="%{fullData.name}<br>%{x}<br>Activity: %{y}<extra></extra>",
            ),
            row=2, col=1,
        )

    n_bars = len(matched)
    fig.update_layout(
        height=max(700, n_bars * 60 + 400),
        title=dict(text="Trending CVEs by Activity Count", font=dict(size=18)),
        showlegend=True,
        legend=dict(x=0, y=-0.15, yanchor="top", orientation="h", font=dict(size=14)),
        font=dict(size=24),
    )
    fig.update_xaxes(title_text="Activity", row=1, col=1, tickfont=dict(size=13))
    fig.update_yaxes(tickfont=dict(size=13), row=1, col=1)
    fig.update_xaxes(title_text="Date", row=2, col=1, tickfont=dict(size=13))
    fig.update_yaxes(title_text="Activity", row=2, col=1, tickfont=dict(size=13))
    return fig


def render():
    st.title("CAUSALITY Rated CVEs Trending on Vulmon")

    if st.button("Refresh data"):
        st.cache_data.clear()

    html = fetch_vulmon_html()
    df_cves = parse_cves(html)
    df_activity = parse_activity(html)
    df_xref = cross_reference(df_cves, df_activity)

    matched = df_xref[df_xref["rating"].notna()]
    col1, col2 = st.columns(2)
    col1.metric("Trending CVE Count", len(df_cves))
    col2.metric("Matched in CAUSALITY Ratings", len(matched))

    st.plotly_chart(build_chart(df_xref, df_activity), use_container_width=True)

    st.subheader("Trending CVEs with CAUSALITY Ratings")
    df_linked = matched.reset_index(drop=True).copy()
    df_linked["cve_id"] = df_linked["cve_id"].apply(
        lambda cid: f'<a href="/?cve_id={cid}" target="_blank">{cid}</a>'
    )
    st.markdown(df_linked.to_html(index=False, escape=False), unsafe_allow_html=True)

    st.subheader("All Trending CVEs")
    st.markdown("""
    <style>
    .cve-list, .cve-list * { overflow: visible !important; white-space: normal !important; }
    [data-testid="stMarkdownContainer"] { overflow: visible !important; }
    </style>
    """, unsafe_allow_html=True)
    cards = []
    for _, row in df_cves.iterrows():
        url = row.get("url") or ""
        link = f'<a href="{url}" target="_blank">{row["cve_id"]}</a>' if url else f'<strong>{row["cve_id"]}</strong>'
        cards.append(
            f'<div style="padding:10px 0;border-bottom:1px solid #ddd">'
            f'<div style="font-weight:bold;margin-bottom:4px">{link}</div>'
            f'<div style="font-size:0.9em;line-height:1.5;white-space:normal;overflow:visible">{row["description"]}</div>'
            f'</div>'
        )
    st.markdown(f'<div class="cve-list">{"".join(cards)}</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Vulmon Trends", layout="wide")
    render()
