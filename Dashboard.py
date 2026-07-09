#!/usr/bin/env python3
"""
ASM Dashboard (read-only, single-customer) — Streamlit over asm_findings.db
--------------------------------------------------------------------------
Read-only console: the database is opened in SQLite read-only mode, so this
dashboard can never scan or write. Scanning stays on the CLI.

  * Pick one customer (sidebar) — the whole console is that customer.
  * "Current scan" — the latest scan's live picture: posture, inventory,
    open services, technologies, cloud attribution, with charts.
  * "Scan history" — a date-grouped discovery changelog.

Run:
    source ~/dashboard-venv/bin/activate
    streamlit run asm_dashboard.py -- --db ~/asm_findings.db
    # reach it over Tailscale / SSH tunnel — never a public IP.
"""

import argparse
import json
import os
from collections import Counter

import pandas as pd

DEFAULT_DB = "asm_findings.db"


# ===========================================================================
# Read-only data access
# ===========================================================================
def ro_connect(db_path):
    import sqlite3
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def fetch(db_path, sql, params=()):
    with ro_connect(db_path) as conn:
        return pd.read_sql_query(sql, conn, params=params)


def list_clients(db_path):
    return fetch(db_path, "SELECT DISTINCT client_id FROM findings ORDER BY client_id")["client_id"].tolist()


def latest_scan(db_path, client):
    df = fetch(db_path,
               "SELECT scan_id, scan_time, run_folder, domain FROM scans "
               "WHERE client_id=? ORDER BY scan_time DESC LIMIT 1", (client,))
    return None if df.empty else df.iloc[0]


def scans_list(db_path, client):
    return fetch(db_path,
                 "SELECT scan_time AS 'date_time', scan_id, domain, run_folder AS evidence "
                 "FROM scans WHERE client_id=? ORDER BY scan_time DESC", (client,))


def _detail(row_detail):
    if not row_detail:
        return {}
    try:
        return json.loads(row_detail)
    except Exception:  # noqa: BLE001
        return {}


def open_ports(db_path, client, scan_id):
    raw = fetch(db_path,
                "SELECT hostname, ip, port, provider, detail FROM findings "
                "WHERE client_id=? AND finding_type='host_service' AND scan_id=? "
                "ORDER BY hostname, port", (client, scan_id))
    rows = []
    for _, r in raw.iterrows():
        d = _detail(r["detail"])
        tech = d.get("tech") or []
        rows.append({
            "hostname": r["hostname"],
            "ip": r["ip"],
            "port": r["port"],
            "status": d.get("status_code"),
            "title": d.get("title"),
            "server": d.get("webserver"),
            "provider": r["provider"],
            "tech": ", ".join(tech) if isinstance(tech, list) else (tech or ""),
        })
    return pd.DataFrame(rows, columns=["hostname", "ip", "port", "status", "title", "server", "provider", "tech"])


def assets(db_path, client, scan_id):
    return fetch(db_path, """
        SELECT hostname,
               MAX(ip) AS ip,
               COALESCE(MAX(CASE WHEN finding_type='cloud' THEN provider END),
                        MAX(CASE WHEN finding_type='host_service' THEN provider END)) AS provider
        FROM findings
        WHERE client_id=? AND scan_id=? AND hostname IS NOT NULL AND hostname!=''
        GROUP BY hostname ORDER BY hostname
    """, (client, scan_id))


def list_subdomains(db_path, client, scan_id):
    return fetch(db_path,
                 "SELECT DISTINCT hostname AS subdomain FROM findings "
                 "WHERE client_id=? AND scan_id=? AND hostname IS NOT NULL AND hostname!='' "
                 "ORDER BY hostname", (client, scan_id))


def list_ips(db_path, client, scan_id):
    return fetch(db_path,
                 "SELECT DISTINCT ip FROM findings "
                 "WHERE client_id=? AND scan_id=? AND ip IS NOT NULL AND ip!='' "
                 "ORDER BY ip", (client, scan_id))


def list_ports(db_path, client, scan_id):
    return fetch(db_path,
                 "SELECT DISTINCT port FROM findings "
                 "WHERE client_id=? AND scan_id=? AND port IS NOT NULL "
                 "ORDER BY port", (client, scan_id))


def port_distribution(db_path, client, scan_id):
    return fetch(db_path,
                 "SELECT CAST(port AS TEXT) AS port, COUNT(*) AS count FROM findings "
                 "WHERE client_id=? AND finding_type='host_service' AND scan_id=? AND port IS NOT NULL "
                 "GROUP BY port ORDER BY count DESC", (client, scan_id))


def technologies(db_path, client, scan_id):
    raw = fetch(db_path,
                "SELECT detail FROM findings "
                "WHERE client_id=? AND finding_type='host_service' AND scan_id=?", (client, scan_id))
    counter = Counter()
    for d in raw["detail"].dropna():
        tech = _detail(d).get("tech") or []
        if isinstance(tech, list):
            for t in tech:
                if t:
                    counter[t] += 1
    return pd.DataFrame(sorted(counter.items(), key=lambda kv: -kv[1]), columns=["technology", "count"])


def cloud_providers_in_use(db_path, client, scan_id=None):
    sql = ("SELECT provider, COUNT(DISTINCT ip) AS hosts FROM findings "
           "WHERE client_id=? AND finding_type='cloud'")
    params = [client]
    if scan_id:
        sql += " AND scan_id=?"
        params.append(scan_id)
    sql += " GROUP BY provider ORDER BY hosts DESC"
    return fetch(db_path, sql, params)


def confirmed_takeovers(db_path, client, scan_id=None):
    sql = ("SELECT hostname, provider AS service, first_seen, last_seen FROM findings "
           "WHERE client_id=? AND finding_type='takeover' AND vulnerable=1")
    params = [client]
    if scan_id:
        sql += " AND scan_id=?"
        params.append(scan_id)
    sql += " ORDER BY last_seen DESC"
    return fetch(db_path, sql, params)


def additions_by_date(db_path, client):
    return fetch(db_path, """
        SELECT substr(first_seen,1,10) AS day, finding_type, COUNT(*) AS count
        FROM findings
        WHERE client_id=? AND NOT (finding_type='takeover' AND vulnerable=0)
        GROUP BY substr(first_seen,1,10), finding_type
        ORDER BY day DESC, finding_type
    """, (client,))


def additions_on_date(db_path, client, day):
    return fetch(db_path, """
        SELECT finding_type, hostname, ip, port, provider
        FROM findings
        WHERE client_id=? AND substr(first_seen,1,10)=?
              AND NOT (finding_type='takeover' AND vulnerable=0)
        ORDER BY finding_type, hostname
    """, (client, day))


# ===========================================================================
# Design system — palette, type, CSS
# ===========================================================================
INK_BG      = "#0f172a"   # deep slate (not hacker-black)
SURFACE     = "#1e293b"
SURFACE_2   = "#172033"
BORDER      = "#334155"
TEXT        = "#e2e8f0"
MUTED       = "#94a3b8"
FAINT       = "#64748b"
ACCENT      = "#38bdf8"   # sky — used with restraint
CRIT        = "#f43f5e"   # rose — confirmed exposure
WARN        = "#fb923c"   # orange — attention
SAFE        = "#34d399"   # emerald — clean / cloud-attributed

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

.stApp {{ background:{INK_BG}; color:{TEXT}; font-family:'Inter',system-ui,sans-serif; }}
h1,h2,h3,h4 {{ font-family:'Space Grotesk',sans-serif !important; color:#f1f5f9 !important; letter-spacing:-0.01em; }}
#MainMenu, footer, [data-testid="stToolbar"] {{ visibility:hidden; }}
section[data-testid="stSidebar"] {{ background:{SURFACE_2}; border-right:1px solid {BORDER}; }}
section[data-testid="stSidebar"] * {{ color:{TEXT}; }}
a, .st-emotion-cache a {{ color:{ACCENT}; }}

.mono {{ font-family:'JetBrains Mono',monospace; }}

.asm-eyebrow {{ font-family:'JetBrains Mono',monospace; font-size:0.70rem; letter-spacing:0.24em;
  text-transform:uppercase; color:{ACCENT}; }}
.asm-title {{ font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:1.7rem; color:#f1f5f9; }}
.asm-sub {{ font-family:'JetBrains Mono',monospace; font-size:0.80rem; color:{FAINT}; margin-top:2px; }}
.asm-rule {{ height:1px; background:{BORDER}; margin:14px 0 4px; }}

.posture {{ border-radius:16px; padding:18px 22px; margin:18px 0 6px; display:flex; align-items:center;
  gap:16px; border:1px solid; }}
.posture-crit {{ background:linear-gradient(100deg,#3a1122,{SURFACE}); border-color:{CRIT}; }}
.posture-ok   {{ background:linear-gradient(100deg,#0e2c23,{SURFACE}); border-color:{SAFE}; }}
.posture-dot {{ width:13px; height:13px; border-radius:50%; flex:none; }}
.posture-state {{ font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:1.05rem; color:#f1f5f9; }}
.posture-msg {{ color:{MUTED}; font-size:0.9rem; margin-top:1px; }}

.kpi-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:16px 0 4px; }}
.kpi {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:16px; padding:18px 20px; }}
.kpi-value {{ font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:2.15rem; line-height:1; }}
.kpi-label {{ margin-top:9px; font-size:0.74rem; color:{MUTED}; text-transform:uppercase; letter-spacing:0.10em; }}

.section-label {{ font-family:'JetBrains Mono',monospace; font-size:0.72rem; letter-spacing:0.20em;
  text-transform:uppercase; color:{FAINT}; margin:30px 0 12px; padding-bottom:8px;
  border-bottom:1px solid {BORDER}; }}

.badge {{ display:inline-block; padding:6px 15px; margin:4px 7px 4px 0; border-radius:999px;
  font-size:0.9rem; font-weight:600; border:1px solid transparent; }}

.callout {{ background:{SURFACE}; border:1px solid {CRIT}; border-left:4px solid {CRIT};
  border-radius:10px; padding:14px 18px; margin:6px 0 2px; }}
.callout-host {{ font-family:'JetBrains Mono',monospace; color:#fecdd3; font-weight:500; }}

[data-testid="stMetric"] {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:16px; padding:16px; }}
[data-testid="stExpander"] {{ border:1px solid {BORDER} !important; border-radius:12px !important;
  background:{SURFACE_2} !important; }}
.stDataFrame {{ border:1px solid {BORDER}; border-radius:12px; overflow:hidden; }}
</style>
"""


def provider_color(name):
    if not name or "unknown" in name.lower() or "non-cloud" in name.lower():
        return FAINT
    return SAFE


def badge_html(text, color):
    return (f"<span class='badge' style='background:{color}22;color:{color};"
            f"border-color:{color}55'>{text}</span>")


def kpi_card(label, value, danger=False, accent=None):
    color = CRIT if danger else (accent or TEXT)
    return (f"<div class='kpi'><div class='kpi-value' style='color:{color}'>{value}</div>"
            f"<div class='kpi-label'>{label}</div></div>")


def alt_theme():
    return {"config": {
        "background": "transparent",
        "view": {"stroke": "transparent"},
        "axis": {"labelColor": MUTED, "titleColor": MUTED, "gridColor": SURFACE,
                 "domainColor": BORDER, "labelFont": "JetBrains Mono", "labelFontSize": 11},
        "axisX": {"grid": False},
    }}


# ===========================================================================
# Pages
# ===========================================================================
def page_current(st, alt, db_path, customer):
    ls = latest_scan(db_path, customer)
    if ls is None:
        st.warning(f"No scans recorded for {customer} yet. "
                   f"Ingest one:  python3 asm_db.py ingest --latest --client {customer}")
        return

    scan_id, scan_time = ls["scan_id"], ls["scan_time"]

    # Header
    st.markdown(
        f"<span class='asm-eyebrow'>Attack Surface</span>"
        f"<div class='asm-title'>{customer}</div>"
        f"<div class='asm-sub'>latest scan {scan_time} · {ls['run_folder']}</div>"
        f"<div class='asm-rule'></div>",
        unsafe_allow_html=True)

    ports_df = open_ports(db_path, customer, scan_id)
    assets_df = assets(db_path, customer, scan_id)
    tech_df = technologies(db_path, customer, scan_id)
    takeovers_df = confirmed_takeovers(db_path, customer, scan_id)
    n_take = len(takeovers_df)

    # Posture banner (signature element)
    if n_take > 0:
        st.markdown(
            f"<div class='posture posture-crit'>"
            f"<span class='posture-dot' style='background:{CRIT};box-shadow:0 0 14px {CRIT}'></span>"
            f"<div><div class='posture-state'>ACTION REQUIRED</div>"
            f"<div class='posture-msg'>{n_take} confirmed subdomain takeover"
            f"{'s' if n_take > 1 else ''} — verify and report.</div></div></div>",
            unsafe_allow_html=True)
        for _, r in takeovers_df.iterrows():
            svc = f" · {r['service']}" if r["service"] else ""
            st.markdown(f"<div class='callout'><span class='callout-host'>{r['hostname']}</span>"
                        f"<span style='color:{MUTED}'>{svc}</span></div>", unsafe_allow_html=True)
    else:
        st.markdown(
            f"<div class='posture posture-ok'>"
            f"<span class='posture-dot' style='background:{SAFE};box-shadow:0 0 14px {SAFE}'></span>"
            f"<div><div class='posture-state'>MONITORED</div>"
            f"<div class='posture-msg'>No confirmed exposures in the latest scan.</div></div></div>",
            unsafe_allow_html=True)

    # KPI cards
    st.markdown(
        "<div class='kpi-grid'>"
        + kpi_card("Assets", len(assets_df))
        + kpi_card("Open services", len(ports_df))
        + kpi_card("Technologies", len(tech_df))
        + kpi_card("Confirmed takeovers", n_take, danger=(n_take > 0),
                   accent=SAFE if n_take == 0 else None)
        + "</div>",
        unsafe_allow_html=True)

    # Cloud attribution
    in_use = cloud_providers_in_use(db_path, customer, scan_id)
    if not in_use.empty:
        st.markdown("<div class='section-label'>Cloud attribution</div>", unsafe_allow_html=True)
        st.markdown(
            "".join(badge_html(f"{r['provider']} · {int(r['hosts'])}", provider_color(r["provider"]))
                    for _, r in in_use.iterrows()),
            unsafe_allow_html=True)

    # Open services + port chart
    st.markdown("<div class='section-label'>Open ports & live services</div>", unsafe_allow_html=True)
    left, right = st.columns([2, 1])
    with left:
        st.dataframe(ports_df, use_container_width=True, hide_index=True, height=340)
    with right:
        pdist = port_distribution(db_path, customer, scan_id)
        if not pdist.empty and alt is not None:
            chart = (alt.Chart(pdist).mark_bar(color=ACCENT, cornerRadiusEnd=3)
                     .encode(x=alt.X("count:Q", title=None),
                             y=alt.Y("port:N", sort="-x", title=None))
                     .properties(height=340))
            st.altair_chart(chart, use_container_width=True)
        elif not pdist.empty:
            st.bar_chart(pdist.set_index("port"))

    # Technologies — horizontal bars (fixes crowded x-axis)
    st.markdown("<div class='section-label'>Technologies in use</div>", unsafe_allow_html=True)
    if tech_df.empty:
        st.info("No technologies fingerprinted in this scan.")
    else:
        top = tech_df.head(15)
        if alt is not None:
            chart = (alt.Chart(top).mark_bar(color=SAFE, cornerRadiusEnd=3)
                     .encode(x=alt.X("count:Q", title=None),
                             y=alt.Y("technology:N", sort="-x", title=None))
                     .properties(height=max(220, 26 * len(top))))
            st.altair_chart(chart, use_container_width=True)
        else:
            st.bar_chart(top.set_index("technology"))

    # Subdomain assets
    st.markdown("<div class='section-label'>Subdomain assets</div>", unsafe_allow_html=True)
    st.dataframe(assets_df, use_container_width=True, hide_index=True)


def page_history(st, alt, db_path, customer):
    st.markdown(
        f"<span class='asm-eyebrow'>History</span>"
        f"<div class='asm-title'>{customer}</div>"
        f"<div class='asm-rule'></div>",
        unsafe_allow_html=True)

    st.markdown("<div class='section-label'>Discovery changelog</div>", unsafe_allow_html=True)
    st.caption("Grouped by date — what was newly discovered each scan day. Expand for detail.")

    by_date = additions_by_date(db_path, customer)
    if by_date.empty:
        st.info("No findings recorded yet.")
    else:
        for day in by_date["day"].dropna().unique():
            rows = by_date[by_date["day"] == day]
            total = int(rows["count"].sum())
            summary = " · ".join(f"{int(r['count'])} {r['finding_type']}" for _, r in rows.iterrows())
            with st.expander(f"{day}    +{total} discovered    —    {summary}"):
                st.dataframe(additions_on_date(db_path, customer, day),
                             use_container_width=True, hide_index=True)

    st.markdown("<div class='section-label'>Scans performed</div>", unsafe_allow_html=True)
    sl = scans_list(db_path, customer)
    if sl.empty:
        st.info("No scans recorded yet.")
    else:
        st.dataframe(sl, use_container_width=True, hide_index=True)


# ===========================================================================
# App
# ===========================================================================
def run_ui(db_path):
    import streamlit as st
    try:
        import altair as alt
        alt.themes.register("asm", alt_theme)
        alt.themes.enable("asm")
    except Exception:  # noqa: BLE001
        alt = None

    st.set_page_config(page_title="ASM Console", layout="wide", page_icon="◆")
    st.markdown(CSS, unsafe_allow_html=True)

    if not os.path.exists(db_path):
        st.error(f"Database not found: {db_path}. "
                 f"Ingest a scan first: python3 asm_db.py ingest --latest --client <domain>")
        st.stop()

    with st.sidebar:
        st.markdown("<div class='asm-eyebrow'>ASM Console</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        db_path = st.text_input("Database", value=db_path)
        try:
            clients = list_clients(db_path)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not read the database: {exc}")
            st.stop()
        if not clients:
            st.warning("No data yet. Ingest a scan to begin.")
            st.stop()
        customer = st.selectbox("Customer", clients)
        page = st.radio("View", ["Current scan", "Scan history"])
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    if page == "Current scan":
        page_current(st, alt, db_path, customer)
    else:
        page_history(st, alt, db_path, customer)


def main():
    parser = argparse.ArgumentParser(description="ASM read-only dashboard.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Database file (default: {DEFAULT_DB})")
    args, _ = parser.parse_known_args()
    run_ui(args.db)


if __name__ == "__main__":
    main()
