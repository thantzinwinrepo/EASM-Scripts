#!/usr/bin/env python3
"""
ASM Dashboard (read-only, single-customer) — Streamlit over asm_findings.db
--------------------------------------------------------------------------
Read-only: the database is opened in SQLite read-only mode, so this dashboard
can never scan or write. Scanning stays on the CLI.

Structure:
  * Pick one customer (top of sidebar) — the whole dashboard is that customer.
  * "Current scan" page  -> the latest scan's live picture: open ports,
    subdomain assets, technologies in use, cloud providers, with charts.
  * "Scan history" page  -> past scans and asset-discovery timeline, with the
    date/time as the leading column.

Run:
    python3 -m venv ~/dashboard-venv
    source ~/dashboard-venv/bin/activate
    pip install streamlit pandas
    streamlit run asm_dashboard.py            # then reach it over Tailscale/SSH-tunnel
    streamlit run asm_dashboard.py -- --db ~/ctibox/data/asm.db
"""

import argparse
import json
import os
from collections import Counter

import pandas as pd

DEFAULT_DB = "asm_findings.db"


# ---------------------------------------------------------------------------
# Read-only data access
# ---------------------------------------------------------------------------
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
    """Past scans, date/time first — for the history page."""
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
    """Live services from the latest scan, with parsed status/title/tech/server."""
    raw = fetch(db_path,
                "SELECT hostname, ip, port, detail FROM findings "
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
            "tech": ", ".join(tech) if isinstance(tech, list) else (tech or ""),
        })
    return pd.DataFrame(rows, columns=["hostname", "ip", "port", "status", "title", "server", "tech"])


def assets(db_path, client, scan_id):
    """One row per subdomain/host seen in the latest scan, with IP + cloud provider."""
    return fetch(db_path, """
        SELECT hostname,
               MAX(ip) AS ip,
               MAX(CASE WHEN finding_type='cloud' THEN provider END) AS provider
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
                 "SELECT port, COUNT(*) AS count FROM findings "
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
    """Per-day counts of newly-discovered findings, grouped by type — the changelog."""
    return fetch(db_path, """
        SELECT substr(first_seen,1,10) AS day, finding_type, COUNT(*) AS count
        FROM findings
        WHERE client_id=? AND NOT (finding_type='takeover' AND vulnerable=0)
        GROUP BY substr(first_seen,1,10), finding_type
        ORDER BY day DESC, finding_type
    """, (client,))


def additions_on_date(db_path, client, day):
    """The specific findings first discovered on a given day (for the expander)."""
    return fetch(db_path, """
        SELECT finding_type, hostname, ip, port, provider
        FROM findings
        WHERE client_id=? AND substr(first_seen,1,10)=?
              AND NOT (finding_type='takeover' AND vulnerable=0)
        ORDER BY finding_type, hostname
    """, (client, day))


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
# Any recognized cloud/CDN -> green ("attributed"); not-on-a-tracked-cloud -> grey.
# Give a provider its own colour by adding it to this map.
PROVIDER_COLORS = {
    "Azure": "#2e7d32", "AWS": "#2e7d32", "GCP": "#2e7d32",
    "Cloudflare": "#2e7d32", "Fastly": "#2e7d32",
}
UNKNOWN_COLOR = "#5f6368"


def provider_color(name):
    if not name or "unknown" in name.lower() or "non-cloud" in name.lower():
        return UNKNOWN_COLOR
    return PROVIDER_COLORS.get(name, "#2e7d32")


def badge_html(text, color):
    return (f"<span style='display:inline-block;padding:5px 14px;margin:4px 6px 4px 0;"
            f"border-radius:14px;background:{color};color:#fff;font-size:0.95rem;"
            f"font-weight:600'>{text}</span>")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_current(st, db_path, customer):
    ls = latest_scan(db_path, customer)
    if ls is None:
        st.warning(f"No scans recorded for {customer} yet.")
        return

    scan_id, scan_time = ls["scan_id"], ls["scan_time"]
    st.subheader(customer)
    st.caption(f"Latest scan: **{scan_time}**  ·  evidence: `{ls['run_folder']}`")

    ports_df = open_ports(db_path, customer, scan_id)
    assets_df = assets(db_path, customer, scan_id)
    tech_df = technologies(db_path, customer, scan_id)
    takeovers_df = confirmed_takeovers(db_path, customer, scan_id)

    # Headline metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Assets (subdomains)", len(assets_df))
    c2.metric("Open services", len(ports_df))
    c3.metric("Technologies", len(tech_df))
    c4.metric("Confirmed takeovers", len(takeovers_df))

    # Takeover alert (loud if any)
    if not takeovers_df.empty:
        st.error(f"{len(takeovers_df)} CONFIRMED takeover(s) — verify and report.")
        st.dataframe(takeovers_df, use_container_width=True, hide_index=True)

    # Quick inventory — simple flat lists, each its own table, at the top.
    st.markdown("### Inventory")
    inv = st.columns(4)
    with inv[0]:
        st.caption("Subdomains")
        st.dataframe(list_subdomains(db_path, customer, scan_id),
                     use_container_width=True, hide_index=True)
    with inv[1]:
        st.caption("IP addresses")
        st.dataframe(list_ips(db_path, customer, scan_id),
                     use_container_width=True, hide_index=True)
    with inv[2]:
        st.caption("Open ports")
        st.dataframe(list_ports(db_path, customer, scan_id),
                     use_container_width=True, hide_index=True)
    with inv[3]:
        st.caption("Technologies")
        st.dataframe(tech_df[["technology"]] if not tech_df.empty else tech_df,
                     use_container_width=True, hide_index=True)

    # Cloud providers in use — green badges
    in_use = cloud_providers_in_use(db_path, customer, scan_id)
    if not in_use.empty:
        st.markdown("**Cloud providers in use**")
        st.markdown(
            "".join(badge_html(f"{r['provider']} · {int(r['hosts'])} host(s)", provider_color(r["provider"]))
                    for _, r in in_use.iterrows()),
            unsafe_allow_html=True,
        )
        st.caption("Green = on a known cloud/CDN · grey = not on a tracked cloud")

    st.divider()

    # Open ports / live services + distribution chart
    st.markdown("### Open ports & live services")
    left, right = st.columns([2, 1])
    with left:
        st.dataframe(ports_df, use_container_width=True, hide_index=True)
    with right:
        pd_dist = port_distribution(db_path, customer, scan_id)
        if not pd_dist.empty:
            st.caption("Ports by frequency")
            st.bar_chart(pd_dist.set_index("port"))

    st.divider()

    # Subdomain assets
    st.markdown("### Subdomain assets")
    st.dataframe(assets_df, use_container_width=True, hide_index=True)

    st.divider()

    # Technologies
    st.markdown("### Technologies in use")
    if tech_df.empty:
        st.info("No technologies fingerprinted in this scan.")
    else:
        tleft, tright = st.columns([1, 2])
        with tleft:
            st.dataframe(tech_df, use_container_width=True, hide_index=True)
        with tright:
            st.bar_chart(tech_df.set_index("technology"))


def page_history(st, db_path, customer):
    st.subheader(f"{customer} — scan history")

    # Date-grouped "what was newly discovered" changelog — one tidy row per day.
    st.markdown("### Discovery changelog")
    st.caption("Grouped by date. Each row is what was newly discovered that day — "
               "expand for detail. Keeps the history readable as scans pile up.")

    by_date = additions_by_date(db_path, customer)
    if by_date.empty:
        st.info("No findings recorded yet.")
    else:
        for day in by_date["day"].dropna().unique():
            rows = by_date[by_date["day"] == day]
            total = int(rows["count"].sum())
            summary = " · ".join(f"{int(r['count'])} {r['finding_type']}"
                                 for _, r in rows.iterrows())
            with st.expander(f"{day}    (+{total} discovered)    —    {summary}"):
                st.dataframe(additions_on_date(db_path, customer, day),
                             use_container_width=True, hide_index=True)

    st.divider()

    # Secondary: the raw list of scans performed (date/time first).
    st.markdown("### Scans performed")
    sl = scans_list(db_path, customer)
    if sl.empty:
        st.info("No scans recorded yet.")
    else:
        st.dataframe(sl, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
def run_ui(db_path):
    import streamlit as st

    st.set_page_config(page_title="ASM Dashboard", layout="wide")
    st.title("ASM Dashboard")

    if not os.path.exists(db_path):
        st.error(f"Database not found: `{db_path}`\n\n"
                 "Ingest a scan first:  `python3 asm_db.py ingest --latest --client <domain>`")
        st.stop()

    with st.sidebar:
        db_path = st.text_input("Database file", value=db_path)
        try:
            clients = list_clients(db_path)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Could not read the database: {exc}")
            st.stop()
        if not clients:
            st.warning("No data in the database yet.")
            st.stop()
        customer = st.selectbox("Customer", clients)
        page = st.radio("Page", ["Current scan", "Scan history"])
        if st.button("Refresh"):
            st.rerun()

    if page == "Current scan":
        page_current(st, db_path, customer)
    else:
        page_history(st, db_path, customer)


def main():
    parser = argparse.ArgumentParser(description="ASM read-only dashboard.")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Database file (default: {DEFAULT_DB})")
    args, _ = parser.parse_known_args()
    run_ui(args.db)


if __name__ == "__main__":
    main()
