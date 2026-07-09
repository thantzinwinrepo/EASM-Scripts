#!/usr/bin/env python3
"""
ASM findings database (SQLite)
------------------------------
A lightweight, single-file database layer for the recon pipeline. It ingests
the structured JSON your tools already write into a run folder and distills it
into one queryable `findings` table with proper history tracking.

DESIGN:
  * The database holds DISTILLED, QUERYABLE findings + history.
  * The raw scan artifacts stay on disk as evidence — this DB does NOT copy
    them; each finding stores `run_folder`, a pointer back to the evidence.
  * Every finding carries: client_id, scan_id, source, and three timestamps —
    first_seen / last_seen / scan_time — which is what powers delta detection
    ("what's new since last scan?") and the eventual dashboard.

IDENTITY / DEDUP:
  A finding is "the same thing seen again" if (client_id, finding_key) matches.
  On first insert:  first_seen = last_seen = scan_time.
  On re-observation: last_seen is refreshed, first_seen is preserved.
  That single rule is what makes history work.

INGESTS (from a run folder):
  cloud_enrichment.json  -> cloud attribution findings (per IP)
  takeover_result.json   -> subdomain-takeover hits
  httpx_result.json      -> live host/service findings (JSONL)

Usage:
  python3 asm_db.py ingest --latest --client example.com
  python3 asm_db.py ingest recon_example.com_20260706_142913/
  python3 asm_db.py stats
  python3 asm_db.py new --days 7
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

RUN_TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})$")
DEFAULT_DB = "asm_findings.db"


# ---------------------------------------------------------------------------
# Time + run-folder helpers
# ---------------------------------------------------------------------------
def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_latest_run(base_dir, domain=None):
    prefix = "recon_"
    match_prefix = f"{prefix}{domain}_" if domain else prefix
    candidates = []
    try:
        entries = os.listdir(base_dir)
    except FileNotFoundError:
        return None
    for name in entries:
        full = os.path.join(base_dir, name)
        if not os.path.isdir(full) or not name.startswith(match_prefix):
            continue
        m = RUN_TIMESTAMP_RE.search(name)
        candidates.append((m.group(1) if m else "", os.path.getmtime(full), full))
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], t[1]))
    return candidates[-1][2]


def parse_run_folder(run_folder):
    """Return (domain, scan_time_iso) parsed from the run folder name."""
    name = os.path.basename(os.path.normpath(run_folder))
    m = RUN_TIMESTAMP_RE.search(name)
    scan_time = ""
    if m:
        try:
            scan_time = datetime.strptime(m.group(1), "%Y%m%d_%H%M%S").strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            scan_time = ""
    domain = name[len("recon_"):] if name.startswith("recon_") else name
    domain = RUN_TIMESTAMP_RE.sub("", domain)
    return domain, (scan_time or utc_now())


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL,
    finding_key   TEXT NOT NULL,          -- deterministic identity for dedup across scans
    finding_type  TEXT NOT NULL,          -- cloud | takeover | host_service | subdomain
    source        TEXT NOT NULL,          -- tool that produced it
    hostname      TEXT,
    ip            TEXT,
    port          INTEGER,
    provider      TEXT,                   -- cloud provider, if applicable
    severity      TEXT,                   -- optional risk label
    vulnerable    INTEGER,                -- 1/0 for takeover verdict; NULL for non-takeover findings
    detail        TEXT,                   -- JSON blob of tool-specific fields
    scan_id       TEXT,                   -- run folder name
    run_folder    TEXT,                   -- path to the raw evidence
    first_seen    TEXT NOT NULL,          -- ISO-8601, when first ever observed
    last_seen     TEXT NOT NULL,          -- ISO-8601, most recent observation
    scan_time     TEXT NOT NULL,          -- ISO-8601, when the producing scan ran
    ingested_at   TEXT NOT NULL,          -- ISO-8601 UTC, when written to the DB
    UNIQUE(client_id, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_client   ON findings(client_id);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_lastseen ON findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_firstseen ON findings(first_seen);
CREATE INDEX IF NOT EXISTS idx_findings_ip       ON findings(ip);
CREATE INDEX IF NOT EXISTS idx_findings_host     ON findings(hostname);

CREATE TABLE IF NOT EXISTS scans (
    scan_id     TEXT PRIMARY KEY,         -- run folder name
    client_id   TEXT NOT NULL,
    domain      TEXT,
    run_folder  TEXT,
    scan_time   TEXT,
    ingested_at TEXT
);
"""

UPSERT = """
INSERT INTO findings
  (client_id, finding_key, finding_type, source, hostname, ip, port,
   provider, severity, vulnerable, detail, scan_id, run_folder,
   first_seen, last_seen, scan_time, ingested_at)
VALUES
  (:client_id, :finding_key, :finding_type, :source, :hostname, :ip, :port,
   :provider, :severity, :vulnerable, :detail, :scan_id, :run_folder,
   :scan_time, :scan_time, :scan_time, :ingested_at)
ON CONFLICT(client_id, finding_key) DO UPDATE SET
   last_seen   = excluded.scan_time,      -- refresh "most recently seen"
   scan_time   = excluded.scan_time,
   scan_id     = excluded.scan_id,
   run_folder  = excluded.run_folder,
   source      = excluded.source,
   provider    = excluded.provider,
   severity    = excluded.severity,
   vulnerable  = excluded.vulnerable,
   detail      = excluded.detail,
   ingested_at = excluded.ingested_at;
   -- first_seen intentionally NOT updated -> preserved from first observation
"""


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------
def upsert_finding(conn, *, client_id, finding_key, finding_type, source,
                   hostname=None, ip=None, port=None, provider=None,
                   severity=None, vulnerable=None, detail=None, scan_id=None,
                   run_folder=None, scan_time=None):
    conn.execute(UPSERT, {
        "client_id": client_id,
        "finding_key": finding_key,
        "finding_type": finding_type,
        "source": source,
        "hostname": hostname,
        "ip": ip,
        "port": port,
        "provider": provider,
        "severity": severity,
        "vulnerable": vulnerable,
        "detail": json.dumps(detail, ensure_ascii=False) if detail is not None else None,
        "scan_id": scan_id,
        "run_folder": run_folder,
        "scan_time": scan_time,
        "ingested_at": utc_now(),
    })


def _read_json(path):
    if not (os.path.isfile(path) and os.path.getsize(path) > 0):
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def _read_jsonl(path):
    """httpx -json writes one JSON object per line."""
    rows = []
    if not (os.path.isfile(path) and os.path.getsize(path) > 0):
        return rows
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# ---------------------------------------------------------------------------
# Ingest: one run folder -> findings
# ---------------------------------------------------------------------------
def ingest_run(conn, run_folder, client_id=None):
    run_folder = os.path.abspath(run_folder)
    scan_id = os.path.basename(os.path.normpath(run_folder))
    domain, scan_time = parse_run_folder(run_folder)
    client_id = client_id or domain

    counts = {"cloud": 0, "takeover": 0, "host_service": 0}

    # -- cloud_enrichment.json --
    cloud = _read_json(os.path.join(run_folder, "cloud_enrichment.json"))
    if cloud:
        for h in cloud.get("hosts", []):
            ip = h.get("ip", "")
            if not ip:
                continue
            hostnames = h.get("hostnames", []) or []
            upsert_finding(
                conn, client_id=client_id, finding_key=f"cloud:{ip}",
                finding_type="cloud", source="cloud_enrich",
                hostname=hostnames[0] if hostnames else None, ip=ip,
                provider=h.get("provider"), detail=h,
                scan_id=scan_id, run_folder=run_folder, scan_time=scan_time,
            )
            counts["cloud"] += 1

    # -- takeover_result.json (subjack JSON array) --
    # subjack lists EVERY host it checked, with a "vulnerable" verdict.
    # We record all of them (so a checked-and-clean host is evidence too), but
    # store the true/false verdict and only mark real hits as high severity.
    to = _read_json(os.path.join(run_folder, "takeover_result.json"))
    if isinstance(to, list):
        for item in to:
            if not isinstance(item, dict):
                continue
            sub = item.get("subdomain") or item.get("Subdomain")
            if not sub:
                continue
            is_vuln = bool(item.get("vulnerable") or item.get("Vulnerable"))
            upsert_finding(
                conn, client_id=client_id, finding_key=f"takeover:{sub}",
                finding_type="takeover", source="subjack",
                hostname=sub,
                severity="high" if is_vuln else "info",
                vulnerable=1 if is_vuln else 0,
                provider=item.get("service") or item.get("Service"),
                detail=item, scan_id=scan_id, run_folder=run_folder, scan_time=scan_time,
            )
            if is_vuln:
                counts["takeover"] += 1          # count only REAL takeovers
            else:
                counts["takeover_checked"] = counts.get("takeover_checked", 0) + 1

    # -- httpx_result.json (JSONL) --
    for row in _read_jsonl(os.path.join(run_folder, "httpx_result.json")):
        host = row.get("host") or row.get("input") or ""
        port = row.get("port")
        ip = None
        a = row.get("a")
        if isinstance(a, list) and a:
            ip = a[0]
        key_input = row.get("input") or f"{host}:{port}"
        if not key_input:
            continue
        detail = {
            "url": row.get("url"),
            "status_code": row.get("status_code") or row.get("status-code"),
            "title": row.get("title"),
            "tech": row.get("tech") or row.get("technologies"),
            "webserver": row.get("webserver"),
        }
        upsert_finding(
            conn, client_id=client_id, finding_key=f"host_service:{key_input}",
            finding_type="host_service", source="httpx",
            hostname=host, ip=ip, port=int(port) if str(port).isdigit() else None,
            detail=detail, scan_id=scan_id, run_folder=run_folder, scan_time=scan_time,
        )
        counts["host_service"] += 1

    # -- record the scan itself --
    conn.execute(
        "INSERT INTO scans (scan_id, client_id, domain, run_folder, scan_time, ingested_at) "
        "VALUES (?,?,?,?,?,?) ON CONFLICT(scan_id) DO UPDATE SET "
        "ingested_at=excluded.ingested_at, scan_time=excluded.scan_time",
        (scan_id, client_id, domain, run_folder, scan_time, utc_now()),
    )
    conn.commit()

    # how many of the just-ingested findings are brand new (first_seen == this scan)?
    new_count = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id=? AND first_seen=scan_time",
        (scan_id,),
    ).fetchone()[0]

    return client_id, scan_time, counts, new_count


# ---------------------------------------------------------------------------
# Queries (CLI)
# ---------------------------------------------------------------------------
def cmd_stats(conn, _args):
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    print(f"Total findings: {total}\n")
    print("By type:")
    for r in conn.execute("SELECT finding_type, COUNT(*) n FROM findings GROUP BY finding_type ORDER BY n DESC"):
        print(f"  {r['finding_type']:<14} {r['n']}")
    print("\nBy provider (cloud):")
    for r in conn.execute("SELECT provider, COUNT(*) n FROM findings WHERE finding_type='cloud' GROUP BY provider ORDER BY n DESC"):
        print(f"  {str(r['provider']):<20} {r['n']}")
    print("\nBy client:")
    for r in conn.execute("SELECT client_id, COUNT(*) n FROM findings GROUP BY client_id ORDER BY n DESC"):
        print(f"  {r['client_id']:<28} {r['n']}")


def cmd_new(conn, args):
    """Findings first observed within the last N days — the delta view.

    Cleared takeover checks (vulnerable=0) are noise, so they're excluded by
    default; pass --all to include them.
    """
    cutoff = args.days
    filt = "" if args.all else "AND NOT (finding_type='takeover' AND vulnerable=0) "
    rows = conn.execute(
        "SELECT client_id, finding_type, hostname, ip, port, provider, vulnerable, first_seen "
        "FROM findings WHERE julianday('now') - julianday(first_seen) <= ? " + filt +
        "ORDER BY first_seen DESC", (cutoff,),
    ).fetchall()
    print(f"Findings first seen in the last {cutoff} day(s): {len(rows)}"
          f"{'' if args.all else '  (cleared takeover checks hidden; --all to show)'}\n")
    for r in rows:
        loc = r["hostname"] or r["ip"] or ""
        extra = f" :{r['port']}" if r["port"] else ""
        prov = f" [{r['provider']}]" if r["provider"] else ""
        vuln = "  <== VULNERABLE" if (r["finding_type"] == "takeover" and r["vulnerable"] == 1) else ""
        print(f"  {r['first_seen']}  {r['finding_type']:<13} {loc}{extra}{prov}{vuln}")


def cmd_takeovers(conn, _args):
    """Only genuine takeover hits — vulnerable=1."""
    rows = conn.execute(
        "SELECT client_id, hostname, provider, first_seen, last_seen "
        "FROM findings WHERE finding_type='takeover' AND vulnerable=1 "
        "ORDER BY last_seen DESC"
    ).fetchall()
    if not rows:
        print("No confirmed takeovers. (Hosts were checked and cleared — good.)")
        return
    print(f"CONFIRMED takeover hits: {len(rows)}\n")
    for r in rows:
        prov = f" [{r['provider']}]" if r["provider"] else ""
        print(f"  {r['client_id']}  {r['hostname']}{prov}  first={r['first_seen']} last={r['last_seen']}")


def cmd_ingest(conn, args):
    if args.latest:
        run = find_latest_run(args.base_dir, args.domain)
        if not run:
            print(f"[!] No recon_* run folders found in '{args.base_dir}'.")
            sys.exit(1)
        print(f"[*] Latest run: {run}")
    else:
        run = args.run_folder
        if not run or not os.path.isdir(run):
            print(f"[!] '{run}' is not a run folder.")
            sys.exit(1)

    client, scan_time, counts, new_count = ingest_run(conn, run, args.client)
    checked = counts.get("takeover_checked", 0)
    print(f"[+] Ingested run for client '{client}' (scan_time {scan_time})")
    print(f"    cloud={counts['cloud']}  host_service={counts['host_service']}")
    print(f"    takeover: {counts['takeover']} VULNERABLE, {checked} checked-and-clean")
    print(f"    {new_count} finding(s) are NEW (first seen this scan).")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="ASM findings database (SQLite).")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Database file (default: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ing = sub.add_parser("ingest", help="Ingest a run folder's JSON outputs")
    p_ing.add_argument("run_folder", nargs="?", help="Path to a recon run folder")
    p_ing.add_argument("--latest", action="store_true", help="Auto-select the newest recon run")
    p_ing.add_argument("-d", "--domain", default=None, help="With --latest, filter by domain")
    p_ing.add_argument("--base-dir", default=".", help="Where to look for run folders (default: .)")
    p_ing.add_argument("--client", default=None, help="Client id (default: domain from folder name)")
    p_ing.set_defaults(func=cmd_ingest)

    p_stats = sub.add_parser("stats", help="Summary counts")
    p_stats.set_defaults(func=cmd_stats)

    p_new = sub.add_parser("new", help="Findings first seen recently (delta view)")
    p_new.add_argument("--days", type=float, default=7, help="Look-back window in days (default: 7)")
    p_new.add_argument("--all", action="store_true",
                       help="Include cleared takeover checks (vulnerable=0), normally hidden")
    p_new.set_defaults(func=cmd_new)

    p_to = sub.add_parser("takeovers", help="Show ONLY confirmed takeover hits (vulnerable=1)")
    p_to.set_defaults(func=cmd_takeovers)

    args = parser.parse_args()
    conn = connect(args.db)
    try:
        args.func(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
