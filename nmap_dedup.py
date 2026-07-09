#!/usr/bin/env python3
"""
Nmap dedup-by-IP deep scan (shared-hosting friendly)
----------------------------------------------------
Standalone tool. Does NOT modify recon-2.py.

Problem it solves: on shared hosting (cPanel, etc.) many hostnames resolve to
ONE server. The pipeline's built-in nmap scans each hostname separately, so a
14-hostname cPanel box gets deep-scanned 14x — wasteful, and a fast way to get
your scanning IP rate-limited/blocked. This tool groups naabu's host:port output
by resolved IP and scans each unique server ONCE, on the union of its ports.

Compatibility: it writes per-hostname evidence files (nmap_<hostname>.nmap/.gnmap
/.xml) for every hostname on a scanned IP, so cloud_enrich.py and asm_db.py keep
working unchanged. It also drops ip_hostnames.json documenting the grouping.

Typical workflow for a shared-hosting target:
    python3 recon-2.py -d <domain> ... --skip-nmap
    python3 nmap_dedup.py --latest

Point it at a run folder or use --latest to grab the newest recon run.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys

RUN_TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})$")


# ---------------------------------------------------------------------------
# Run-folder helpers (self-contained; mirror the other tools)
# ---------------------------------------------------------------------------
def has_content(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


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


def parse_naabu_hosts(naabu_file):
    """Parse naabu 'host:port' into {host: [ports]} (last-colon split, IPv6-safe)."""
    host_ports = {}
    with open(naabu_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and "]:" in line:
                host, _, port = line.rpartition("]:")
                host = host.lstrip("[")
            else:
                host, sep, port = line.rpartition(":")
                if not sep:
                    continue
            port = port.strip()
            if port.isdigit():
                host_ports.setdefault(host, set()).add(port)
    return {h: sorted(p, key=int) for h, p in host_ports.items()}


def safe_name(name):
    return name.replace(":", "_").replace("/", "_")


# ---------------------------------------------------------------------------
# Resolution + grouping
# ---------------------------------------------------------------------------
def resolve_ip(host):
    """Return the IPv4 for a host (or the host itself if it's already an IP)."""
    try:
        ipaddress.ip_address(host)
        return host                      # already an IP
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:                    # noqa: BLE001
        return None


def group_by_ip(host_ports, resolver=resolve_ip):
    """
    Group hostnames by resolved IP, unioning ports per IP.
    Returns (groups, unresolved) where
      groups     = {ip: {"hostnames": set, "ports": set}}
      unresolved = {host: [ports]}  (couldn't resolve — scanned individually)
    """
    groups = {}
    unresolved = {}
    for host, ports in host_ports.items():
        ip = resolver(host)
        if ip is None:
            unresolved[host] = ports
            continue
        g = groups.setdefault(ip, {"hostnames": set(), "ports": set()})
        g["hostnames"].add(host)
        g["ports"].update(ports)
    return groups, unresolved


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def _run_nmap(target, ports, base, timing, nmap_bin):
    port_list = ",".join(sorted(ports, key=int))
    cmd = [nmap_bin, "-Pn", "-sV", "-sC", f"-T{timing}",
           "-p", port_list, "-oA", base, target]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return False, "nmap binary not found on $PATH"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    return os.path.exists(base + ".xml"), ""


def _replicate(base, hostnames, nmap_dir):
    """Copy the representative scan's files to every hostname on this IP,
    so hostname-based consumers (cloud_enrich/asm_db) see each host."""
    for host in sorted(hostnames):
        dst_base = os.path.join(nmap_dir, f"nmap_{safe_name(host)}")
        if dst_base == base:
            continue
        for ext in (".nmap", ".gnmap", ".xml"):
            if os.path.exists(base + ext):
                shutil.copyfile(base + ext, dst_base + ext)


def scan_ip(ip, hostnames, ports, nmap_dir, timing, nmap_bin):
    """Scan one server (IP) once, then replicate evidence per hostname."""
    rep = sorted(hostnames)[0]                       # representative hostname
    base = os.path.join(nmap_dir, f"nmap_{safe_name(rep)}")
    ok, err = _run_nmap(ip, ports, base, timing, nmap_bin)
    if ok:
        _replicate(base, hostnames, nmap_dir)
    detail = f"{len(hostnames)} host(s), {len(ports)} port(s)"
    return ip, ok, (detail if ok else err)


def scan_single(host, ports, nmap_dir, timing, nmap_bin):
    """Fallback: scan an unresolved host by hostname."""
    base = os.path.join(nmap_dir, f"nmap_{safe_name(host)}")
    ok, err = _run_nmap(host, ports, base, timing, nmap_bin)
    return host, ok, (f"{len(ports)} port(s)" if ok else err)


def run_dedup_scan(naabu_file, outdir, timing, max_workers, nmap_bin):
    host_ports = parse_naabu_hosts(naabu_file)
    if not host_ports:
        print("[!] No host:port pairs in naabu output — nothing to scan.")
        return

    groups, unresolved = group_by_ip(host_ports, resolver=resolve_ip)
    total_hosts = len(host_ports)
    unique_ips = len(groups)

    nmap_dir = os.path.join(outdir, "nmap")
    os.makedirs(nmap_dir, exist_ok=True)

    saved = total_hosts - unique_ips - len(unresolved)
    print(f"    {total_hosts} hostname(s) -> {unique_ips} unique server IP(s)"
          + (f" (+{len(unresolved)} unresolved)" if unresolved else ""))
    if saved > 0:
        print(f"    Dedup avoids {saved} redundant scan(s) of shared servers.")
    print(f"    Output -> {nmap_dir}")

    # Record the grouping for transparency / downstream use.
    mapping = {ip: sorted(g["hostnames"]) for ip, g in groups.items()}
    with open(os.path.join(nmap_dir, "ip_hostnames.json"), "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = []
        for ip, g in groups.items():
            futures.append(pool.submit(scan_ip, ip, g["hostnames"], g["ports"],
                                       nmap_dir, timing, nmap_bin))
        for host, ports in unresolved.items():
            futures.append(pool.submit(scan_single, host, ports, nmap_dir, timing, nmap_bin))
        for fut in concurrent.futures.as_completed(futures):
            key, ok, info = fut.result()
            print(f"    [nmap {'OK ' if ok else 'FAIL'}] {key} ({info})")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Dedup-by-IP nmap deep scan over a recon run's naabu output."
    )
    parser.add_argument("-i", "--input", default=None, help="Recon run folder")
    parser.add_argument("--latest", action="store_true",
                        help="Auto-select the newest recon_* run folder")
    parser.add_argument("-d", "--domain", default=None,
                        help="With --latest, only consider runs for this domain")
    parser.add_argument("--base-dir", default=".",
                        help="Where to look for run folders with --latest (default: .)")
    parser.add_argument("--nmap-timing", type=int, default=3, choices=range(0, 6),
                        help="Nmap -T timing template 0-5 (default: 3)")
    parser.add_argument("--nmap-workers", type=int, default=3,
                        help="Max parallel nmap processes, one per server (default: 3)")
    parser.add_argument("--nmap-bin", default="nmap",
                        help="Path to the nmap binary (default: 'nmap' on $PATH)")

    args = parser.parse_args()

    if args.latest:
        run_dir = find_latest_run(args.base_dir, args.domain)
        if not run_dir:
            scope = f" for domain '{args.domain}'" if args.domain else ""
            print(f"[!] No recon_* run folders found{scope} in '{args.base_dir}'.")
            sys.exit(1)
        print(f"[*] Auto-selected latest run: {run_dir}")
    elif args.input:
        run_dir = args.input
    else:
        parser.error("provide -i/--input (a run folder) or --latest")

    if not os.path.isdir(run_dir):
        print(f"[!] '{run_dir}' is not a directory.")
        sys.exit(1)

    naabu_file = os.path.join(run_dir, "naabu_result.txt")
    if not has_content(naabu_file):
        print(f"[!] No naabu_result.txt in {run_dir}. Run recon first (with --skip-nmap).")
        sys.exit(1)

    print("[*] Nmap dedup-by-IP deep scan")
    try:
        run_dedup_scan(naabu_file, run_dir, args.nmap_timing, args.nmap_workers, args.nmap_bin)
    except KeyboardInterrupt:
        print("\n[!] Interrupted — partial results preserved.")
        sys.exit(130)

    print("\n[+] Done. Per-hostname nmap files written; ip_hostnames.json records the grouping.")


if __name__ == "__main__":
    main()
