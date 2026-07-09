#!/usr/bin/env python3
"""
Cloud Enrichment (offline CIDR matching — AWS / Azure / GCP)
-----------------------------------------------------------
Standalone tool. Does NOT modify or depend on recon.py / takeover_check.py.

No API key. It matches the IPs a recon run actually observed (parsed from the
nmap output) against the cloud providers' own published IP-range files, held in
a local cache. For each IP it reports provider + region + service + the exact
matching CIDR, and writes cloud_enrichment.json back into the run folder.

TWO PHASES (deliberately separated):

  1. Refresh the range data (do this periodically, e.g. weekly):
        python3 cloud_enrich.py --update --azure-file ServiceTags_Public_YYYYMMDD.json

  2. Enrich a scan (offline, fast, every run):
        python3 cloud_enrich.py --latest

RANGE SOURCES:
  AWS   : https://ip-ranges.amazonaws.com/ip-ranges.json        (stable URL — auto-fetched)
  GCP   : https://www.gstatic.com/ipranges/cloud.json           (stable URL — auto-fetched)
  Azure : Service Tags JSON from the Microsoft Download Center   (weekly, NO stable URL)
          Download page: https://www.microsoft.com/download/details.aspx?id=56519
          The file URL changes each week, so download it manually and pass it
          with --azure-file; --update will copy it into the cache.

CAVEAT: this reports the provider AT the IP. A host behind a CDN/WAF edge
(CloudFront, Azure Front Door) matches the edge's range, not the hidden origin.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import urllib.request

RUN_TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})$")
GNMAP_HOST_RE = re.compile(r"^Host:\s+(\S+)")

AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
# CDN / edge providers — so a host behind a WAF/CDN labels as the edge, not "Unknown".
CF_V4_URL = "https://www.cloudflare.com/ips-v4"
CF_V6_URL = "https://www.cloudflare.com/ips-v6"
FASTLY_URL = "https://api.fastly.com/public-ip-list"

DEFAULT_CACHE = os.path.expanduser("~/.cloud_ranges")


# ---------------------------------------------------------------------------
# Run-folder helpers (self-contained; mirror takeover_check.py conventions)
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
        stamp = m.group(1) if m else ""
        candidates.append((stamp, os.path.getmtime(full), full))
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], t[1]))
    return candidates[-1][2]


def extract_nmap_ips(run_dir):
    """Parse nmap/*.gnmap into {ip: [hostnames]}, tying each IP to its host(s)."""
    nmap_dir = os.path.join(run_dir, "nmap")
    mapping = {}
    if not os.path.isdir(nmap_dir):
        return mapping
    for name in sorted(os.listdir(nmap_dir)):
        if not name.endswith(".gnmap"):
            continue
        host = name[len("nmap_"):] if name.startswith("nmap_") else name
        host = host[:-len(".gnmap")]
        with open(os.path.join(nmap_dir, name), "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = GNMAP_HOST_RE.match(line)
                if m:
                    mapping.setdefault(m.group(1), set()).add(host)
    return {ip: sorted(hosts) for ip, hosts in mapping.items()}


# ---------------------------------------------------------------------------
# Range data: refresh (download) and load
# ---------------------------------------------------------------------------
def _download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "cloud_enrich/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    with open(dest, "wb") as f:
        f.write(data)
    return len(data)


def update_ranges(cache_dir, azure_file):
    """Refresh the local cache: fetch AWS + GCP; copy Azure from --azure-file."""
    os.makedirs(cache_dir, exist_ok=True)
    ok = True

    sources = (
        ("AWS", AWS_URL, "aws.json"),
        ("GCP", GCP_URL, "gcp.json"),
        ("Cloudflare-v4", CF_V4_URL, "cf_v4.txt"),
        ("Cloudflare-v6", CF_V6_URL, "cf_v6.txt"),
        ("Fastly", FASTLY_URL, "fastly.json"),
    )
    for label, url, fname in sources:
        dest = os.path.join(cache_dir, fname)
        try:
            size = _download(url, dest)
            print(f"[+] {label}: downloaded {size:,} bytes -> {dest}")
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {label}: download failed ({exc}). Kept any existing cache copy.")
            ok = False

    az_dest = os.path.join(cache_dir, "azure.json")
    if azure_file:
        if has_content(azure_file):
            shutil.copyfile(azure_file, az_dest)
            print(f"[+] Azure: copied {azure_file} -> {az_dest}")
        else:
            print(f"[!] Azure: --azure-file '{azure_file}' missing or empty.")
            ok = False
    else:
        print("[i] Azure: no --azure-file given. Download the weekly Service Tags JSON")
        print("           from https://www.microsoft.com/download/details.aspx?id=56519")
        print("           and re-run --update --azure-file <that file>. "
              "(Existing cache copy, if any, is kept.)")

    return ok


def _load_json(path):
    if not has_content(path):
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def load_ranges(cache_dir):
    """
    Build lookup structures from cached provider files.
    Returns (v4_buckets, v6_list, meta) where:
      v4_buckets: {first_octet_int: [(network, provider, region, service), ...]}
      v6_list:    [(network, provider, region, service), ...]
      meta:       per-provider {loaded: bool, count: int, age: 'YYYY-mm-dd'}
    """
    v4_buckets = {}
    v6_list = []
    meta = {}

    def add(cidr, provider, region, service):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return 0
        entry = (net, provider, region, service)
        if net.version == 4:
            lo = int(net.network_address) >> 24
            hi = int(net.broadcast_address) >> 24
            for octet in range(lo, hi + 1):
                v4_buckets.setdefault(octet, []).append(entry)
        else:
            v6_list.append(entry)
        return 1

    def file_age(path):
        if os.path.exists(path):
            return time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path)))
        return None

    # AWS: prefixes[].ip_prefix / ipv6_prefixes[].ipv6_prefix + region + service
    aws_path = os.path.join(cache_dir, "aws.json")
    aws = _load_json(aws_path)
    count = 0
    if aws:
        for p in aws.get("prefixes", []):
            count += add(p.get("ip_prefix", ""), "AWS", p.get("region", ""), p.get("service", ""))
        for p in aws.get("ipv6_prefixes", []):
            count += add(p.get("ipv6_prefix", ""), "AWS", p.get("region", ""), p.get("service", ""))
    meta["AWS"] = {"loaded": bool(aws), "count": count, "age": file_age(aws_path)}

    # GCP: prefixes[] each has ipv4Prefix or ipv6Prefix + service + scope(region)
    gcp_path = os.path.join(cache_dir, "gcp.json")
    gcp = _load_json(gcp_path)
    count = 0
    if gcp:
        for p in gcp.get("prefixes", []):
            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix") or ""
            count += add(cidr, "GCP", p.get("scope", ""), p.get("service", ""))
    meta["GCP"] = {"loaded": bool(gcp), "count": count, "age": file_age(gcp_path)}

    # Azure: values[].properties.addressPrefixes[] + region + systemService
    az_path = os.path.join(cache_dir, "azure.json")
    az = _load_json(az_path)
    count = 0
    if az:
        for val in az.get("values", []):
            props = val.get("properties", {}) or {}
            region = props.get("region", "") or ""
            service = props.get("systemService", "") or val.get("name", "")
            for cidr in props.get("addressPrefixes", []) or []:
                count += add(cidr, "Azure", region, service)
    meta["Azure"] = {"loaded": bool(az), "count": count, "age": file_age(az_path)}

    # Fastly (edge/CDN): {"addresses":[...], "ipv6_addresses":[...]}
    fastly_path = os.path.join(cache_dir, "fastly.json")
    fastly = _load_json(fastly_path)
    count = 0
    if fastly:
        for cidr in (fastly.get("addresses", []) or []) + (fastly.get("ipv6_addresses", []) or []):
            count += add(cidr, "Fastly", "Global", "Edge/CDN")
    meta["Fastly"] = {"loaded": bool(fastly), "count": count, "age": file_age(fastly_path)}

    # Cloudflare (edge/CDN): plain text, one CIDR per line, v4 + v6 files
    cf_count = 0
    cf_loaded = False
    cf_age = None
    for cf_file in ("cf_v4.txt", "cf_v6.txt"):
        cf_path = os.path.join(cache_dir, cf_file)
        if has_content(cf_path):
            cf_loaded = True
            cf_age = file_age(cf_path)
            with open(cf_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        cf_count += add(line, "Cloudflare", "Global", "Edge/CDN")
    meta["Cloudflare"] = {"loaded": cf_loaded, "count": cf_count, "age": cf_age}

    # Step 2: pre-sort every bucket most-specific-first (longest prefix first),
    # so match_ip can return on the FIRST hit and still get the best match.
    for octet in v4_buckets:
        v4_buckets[octet].sort(key=lambda e: e[0].prefixlen, reverse=True)
    v6_list.sort(key=lambda e: e[0].prefixlen, reverse=True)

    return v4_buckets, v6_list, meta


def match_ip(ip_str, v4_buckets, v6_list):
    """
    Return the most specific match, or None.
    Buckets are pre-sorted longest-prefix-first (see load_ranges), so the first
    containing network IS the most specific — we can return immediately.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    candidates = v4_buckets.get(int(ip) >> 24, ()) if ip.version == 4 else v6_list
    for net, provider, region, service in candidates:
        if ip in net:
            return (net.prefixlen, provider, region, service, str(net))
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Offline cloud enrichment (AWS/Azure/GCP) via published IP ranges."
    )
    parser.add_argument("-i", "--input", default=None, help="Recon run folder to enrich")
    parser.add_argument("--latest", action="store_true",
                        help="Auto-select the newest recon_* run folder")
    parser.add_argument("-d", "--domain", default=None,
                        help="With --latest, only consider runs for this domain")
    parser.add_argument("--base-dir", default=".",
                        help="Where to look for recon_* folders when using --latest (default: current dir)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output JSON path (default: cloud_enrichment.json inside the run folder)")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE,
                        help=f"Where cached range files live (default: {DEFAULT_CACHE})")
    parser.add_argument("--update", action="store_true",
                        help="Refresh the range cache (fetch AWS+GCP; copy Azure from --azure-file) and exit")
    parser.add_argument("--azure-file", default=None,
                        help="Path to a manually downloaded Azure Service Tags JSON (used with --update)")

    args = parser.parse_args()

    # Phase 1: refresh cache, then exit.
    if args.update:
        print(f"[*] Updating range cache in {args.cache_dir}\n")
        ok = update_ranges(args.cache_dir, args.azure_file)
        print("\n[+] Cache update complete." if ok else "\n[!] Cache update finished with warnings.")
        sys.exit(0 if ok else 1)

    # Phase 2: enrich a run.
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
        parser.error("provide -i/--input (a run folder) or --latest; or use --update to refresh ranges")

    if not os.path.isdir(run_dir):
        print(f"[!] '{run_dir}' is not a directory.")
        sys.exit(1)

    # Load range data from cache.
    v4_buckets, v6_list, meta = load_ranges(args.cache_dir)
    if not any(m["loaded"] for m in meta.values()):
        print(f"[!] No range data in cache ({args.cache_dir}). Run --update first:")
        print("      python3 cloud_enrich.py --update --azure-file <ServiceTags.json>")
        sys.exit(1)

    print("[*] Range data loaded:")
    for prov in ("AWS", "Azure", "GCP", "Cloudflare", "Fastly"):
        m = meta[prov]
        if m["loaded"]:
            print(f"      {prov:<11} {m['count']:>6,} prefixes  (as of {m['age']})")
        else:
            print(f"      {prov:<11} not cached — skipped (run --update)")

    # Observed IPs from the nmap output.
    ip_hostnames = extract_nmap_ips(run_dir)
    ips = sorted(ip_hostnames.keys())
    if not ips:
        print("\n[!] No IPs found in the run's nmap output "
              "(did nmap run? no open ports means no IPs to enrich).")
        sys.exit(1)

    # Match each IP.
    hosts = []
    summary = {}
    for ip in ips:
        best = match_ip(ip, v4_buckets, v6_list)
        if best:
            _, provider, region, service, cidr = best
        else:
            provider, region, service, cidr = "Non-cloud / Unknown", "", "", ""
        summary[provider] = summary.get(provider, 0) + 1
        hosts.append({
            "ip": ip,
            "hostnames": ip_hostnames.get(ip, []),
            "provider": provider,
            "region": region,
            "service": service,
            "cidr": cidr,
        })
    hosts.sort(key=lambda h: (h["provider"], h["ip"]))

    output_file = args.output or os.path.join(run_dir, "cloud_enrichment.json")
    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "run_folder": os.path.abspath(run_dir),
        "range_data_age": {p: meta[p]["age"] for p in meta if meta[p]["loaded"]},
        "count": len(hosts),
        "summary": summary,
        "hosts": hosts,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[+] Enriched {len(hosts)} IP(s) -> {output_file}\n")
    print("    Provider breakdown:")
    for provider, n in sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"      {provider:<20} {n}")
    print("\n[i] Reminder: this is the provider AT each IP. A host behind a CDN/WAF "
          "edge (CloudFront, Azure Front Door) matches the edge range, not the origin.")


if __name__ == "__main__":
    main()
