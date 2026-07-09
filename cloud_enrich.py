#!/usr/bin/env python3
"""
Cloud Enrichment (offline CIDR matching + ipgeolocation.io API Fallback)
-----------------------------------------------------------
Matches IPs against local cloud provider files (AWS/Azure/GCP/Cloudflare).
If an IP is NOT found locally, it falls back to ipgeolocation.io to 
identify the owner, caching the result to save your daily 1,000 API credits.
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
import urllib.error

RUN_TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})$")
GNMAP_HOST_RE = re.compile(r"^Host:\s+(\S+)")

AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CF_V4_URL = "https://www.cloudflare.com/ips-v4"
CF_V6_URL = "https://www.cloudflare.com/ips-v6"
FASTLY_URL = "https://api.fastly.com/public-ip-list"

DEFAULT_CACHE = os.path.expanduser("~/.cloud_ranges")

# ---------------------------------------------------------------------------
# Run-folder helpers
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
        except Exception as exc: 
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

    return ok

def _load_json(path):
    if not has_content(path):
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)

def load_ranges(cache_dir):
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

    # Load AWS
    aws_path = os.path.join(cache_dir, "aws.json")
    aws = _load_json(aws_path)
    count = 0
    if aws:
        for p in aws.get("prefixes", []): count += add(p.get("ip_prefix", ""), "AWS", p.get("region", ""), p.get("service", ""))
    meta["AWS"] = {"loaded": bool(aws), "count": count, "age": file_age(aws_path)}

    # Load GCP
    gcp_path = os.path.join(cache_dir, "gcp.json")
    gcp = _load_json(gcp_path)
    count = 0
    if gcp:
        for p in gcp.get("prefixes", []):
            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix") or ""
            count += add(cidr, "GCP", p.get("scope", ""), p.get("service", ""))
    meta["GCP"] = {"loaded": bool(gcp), "count": count, "age": file_age(gcp_path)}

    # Load Azure
    az_path = os.path.join(cache_dir, "azure.json")
    az = _load_json(az_path)
    count = 0
    if az:
        for val in az.get("values", []):
            props = val.get("properties", {}) or {}
            region = props.get("region", "") or ""
            service = props.get("systemService", "") or val.get("name", "")
            for cidr in props.get("addressPrefixes", []) or []: count += add(cidr, "Azure", region, service)
    meta["Azure"] = {"loaded": bool(az), "count": count, "age": file_age(az_path)}

    # Load Fastly
    fastly_path = os.path.join(cache_dir, "fastly.json")
    fastly = _load_json(fastly_path)
    count = 0
    if fastly:
        for cidr in (fastly.get("addresses", []) or []) + (fastly.get("ipv6_addresses", []) or []):
            count += add(cidr, "Fastly", "Global", "Edge/CDN")
    meta["Fastly"] = {"loaded": bool(fastly), "count": count, "age": file_age(fastly_path)}

    # Load Cloudflare
    cf_count, cf_loaded, cf_age = 0, False, None
    for cf_file in ("cf_v4.txt", "cf_v6.txt"):
        cf_path = os.path.join(cache_dir, cf_file)
        if has_content(cf_path):
            cf_loaded = True
            cf_age = file_age(cf_path)
            with open(cf_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line: cf_count += add(line, "Cloudflare", "Global", "Edge/CDN")
    meta["Cloudflare"] = {"loaded": cf_loaded, "count": cf_count, "age": cf_age}

    for octet in v4_buckets: v4_buckets[octet].sort(key=lambda e: e[0].prefixlen, reverse=True)
    v6_list.sort(key=lambda e: e[0].prefixlen, reverse=True)

    return v4_buckets, v6_list, meta


def match_ip(ip_str, v4_buckets, v6_list):
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
# NEW: API Fallback Logic (ipgeolocation.io)
# ---------------------------------------------------------------------------
def fetch_api_info(ip, cache_dir, api_key):
    """Fallback API check using ipgeolocation.io, with its own local cache."""
    api_cache_path = os.path.join(cache_dir, "api_cache.json")
    
    # 1. Load existing API cache
    api_cache = {}
    if os.path.exists(api_cache_path):
        try:
            with open(api_cache_path, "r", encoding="utf-8") as f:
                api_cache = json.load(f)
        except Exception:
            pass
            
    # 2. Check if we already queried this IP
    if ip in api_cache:
        return api_cache[ip]
        
    # Guard against missing API key
    if not api_key:
        print(f"    [!] {ip} missed local cache, but no --api-key provided. Skipping.")
        return {"provider": "Non-cloud / Unknown", "region": "", "service": "", "cidr": ""}
        
    print(f"    [*] {ip} missed local cache. Querying ipgeolocation.io...")
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "cloud_enrich/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                
                # ipgeolocation.io fields
                org = data.get("organization") or data.get("isp") or "Unknown Org"
                city = data.get("city") or "Unknown"
                country = data.get("country_code2") or ""
                region = f"{city}, {country}".strip(", ")
                
                result = {
                    "provider": f"API: {org}",
                    "region": region,
                    "service": "External API",
                    "cidr": ""
                }
                
                # 3. Save to cache so we never query it again
                api_cache[ip] = result
                with open(api_cache_path, "w", encoding="utf-8") as f:
                    json.dump(api_cache, f, indent=2)
                    
                return result
                
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print("    [!] API Key invalid or unauthorized for ipgeolocation.io.")
        elif e.code == 429:
            print("    [!] API Rate Limit hit. Skipping further API checks for now.")
        else:
            print(f"    [!] API Error for {ip}: {e}")
    except Exception as e:
        print(f"    [!] API connection failed for {ip}: {e}")
        
    return {"provider": "Non-cloud / Unknown", "region": "", "service": "", "cidr": ""}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Offline cloud enrichment + ipgeolocation.io API fallback.")
    parser.add_argument("-i", "--input", default=None, help="Recon run folder to enrich")
    parser.add_argument("--latest", action="store_true", help="Auto-select the newest recon_* run folder")
    parser.add_argument("-d", "--domain", default=None, help="With --latest, only consider runs for this domain")
    parser.add_argument("--base-dir", default=".", help="Where to look for recon_* folders (default: current dir)")
    parser.add_argument("-o", "--output", default=None, help="Output JSON path")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE, help=f"Where cached range files live (default: {DEFAULT_CACHE})")
    parser.add_argument("--update", action="store_true", help="Refresh the range cache and exit")
    parser.add_argument("--azure-file", default=None, help="Path to a manually downloaded Azure Service Tags JSON")
    
    # NEW: Secure API Key argument
    parser.add_argument("--api-key", default=os.environ.get("IPGEO_API_KEY", ""), 
                        help="API key for ipgeolocation.io (or set IPGEO_API_KEY env var)")
    args = parser.parse_args()

    # Phase 1: refresh cache
    if args.update:
        print(f"[*] Updating range cache in {args.cache_dir}\n")
        ok = update_ranges(args.cache_dir, args.azure_file)
        print("\n[+] Cache update complete." if ok else "\n[!] Cache update finished with warnings.")
        sys.exit(0 if ok else 1)

    # Phase 2: enrich a run
    if args.latest:
        run_dir = find_latest_run(args.base_dir, args.domain)
        if not run_dir:
            print(f"[!] No recon_* run folders found in '{args.base_dir}'.")
            sys.exit(1)
        print(f"[*] Auto-selected latest run: {run_dir}")
    elif args.input:
        run_dir = args.input
    else:
        parser.error("provide -i/--input or --latest; or use --update to refresh ranges")

    if not os.path.isdir(run_dir):
        sys.exit(1)

    v4_buckets, v6_list, meta = load_ranges(args.cache_dir)
    if not any(m["loaded"] for m in meta.values()):
        sys.exit(1)

    ip_hostnames = extract_nmap_ips(run_dir)
    ips = sorted(ip_hostnames.keys())
    if not ips:
        print("\n[!] No IPs found in the run's nmap output.")
        sys.exit(1)

    # Match each IP.
    hosts = []
    summary = {}
    for ip in ips:
        best = match_ip(ip, v4_buckets, v6_list)
        if best:
            # Found in Local JSON cache
            _, provider, region, service, cidr = best
        else:
            # Fall back to free API if not found locally
            api_result = fetch_api_info(ip, args.cache_dir, args.api_key)
            provider = api_result["provider"]
            region = api_result["region"]
            service = api_result["service"]
            cidr = api_result["cidr"]

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

if __name__ == "__main__":
    main()
