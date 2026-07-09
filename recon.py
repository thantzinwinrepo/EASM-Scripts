#!/usr/bin/env python3
"""
Automated ProjectDiscovery Recon Pipeline
------------------------------------------
subfinder -> alterx -> shuffledns -> dnsx -> naabu -> httpx

Improvements over the original:
  * Uniform step runner (one flaky tool degrades the run instead of aborting it)
  * Empty-input guards (skip a stage if the previous one produced nothing)
  * Per-target timestamped output directory (no cross-engagement overwrites)
  * Deduplicated subdomain merge
  * httpx writes JSON output (ready for MISP / n8n ingestion)
  * Tool paths configurable via CLI (no hardcoded ./alterx dependency on CWD)
  * Optional --skip-nmap: stop before the built-in nmap stage (e.g. for
    shared-hosting targets, to run a dedup-by-IP nmap tool separately)
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def cool_down(seconds):
    """Pause between tools to avoid system/network overload."""
    if seconds > 0:
        print(f"\n[~] Cooling down for {seconds} seconds...")
        time.sleep(seconds)


def has_content(path):
    """True only if the file exists and is non-empty."""
    return os.path.exists(path) and os.path.getsize(path) > 0


def run_step(cmd, label, stdin=None):
    """
    Run a single tool. Never raises: a non-zero exit is logged and the
    pipeline continues, so one rate-limited tool doesn't cost you the run.
    Returns True on success (exit 0), False otherwise.
    """
    print(f"\n[*] {label}")
    print(f"    $ {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, stdin=stdin)
    except FileNotFoundError:
        print(f"[!] {label}: binary not found ('{cmd[0]}') — is it on $PATH? Skipping.")
        return False
    except Exception as exc:  # noqa: BLE001 - we want the pipeline to survive anything
        print(f"[!] {label}: unexpected error: {exc}. Skipping.")
        return False

    if result.returncode != 0:
        print(f"[!] {label}: exited with code {result.returncode} (continuing)")
        return False
    return True


def merge_dedup(sources, dest):
    """Merge line-oriented files into dest, stripped and deduplicated."""
    seen = set()
    for fname in sources:
        if has_content(fname):
            with open(fname, "r", encoding="utf-8", errors="ignore") as infile:
                seen.update(line.strip() for line in infile if line.strip())
    with open(dest, "w", encoding="utf-8") as outfile:
        outfile.write("\n".join(sorted(seen)))
        if seen:
            outfile.write("\n")
    return len(seen)


def parse_naabu_hosts(naabu_file):
    """
    Parse naabu 'host:port' output into {host: [ports]}.
    Splits on the LAST colon so hostnames and IPv4 are safe, and handles
    bracketed IPv6 ('[2001:db8::1]:443') explicitly.
    """
    host_ports = {}
    with open(naabu_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("[") and "]:" in line:            # [ipv6]:port
                host, _, port = line.rpartition("]:")
                host = host.lstrip("[")
            else:                                                 # host:port / ipv4:port
                host, sep, port = line.rpartition(":")
                if not sep:
                    continue
            port = port.strip()
            if port.isdigit():
                host_ports.setdefault(host, set()).add(port)
    return {h: sorted(p, key=int) for h, p in host_ports.items()}


def run_nmap_host(host, ports, nmap_dir, timing):
    """Deep-scan a single host on exactly the ports naabu found open."""
    port_list = ",".join(ports)
    safe_name = host.replace(":", "_").replace("/", "_")
    base = os.path.join(nmap_dir, f"nmap_{safe_name}")   # -> .nmap/.gnmap/.xml
    cmd = [
        "nmap", "-Pn", "-sV", "-sC", f"-T{timing}",
        "-p", port_list, "-oA", base, host,
    ]
    try:
        # Suppress per-host stdout so parallel runs don't interleave;
        # full output is preserved in the -oA files.
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return (host, False, "nmap binary not found on $PATH")
    except Exception as exc:  # noqa: BLE001
        return (host, False, str(exc))
    return (host, os.path.exists(base + ".xml"), f"{len(ports)} port(s)")


def run_nmap_deep_scan(naabu_file, outdir, timing, max_workers):
    """
    Parse naabu output and run capped-concurrency nmap deep scans,
    one invocation per host on only that host's open ports.
    """
    host_ports = parse_naabu_hosts(naabu_file)
    if not host_ports:
        print("[!] No host:port pairs parsed from naabu output — skipping nmap.")
        return

    nmap_dir = os.path.join(outdir, "nmap")
    os.makedirs(nmap_dir, exist_ok=True)
    print(f"    Targets: {len(host_ports)} host(s), up to {max_workers} in parallel")
    print(f"    Per-host output (.nmap/.gnmap/.xml) -> {nmap_dir}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run_nmap_host, host, ports, nmap_dir, timing): host
            for host, ports in host_ports.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            host, ok, info = fut.result()
            print(f"    [nmap {'OK ' if ok else 'FAIL'}] {host} ({info})")


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------
def run_recon_workflow(domain, resolvers_file, delay, alterx_bin, outdir,
                       nmap_timing, nmap_workers, skip_nmap=False):
    os.makedirs(outdir, exist_ok=True)

    # Output file paths, all scoped to this run's directory.
    subfinder_out = os.path.join(outdir, "subfinder_result.txt")
    alterx_out = os.path.join(outdir, "alterx_result.txt")
    unverified = os.path.join(outdir, "unverified_subdomain.txt")
    shuffledns_out = os.path.join(outdir, "shuffledns_result.txt")
    dnsx_out = os.path.join(outdir, "dnsx_result.txt")
    naabu_out = os.path.join(outdir, "naabu_result.txt")
    httpx_out = os.path.join(outdir, "httpx_result.json")
    techstack_out = os.path.join(outdir, "techstack_result.txt")

    print(f"[*] Starting recon workflow for: {domain}")
    print(f"[*] Output directory: {outdir}")
    print("=" * 50)

    # -- STEP 1: Subfinder -------------------------------------------------
    run_step(
        ["subfinder", "-d", domain, "-all", "-silent", "-o", subfinder_out],
        "Running Subfinder (passive subdomain enumeration)",
    )
    if not has_content(subfinder_out):
        print("[!] Subfinder produced no results — nothing to work with. Aborting.")
        return
    cool_down(delay)

    # -- STEP 2: Alterx ----------------------------------------------------
    with open(subfinder_out, "r", encoding="utf-8", errors="ignore") as sub_in:
        run_step(
            [alterx_bin, "-silent", "-o", alterx_out],
            "Running Alterx (permutation generation)",
            stdin=sub_in,
        )
    cool_down(delay)

    # -- STEP 3: Merge + dedup --------------------------------------------
    count = merge_dedup([subfinder_out, alterx_out], unverified)
    print(f"\n[3] Combined {count} unique candidate subdomains -> {unverified}")
    if not has_content(unverified):
        print("[!] No candidate subdomains to resolve. Aborting.")
        return
    cool_down(delay)

    # -- STEP 4: Shuffledns (resolve) -------------------------------------
    if not has_content(resolvers_file):
        print(f"[!] Resolvers file '{resolvers_file}' missing or empty. Aborting.")
        return
    run_step(
        [
            "shuffledns", "-mode", "resolve", "-list", unverified,
            "-d", domain, "-r", resolvers_file, "-silent", "-o", shuffledns_out,
        ],
        "Running Shuffledns (mass DNS resolution)",
    )
    if not has_content(shuffledns_out):
        print("[!] Shuffledns resolved nothing. Aborting.")
        return
    cool_down(delay)

    # -- STEP 5: Dnsx -----------------------------------------------------
    run_step(
        ["dnsx", "-l", shuffledns_out, "-silent", "-o", dnsx_out],
        "Running Dnsx (filtering live subdomains)",
    )
    if not has_content(dnsx_out):
        print("[!] No live hosts from dnsx — skipping naabu/httpx.")
        return
    cool_down(delay)

    # -- STEP 6: Naabu ----------------------------------------------------
    run_step(
        ["naabu", "-list", dnsx_out, "-silent", "-o", naabu_out],
        "Running Naabu (port scanning)",
    )
    if not has_content(naabu_out):
        print("[!] Naabu found no open ports — skipping httpx.")
        return
    cool_down(delay)

    # -- STEP 7: Httpx ----------------------------------------------------
    run_step(
        [
            "httpx", "-l", naabu_out,
            "-title", "-status-code", "-tech-detect",
            "-json", "-o", httpx_out,
        ],
        "Running Httpx (probing active services)",
    )
    cool_down(delay)

    # -- STEP 8: Httpx tech-stack fingerprint -----------------------------
    # Human-readable pass to identify web technologies (server, CMS,
    # frameworks, etc.) alongside title and status code.
    run_step(
        [
            "httpx", "-l", naabu_out,
            "-title", "-status-code", "-tech-detect",
            "-o", techstack_out,
        ],
        "Running Httpx (tech-stack fingerprinting)",
    )
    cool_down(delay)

    # -- STEP 9: Nmap deep scan -------------------------------------------
    # Consumes the naabu output (step 6). Runs -sV -sC per host on ONLY the
    # ports naabu confirmed open, with -Pn (host already known up) and a
    # capped worker pool so concurrent scans don't overload the network.
    if skip_nmap:
        print("\n[*] Nmap stage skipped (--skip-nmap).")
        print("    naabu output is ready for a separate nmap tool:")
        print(f"      {naabu_out}")
    else:
        print("\n[*] Running Nmap (deep service/script scan on open ports)")
        run_nmap_deep_scan(naabu_out, outdir, nmap_timing, nmap_workers)

    print("\n" + "=" * 50)
    print(f"[+] Workflow completed for {domain}")
    print(f"[+] Artifacts saved under: {outdir}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Automated ProjectDiscovery Recon Pipeline"
    )
    parser.add_argument("-d", "--domain", required=True,
                        help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-r", "--resolvers", default="resolvers-trusted.txt",
                        help="Path to your trusted resolvers file")
    parser.add_argument("--delay", type=int, default=5,
                        help="Sleep delay in seconds between tools (default: 5)")
    parser.add_argument("--alterx-bin", default="./alterx/alterx",
                        help="Path to the alterx binary (default: ./alterx/alterx)")
    parser.add_argument("-o", "--outdir", default=None,
                        help="Output directory (default: recon_<domain>_<timestamp>)")
    parser.add_argument("--nmap-timing", type=int, default=3, choices=range(0, 6),
                        help="Nmap -T timing template 0-5 (default: 3)")
    parser.add_argument("--nmap-workers", type=int, default=3,
                        help="Max parallel nmap processes (default: 3)")
    parser.add_argument("--skip-nmap", action="store_true",
                        help="Stop before the built-in nmap stage "
                             "(e.g. for shared-hosting targets — run a dedup nmap tool separately)")

    args = parser.parse_args()

    outdir = args.outdir or f"recon_{args.domain}_{time.strftime('%Y%m%d_%H%M%S')}"

    try:
        run_recon_workflow(
            domain=args.domain,
            resolvers_file=args.resolvers,
            delay=args.delay,
            alterx_bin=args.alterx_bin,
            outdir=outdir,
            nmap_timing=args.nmap_timing,
            nmap_workers=args.nmap_workers,
            skip_nmap=args.skip_nmap,
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user — partial results preserved in the output dir.")
        sys.exit(130)
