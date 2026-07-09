#!/usr/bin/env python3
"""
Subdomain Takeover Check (subjack wrapper)
------------------------------------------
Standalone tool. Does NOT modify or depend on recon.py — your existing
pipeline is untouched.

It consumes the dnsx output (resolved, live subdomains) from a recon run and
screens it for subdomain-takeover indicators using subjack.

Point it at either:
  * the dnsx result file directly:   -i recon_.../dnsx_result.txt
  * or the whole run folder:         -i recon_myanmar-brewery.com_20260704_105337/
    (it will locate dnsx_result.txt inside and write results back into the
     same folder, keeping each run a self-contained evidence package)

IMPORTANT: subjack is a SCREENING tool. It flags *candidates*. Every positive
must be verified manually before it goes into a client report — especially the
aggressive checks (-ar / -mail / -axfr), which are noisy and false-positive
prone (a live host behind a WAF/CDN that ignores probes can look "dead").
"""

import argparse
import json
import os
import re
import subprocess
import sys

# Recon run folders are named recon_<domain>_<YYYYMMDD_HHMMSS>.
RUN_TIMESTAMP_RE = re.compile(r"_(\d{8}_\d{6})$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def has_content(path):
    """True only if the path is a file that exists and is non-empty."""
    return os.path.isfile(path) and os.path.getsize(path) > 0


def resolve_input(path):
    """
    Accept either the dnsx result file directly, or a recon run folder that
    contains dnsx_result.txt. Returns the path to the subdomain list to feed
    subjack.
    """
    if os.path.isdir(path):
        return os.path.join(path, "dnsx_result.txt")
    return path


def find_latest_run(base_dir, domain=None):
    """
    Find the newest recon_* run folder under base_dir, optionally filtered to a
    single domain. Ordered by the timestamp embedded in the folder name (with
    directory mtime as a tiebreaker). Returns the folder path, or None.
    """
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


def default_output(input_file, explicit):
    """Place results beside the input (i.e. inside the run folder) by default."""
    if explicit:
        return explicit
    outdir = os.path.dirname(os.path.abspath(input_file))
    return os.path.join(outdir, "takeover_result.json")


def build_command(subjack_bin, input_file, output_file, args):
    """Assemble the subjack command line from the parsed arguments."""
    cmd = [
        subjack_bin,
        "-w", input_file,
        "-o", output_file,
        "-t", str(args.threads),
        "-timeout", str(args.timeout),
    ]
    if args.ssl:
        cmd.append("-ssl")
    if args.all_hosts:
        cmd.append("-a")
    if args.resolvers:
        cmd += ["-r", args.resolvers]
    if args.fingerprints:
        cmd += ["-c", args.fingerprints]
    if args.extra_args:
        # Raw passthrough for aggressive/optional flags (e.g. "-ar -mail").
        cmd += args.extra_args.split()
    return cmd


def summarize(output_file):
    """
    subjack writes its results as JSON. Read them back for a quick, readable
    count/list so you don't have to open the file to know what was flagged.
    """
    if not has_content(output_file):
        print("[+] No takeover indicators recorded (clean / empty result).")
        return

    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        print(f"[!] Could not parse {output_file} as JSON — inspect it manually.")
        return

    if isinstance(data, list) and data:
        n = len(data)
        print(f"[+] subjack flagged {n} entr{'y' if n == 1 else 'ies'} -> {output_file}")
        for item in data:
            if isinstance(item, dict):
                sub = item.get("subdomain") or item.get("Subdomain") or "?"
                svc = item.get("service") or item.get("Service") or "?"
                print(f"    - {sub}  ({svc})")
            else:
                print(f"    - {item}")
    else:
        print(f"[+] No entries flagged. Results file: {output_file}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Subdomain takeover screening via subjack (reads dnsx output)."
    )
    parser.add_argument("-i", "--input", default=None,
                        help="dnsx result file, OR a recon run folder containing dnsx_result.txt")
    parser.add_argument("--latest", action="store_true",
                        help="Auto-select the newest recon_* run folder (no need to type the path)")
    parser.add_argument("-d", "--domain", default=None,
                        help="With --latest, only consider runs for this domain (e.g. example.com)")
    parser.add_argument("--base-dir", default=".",
                        help="Where to look for recon_* folders when using --latest (default: current dir)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output JSON path (default: takeover_result.json beside the input)")
    parser.add_argument("--subjack-bin", default="subjack",
                        help="Path to the subjack binary (default: 'subjack' on $PATH)")
    parser.add_argument("-r", "--resolvers", default=None,
                        help="Optional trusted resolvers file (passed to subjack -r)")
    parser.add_argument("-c", "--fingerprints", default=None,
                        help="Optional subjack fingerprints JSON (passed to subjack -c)")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=True,
                        help="Force HTTPS checks (default: on; use --no-ssl to disable)")
    parser.add_argument("--all-hosts", action="store_true",
                        help="subjack -a: probe every host, not just identified CNAMEs "
                             "(broader coverage, slower)")
    parser.add_argument("--extra-args", default=None,
                        help="Raw extra flags passed straight to subjack, e.g. \"-ar -mail\". "
                             "WARNING: aggressive checks (-ar/-mail/-axfr) are noisy and "
                             "false-positive prone — verify every hit manually.")

    args = parser.parse_args()

    # Decide where the input comes from: --latest auto-picks the newest run,
    # otherwise fall back to an explicit -i path.
    if args.latest:
        input_arg = find_latest_run(args.base_dir, args.domain)
        if not input_arg:
            scope = f" for domain '{args.domain}'" if args.domain else ""
            print(f"[!] No recon_* run folders found{scope} in '{args.base_dir}'.")
            sys.exit(1)
        print(f"[*] Auto-selected latest run: {input_arg}")
    elif args.input:
        input_arg = args.input
    else:
        parser.error("provide -i/--input, or use --latest to auto-pick the newest recon run")

    # Resolve and validate input.
    input_file = resolve_input(input_arg)
    if not has_content(input_file):
        print(f"[!] Input '{input_file}' is missing or empty.")
        if os.path.isdir(input_arg):
            print("    (Pointed at a folder, but no non-empty dnsx_result.txt was found inside.)")
        sys.exit(1)

    # Resolve output and make sure its directory exists.
    output_file = default_output(input_file, args.output)
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    cmd = build_command(args.subjack_bin, input_file, output_file, args)

    print(f"[*] Input : {input_file}")
    print(f"[*] Output: {output_file}")
    print(f"[*] Running: {' '.join(cmd)}\n")

    if args.extra_args:
        print("[!] Aggressive checks enabled via --extra-args. Treat ALL hits as "
              "UNVERIFIED until manually confirmed.\n")

    # Run subjack. Let stdout stream live so you see findings as they land;
    # the JSON evidence is written to the output file via subjack's -o.
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print(f"[!] subjack binary not found ('{args.subjack_bin}'). "
              "Install it or pass --subjack-bin /path/to/subjack.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted — partial results may be in the output file.")
        sys.exit(130)

    print()
    summarize(output_file)
    print("\n[i] Reminder: subjack screens for candidates only. Verify each hit "
          "manually (dig the CNAME, check the service's claim status) before "
          "reporting anything to a client.")


if __name__ == "__main__":
    main()
