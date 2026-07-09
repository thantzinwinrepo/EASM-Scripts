#!/usr/bin/env bash
#
# install-tools.sh — set up the ASM pipeline on a fresh Ubuntu 24 machine
# -----------------------------------------------------------------------
# Installs everything the core pipeline needs:
#   apt deps -> Go -> ProjectDiscovery tools + subjack -> massdns ->
#   dashboard venv (streamlit/pandas) -> directory layout.
#
# It does NOT copy your data (asm_findings.db, recon_* folders) — those live
# only on your machine/backups. This sets up the TOOLING; you bring your own
# scripts (recon.py, nmap_dedup.py, takeover.py, cloud_enrich.py, asm_db.py,
# asm_dashboard.py) and data separately.
#
# Safe to re-run: it skips steps whose result already exists where it can.
#
# Usage:
#   chmod +x install-tools.sh
#   ./install-tools.sh
#
# Run as your normal user (NOT root) — it uses sudo only where needed.

set -uo pipefail

GOBIN="$HOME/go/bin"
ok=0; failed=0
note()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
good()  { printf '  [ok]   %s\n' "$1"; ((ok++)); }
warn()  { printf '  [!!]   %s\n' "$1"; ((failed++)); }

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------
note "0. Preflight checks"
if [[ "$(id -u)" -eq 0 ]]; then
    echo "  Please run as a normal user, not root (sudo is used where needed)."
    exit 1
fi
if ! command -v sudo >/dev/null; then
    echo "  'sudo' is required but not found. Install it first."
    exit 1
fi
good "running as $(whoami) on $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown OS}")"

# ---------------------------------------------------------------------------
# 1. System packages (apt)
# ---------------------------------------------------------------------------
note "1. Installing system packages (apt)"
sudo apt-get update -y
APT_PKGS=(
    python3 python3-venv python3-full python3-pip
    git curl wget jq
    nmap dnsutils
    build-essential libpcap-dev
    golang-go
)
if sudo apt-get install -y "${APT_PKGS[@]}"; then
    good "apt packages installed (${#APT_PKGS[@]} packages)"
else
    warn "apt install hit an error — check the output above"
fi

# ---------------------------------------------------------------------------
# 2. Go toolchain check + PATH
# ---------------------------------------------------------------------------
note "2. Go toolchain"
if command -v go >/dev/null; then
    good "go present: $(go version)"
else
    warn "go not found after apt install — install Go manually, then re-run"
fi
mkdir -p "$GOBIN"
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$GOBIN"; then
    if ! grep -qs 'go/bin' "$HOME/.bashrc"; then
        echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
        good "added ~/go/bin to PATH in ~/.bashrc (run: source ~/.bashrc)"
    fi
fi
export PATH="$PATH:$GOBIN"

# ---------------------------------------------------------------------------
# 3. Go-based recon tools
# ---------------------------------------------------------------------------
note "3. Installing Go-based tools (this can take a few minutes)"
# name  ->  go module path
GO_TOOLS=(
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "subjack|github.com/haccer/subjack@latest"
)
for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%|*}"; mod="${entry#*|}"
    if command -v "$name" >/dev/null; then
        good "$name already installed"
        continue
    fi
    printf '  installing %s ...\n' "$name"
    if go install -v "$mod" >/dev/null 2>&1; then
        good "$name -> $GOBIN/$name"
    else
        warn "$name failed to install ($mod)"
    fi
done

# ---------------------------------------------------------------------------
# 4. massdns (compiled from source; needed by shuffledns)
# ---------------------------------------------------------------------------
note "4. massdns"
if command -v massdns >/dev/null; then
    good "massdns already installed"
else
    tmp="$(mktemp -d)"
    if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$tmp/massdns" >/dev/null 2>&1 \
        && make -C "$tmp/massdns" >/dev/null 2>&1 \
        && sudo cp "$tmp/massdns/bin/massdns" /usr/local/bin/massdns; then
        good "massdns -> /usr/local/bin/massdns"
    else
        warn "massdns build failed — install manually from github.com/blechschmidt/massdns"
    fi
    rm -rf "$tmp"
fi

# ---------------------------------------------------------------------------
# 5. Dashboard Python environment (streamlit + pandas in a venv)
# ---------------------------------------------------------------------------
note "5. Dashboard virtualenv"
VENV="$HOME/dashboard-venv"
if [[ -d "$VENV" ]]; then
    good "venv already exists at $VENV"
else
    if python3 -m venv "$VENV"; then
        good "created venv at $VENV"
    else
        warn "venv creation failed (need python3-venv?)"
    fi
fi
if [[ -x "$VENV/bin/pip" ]]; then
    if "$VENV/bin/pip" install --quiet --upgrade pip streamlit pandas; then
        good "streamlit + pandas installed in venv"
    else
        warn "pip install into venv failed"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Directory layout + starter data
# ---------------------------------------------------------------------------
note "6. Directories + starter config"
mkdir -p "$HOME/cloud_ranges" && good "cloud range cache dir: ~/cloud_ranges"

# A trusted-resolvers starter list (refine/replace with your own vetted list).
if [[ -f "$HOME/resolvers-trusted.txt" ]]; then
    good "resolvers-trusted.txt already present"
else
    if curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
        -o "$HOME/resolvers-trusted.txt" 2>/dev/null \
        && [[ -s "$HOME/resolvers-trusted.txt" ]]; then
        good "fetched a starter resolvers-trusted.txt (review/replace as needed)"
    else
        warn "couldn't fetch resolvers list — provide your own ~/resolvers-trusted.txt"
    fi
fi

# ---------------------------------------------------------------------------
# 7. Optional extras (uncomment what you actually use)
# ---------------------------------------------------------------------------
# note "7. Optional extras"
# go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# git clone https://github.com/projectdiscovery/nuclei-templates.git "$HOME/nuclei-templates"
# git clone https://github.com/laramies/theHarvester.git "$HOME/theHarvester"
# git clone https://github.com/owasp-amass/amass.git   # or: go install ...
# git clone https://github.com/initstring/cloud_enum.git "$HOME/cloud_enum"
# pipx install trufflehog   # or download the release binary

# ---------------------------------------------------------------------------
# Summary + next steps
# ---------------------------------------------------------------------------
note "Summary"
printf '  %d step(s) OK, %d warning(s).\n' "$ok" "$failed"

cat <<'NEXT'

Next steps (not automated — you provide these):
  1. Reload PATH:            source ~/.bashrc
  2. Copy your scripts in:   recon.py, nmap_dedup.py, takeover.py,
                             cloud_ranges/cloud_enrich.py, asm_db.py,
                             asm_dashboard.py   (from your GitHub repo)
  3. Populate cloud ranges:  python3 cloud_ranges/cloud_enrich.py --update \
                               --cache-dir ~/cloud_ranges --azure-file <ServiceTags.json>
  4. Verify tools:           subfinder -version; naabu -version; nmap --version
  5. Run the dashboard:      source ~/dashboard-venv/bin/activate
                             streamlit run asm_dashboard.py -- --db ~/asm_findings.db

Notes:
  * naabu SYN scanning and nmap -sC need root — run those steps with sudo.
  * alterx installs to ~/go/bin/alterx, so run recon with:
        --alterx-bin ~/go/bin/alterx
  * subjack: this installs haccer/subjack@latest. If you relied on -ar/-mail/
    -axfr flags, verify with 'subjack -h' — those may come from a fork.
NEXT
