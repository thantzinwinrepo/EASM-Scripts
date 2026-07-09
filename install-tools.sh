#!/usr/bin/env bash
#
# install-tools.sh — ONE-COMMAND setup for the ASM pipeline on fresh Ubuntu 24
# ---------------------------------------------------------------------------
# Does everything the manual setup needed, in order, with the gotchas fixed:
#   apt deps -> Go -> recon tools -> /usr/local/bin symlinks (fixes sudo PATH)
#   -> massdns -> nuclei templates -> dashboard venv -> PowerShell
#   -> Azure fetch -> cloud cache populate.
#
# Run from inside your cloned repo (so your *.py scripts are alongside it):
#   chmod +x install-tools.sh
#   ./install-tools.sh
#   source ~/.bashrc
#
# Installs TOOLING only — never touches data (asm_findings.db, recon_* folders).
# Safe to re-run; skips work already done. Run as normal user (uses sudo).

set -uo pipefail

GOBIN="$HOME/go/bin"
CACHE_DIR="$HOME/cloud_ranges"
# FIX: Download to a temp directory so python's shutil.copyfile doesn't trip over itself
AZURE_FILE="/tmp/azure.json"
AZURE_PAGE="https://www.microsoft.com/download/details.aspx?id=56519"
ok=0; failed=0

note() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
good() { printf '  [ok] %s\n' "$1"; ((ok++)); }
warn() { printf '  [!!] %s\n' "$1"; ((failed++)); }

valid_azure() {
    local f="$1"; [[ -f "$f" ]] || return 1
    local sz; sz=$(stat -c%s "$f" 2>/dev/null || echo 0); [[ "$sz" -ge 1000000 ]] || return 1
    [[ "$(head -c 512 "$f" | tr -d '[:space:]' | head -c 1)" == "{" ]]
}

note "0. Preflight"
[[ "$(id -u)" -eq 0 ]] && { echo "  Run as a normal user, not root."; exit 1; }
command -v sudo >/dev/null || { echo "  sudo required."; exit 1; }
good "user $(whoami) on $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Ubuntu}")"

note "1. System packages"
sudo apt-get update -y
if sudo apt-get install -y python3 python3-venv python3-full python3-pip \
        git curl wget jq nmap dnsutils build-essential libpcap-dev golang-go; then
    good "apt packages installed"
else
    warn "apt install error (see above)"
fi

note "2. Go + PATH"
command -v go >/dev/null && good "go: $(go version)" || warn "go missing"
mkdir -p "$GOBIN"
if ! grep -qs 'go/bin' "$HOME/.bashrc"; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
    good "added ~/go/bin to PATH in ~/.bashrc"
fi
export PATH="$PATH:$GOBIN"

note "3. Recon tools (go install — a few minutes)"
GO_TOOLS=(
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "asnmap|github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "alterx|github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "subjack|github.com/haccer/subjack@latest"
    "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)
for entry in "${GO_TOOLS[@]}"; do
    name="${entry%%|*}"; mod="${entry#*|}"
    if command -v "$name" >/dev/null || [[ -x "$GOBIN/$name" ]]; then
        good "$name already present"
    elif go install -v "$mod" >/dev/null 2>&1; then
        good "$name installed"
    else
        warn "$name failed ($mod)"
    fi
done

note "4. Symlink tools into /usr/local/bin (so sudo finds them)"
for t in subfinder dnsx naabu httpx shuffledns asnmap alterx subjack nuclei; do
    if [[ -x "$GOBIN/$t" ]]; then
        sudo ln -sf "$GOBIN/$t" "/usr/local/bin/$t" && good "linked $t"
    fi
done

note "5. massdns"
if command -v massdns >/dev/null; then
    good "massdns present"
else
    tmp="$(mktemp -d)"
    if git clone --depth 1 https://github.com/blechschmidt/massdns.git "$tmp/m" >/dev/null 2>&1 \
        && make -C "$tmp/m" >/dev/null 2>&1 \
        && sudo cp "$tmp/m/bin/massdns" /usr/local/bin/massdns; then
        good "massdns -> /usr/local/bin"
    else
        warn "massdns build failed"
    fi
    rm -rf "$tmp"
fi

note "6. Nuclei templates"
if command -v nuclei >/dev/null; then
    nuclei -update-templates >/dev/null 2>&1 && good "nuclei templates updated" \
        || warn "template update failed (run 'nuclei -update-templates' later)"
fi

note "7. Dashboard virtualenv (streamlit + pandas)"
VENV="$HOME/dashboard-venv"
[[ -d "$VENV" ]] || python3 -m venv "$VENV"
if [[ -x "$VENV/bin/pip" ]] && "$VENV/bin/pip" install -q --upgrade pip streamlit pandas; then
    good "streamlit + pandas ready"
else
    warn "dashboard venv setup failed"
fi

note "8. Directories + resolvers"
mkdir -p "$CACHE_DIR" && good "cache dir: $CACHE_DIR"

# Organize the cloud_ranges directory to match required structure
for f in cloud_enrich.py update_azure.sh azure.json; do
    if [[ -f "./$f" ]]; then
        cp "./$f" "$CACHE_DIR/" && chmod +x "$CACHE_DIR/$f" 2>/dev/null
        good "copied $f -> $CACHE_DIR/"
    fi
done

if [[ ! -f "$HOME/resolvers-trusted.txt" ]]; then
    curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt" \
        -o "$HOME/resolvers-trusted.txt" 2>/dev/null && [[ -s "$HOME/resolvers-trusted.txt" ]] \
        && good "starter resolvers fetched" || warn "provide your own ~/resolvers-trusted.txt"
else
    good "resolvers-trusted.txt present"
fi

note "9. PowerShell (for Azure fetch)"
if command -v pwsh >/dev/null; then
    good "PowerShell present"
elif command -v snap >/dev/null && sudo snap install powershell --classic >/dev/null 2>&1; then
    good "PowerShell installed"
else
    warn "PowerShell not installed — Azure fetch will be skipped"
fi

note "10. Cloud range cache"
ENRICH="$CACHE_DIR/cloud_enrich.py"

if [[ ! -f "$ENRICH" ]]; then
    warn "cloud_enrich.py not found in $CACHE_DIR — run its --update manually later"
else
    if command -v pwsh >/dev/null; then
        ps1="$(mktemp --suffix=.ps1)"
        cat > "$ps1" <<'PS'
$ErrorActionPreference="Stop"
$p=Invoke-WebRequest -Uri $env:AZ_PAGE -UseBasicParsing
$u=$p.Links.href | Where-Object { $_ -like '*ServiceTags_Public*' } | Select-Object -First 1
if(-not $u){exit 2}
Invoke-WebRequest -Uri $u -OutFile $env:AZ_OUT
PS
        AZ_PAGE="$AZURE_PAGE" AZ_OUT="$AZURE_FILE" pwsh -File "$ps1" >/dev/null 2>&1
        rm -f "$ps1"
    fi
    if valid_azure "$AZURE_FILE"; then
        good "Azure Service Tags fetched to $AZURE_FILE"
        python3 "$ENRICH" --update --cache-dir "$CACHE_DIR" --azure-file "$AZURE_FILE" \
            && good "cloud cache populated (all 5 providers)" || warn "cache update failed"
    else
        warn "Azure not obtained — populating the other 4 providers"
        python3 "$ENRICH" --update --cache-dir "$CACHE_DIR" \
            && good "cloud cache populated (AWS/GCP/CF/Fastly)" || warn "cache update failed"
        echo "     Add Azure later: download from $AZURE_PAGE, then re-run --update --azure-file"
    fi
fi

note "Summary"
printf '  %d step(s) OK, %d warning(s).\n' "$ok" "$failed"
cat <<'NEXT'

Reload PATH and verify:
    source ~/.bashrc
    subfinder -version && naabu -version && nmap --version | head -1

Scan (authorized targets only):
    python3 recon.py -d TARGET.com -r ~/resolvers-trusted.txt --delay 5 --skip-nmap
    sudo python3 nmap_dedup.py --latest
    python3 takeover.py --latest
    python3 ~/cloud_ranges/cloud_enrich.py --latest --cache-dir ~/cloud_ranges
    python3 asm_db.py ingest --latest --client TARGET.com

Dashboard:
    source ~/dashboard-venv/bin/activate
    streamlit run asm_dashboard.py -- --db ~/asm_findings.db
NEXT
