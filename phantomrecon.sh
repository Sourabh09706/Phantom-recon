#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║          PHANTOMRECON — Bash Launcher & Setup Script            ║
# ║              Network Reconnaissance & Mapping Suite             ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Usage:
#   ./phantomrecon.sh                    # Interactive mode
#   ./phantomrecon.sh -t 192.168.1.0/24 # Quick scan
#   ./phantomrecon.sh --install          # Install dependencies
#   ./phantomrecon.sh --update           # Update tool
#   ./phantomrecon.sh --demo             # Demo on localhost

set -euo pipefail

# ─────────────────────── Colors ────────────────────────────────────
R="\033[38;5;196m"  # Red
G="\033[38;5;82m"   # Green
Y="\033[38;5;220m"  # Yellow
C="\033[38;5;51m"   # Cyan
M="\033[38;5;201m"  # Magenta
W="\033[38;5;255m"  # White
DIM="\033[2m"
BOLD="\033[1m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/phantomrecon.py"
OUTPUT_DIR="$SCRIPT_DIR/output"
LOG_FILE="$OUTPUT_DIR/phantomrecon.log"

# ─────────────────────── Banner ────────────────────────────────────
banner() {
cat << "EOF"

  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
EOF
printf "  ${C}${BOLD}RECON${RESET} — Network Reconnaissance & Mapping Suite v1.0\n"
printf "  ${DIM}Final Year Project | Open Source | Kali Linux${RESET}\n\n"
}

# ─────────────────────── Logging ───────────────────────────────────
log()     { printf "${C}[*]${RESET} %s\n" "$*"; }
success() { printf "${G}[+]${RESET} %s\n" "$*"; }
warn()    { printf "${Y}[!]${RESET} %s\n" "$*"; }
error()   { printf "${R}[-]${RESET} %s\n" "$*" >&2; }
section() {
    local title="$1"
    local line
    line=$(printf '─%.0s' {1..60})
    printf "\n${C}${line}${RESET}\n"
    printf "${C}  ${BOLD}%s${RESET}\n" "$title"
    printf "${C}${line}${RESET}\n"
}

# ─────────────────────── Privilege Check ───────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. SYN scan and OS detection will be limited."
        warn "Run: sudo ./phantomrecon.sh $* for full functionality"
        echo ""
        read -r -p "  Continue without root? [y/N] " choice
        [[ "$choice" =~ ^[Yy]$ ]] || { log "Exiting. Run with sudo for best results."; exit 0; }
    else
        success "Running as root — full scan capabilities enabled"
    fi
}

# ─────────────────────── Dependency Installer ──────────────────────
install_dependencies() {
    section "Installing Dependencies"
    
    if ! command -v apt-get &>/dev/null; then
        error "This installer requires apt-get (Debian/Ubuntu/Kali)"
        exit 1
    fi

    log "Updating package lists..."
    apt-get update -qq

    declare -A PACKAGES=(
        ["nmap"]="Network scanner"
        ["arp-scan"]="ARP host discovery"
        ["whois"]="WHOIS lookups"
        ["dnsutils"]="DNS tools (dig, nslookup)"
        ["netdiscover"]="Passive network discovery"
        ["python3"]="Python 3 runtime"
    )

    for pkg in "${!PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            success "${pkg} — already installed"
        else
            log "Installing ${pkg} (${PACKAGES[$pkg]})..."
            if apt-get install -y -qq "$pkg" 2>/dev/null; then
                success "${pkg} installed"
            else
                warn "Could not install ${pkg}"
            fi
        fi
    done

    # Make scripts executable
    chmod +x "$PYTHON_SCRIPT" "$0"
    
    success "All dependencies handled. Run: sudo ./phantomrecon.sh"
}

# ─────────────────────── Network Interface Info ────────────────────
show_network_info() {
    section "Network Interface Information"
    
    # Get all interfaces
    while IFS= read -r iface; do
        [[ "$iface" == "lo" ]] && continue
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' || true)
        mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "N/A")
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        
        if [[ -n "$ip_addr" ]]; then
            printf "  ${Y}%-12s${RESET} ${G}%-20s${RESET} ${DIM}%s  %s${RESET}\n" \
                "$iface" "$ip_addr" "$mac" "$state"
        fi
    done < <(ls /sys/class/net/)

    echo ""
    # Default gateway
    gw=$(ip route show default 2>/dev/null | grep -oP '(?<=via\s)\d+(\.\d+){3}' | head -1 || echo "None")
    log "Default Gateway: ${Y}${gw}${RESET}"
    
    # Suggest target range
    local_ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP '(?<=src\s)\d+(\.\d+){3}' || echo "")
    if [[ -n "$local_ip" ]]; then
        # Build CIDR suggestion
        prefix=$(ip -4 addr show | grep "$local_ip" | grep -oP '/\d+' | head -1 || echo "/24")
        # Extract network
        IFS='.' read -r o1 o2 o3 o4 <<< "$local_ip"
        suggested="${o1}.${o2}.${o3}.0${prefix}"
        success "Suggested target range: ${C}${suggested}${RESET}"
        echo "$suggested"
    fi
}

# ─────────────────────── Interactive Mode ──────────────────────────
interactive_mode() {
    section "Interactive Scan Setup"
    
    # Show network info and capture suggested range
    suggested=$(show_network_info | tail -1)
    echo ""

    # Target input
    printf "  ${C}Target${RESET} (IP/CIDR) [${Y}${suggested}${RESET}]: "
    read -r target
    target="${target:-$suggested}"
    
    if [[ -z "$target" ]]; then
        error "No target specified"
        exit 1
    fi

    # Validate target
    if ! python3 -c "import ipaddress; ipaddress.ip_network('$target', strict=False)" 2>/dev/null; then
        warn "Target doesn't look like a valid IP/CIDR. Continuing anyway..."
    fi

    # Port range
    echo ""
    echo "  Port ranges:"
    printf "    ${DIM}1)${RESET} Top 1000 ports       ${DIM}(fast, ~2-5 min)${RESET}\n"
    printf "    ${DIM}2)${RESET} Common ports (1-1024) ${DIM}(standard)${RESET}\n"
    printf "    ${DIM}3)${RESET} Extended (1-10000)    ${DIM}(thorough)${RESET}\n"
    printf "    ${DIM}4)${RESET} Full (1-65535)        ${DIM}(slow, ~30+ min)${RESET}\n"
    printf "    ${DIM}5)${RESET} Custom range\n"
    printf "\n  ${C}Choice${RESET} [1]: "
    read -r port_choice

    case "${port_choice:-1}" in
        1) ports="1-1000"   ;;
        2) ports="1-1024"   ;;
        3) ports="1-10000"  ;;
        4) ports="1-65535"  ;;
        5)
            printf "  Custom ports (e.g. 22,80,443 or 1-500): "
            read -r ports
            ;;
        *) ports="1-1000"   ;;
    esac

    # Options
    echo ""
    printf "  ${C}Enable OS detection?${RESET} [Y/n]: "
    read -r os_choice
    no_os=""
    [[ "${os_choice,,}" == "n" ]] && no_os="--no-os"

    printf "  ${C}Enable banner grabbing?${RESET} [Y/n]: "
    read -r banner_choice
    no_banner=""
    [[ "${banner_choice,,}" == "n" ]] && no_banner="--no-banner"

    printf "  ${C}Output directory${RESET} [${Y}./output${RESET}]: "
    read -r out_dir
    out_dir="${out_dir:-./output}"

    echo ""
    section "Launching Scan"
    log "Target   : ${Y}${target}${RESET}"
    log "Ports    : ${Y}${ports}${RESET}"
    log "Output   : ${Y}${out_dir}${RESET}"
    echo ""

    # Run the Python engine
    run_scan "$target" "$ports" "$out_dir" "$no_os" "$no_banner"
}

# ─────────────────────── Run Scan ──────────────────────────────────
run_scan() {
    local target="$1"
    local ports="${2:-1-1000}"
    local out_dir="${3:-./output}"
    local extra_args="${4:-} ${5:-}"

    mkdir -p "$out_dir"

    # Tee output to log file
    python3 "$PYTHON_SCRIPT" \
        --target "$target" \
        --ports "$ports" \
        --out "$out_dir" \
        $extra_args \
        2>&1 | tee -a "$out_dir/scan_$(date +%Y%m%d_%H%M%S).log"
    
    local exit_code=${PIPESTATUS[0]}

    if [[ $exit_code -eq 0 ]]; then
        echo ""
        success "Scan complete!"
        
        # Find latest HTML report
        latest_report=$(find "$out_dir" -name "*.html" -newer "$PYTHON_SCRIPT" 2>/dev/null | sort | tail -1 || true)
        
        if [[ -n "$latest_report" ]]; then
            success "Report: ${C}${latest_report}${RESET}"
            echo ""
            printf "  Open report now? [Y/n]: "
            read -r open_choice
            if [[ "${open_choice,,}" != "n" ]]; then
                if command -v firefox &>/dev/null; then
                    firefox "$latest_report" &>/dev/null &
                    success "Opened in Firefox"
                elif command -v xdg-open &>/dev/null; then
                    xdg-open "$latest_report" &>/dev/null &
                    success "Opened in browser"
                else
                    warn "No browser found. Open manually: $latest_report"
                fi
            fi
        fi
    else
        error "Scan encountered errors (exit code: $exit_code)"
    fi
}

# ─────────────────────── Demo Mode ─────────────────────────────────
demo_mode() {
    section "Demo Mode — Scanning Localhost"
    warn "Demo mode scans only 127.0.0.1 — safe for testing"
    echo ""
    
    log "Starting demo scan on 127.0.0.1..."
    mkdir -p ./output
    
    python3 "$PYTHON_SCRIPT" \
        --target "127.0.0.1" \
        --ports "1-1000" \
        --no-os \
        --out "./output" \
        2>&1 | tee -a "./output/demo_$(date +%Y%m%d_%H%M%S).log"
}

# ─────────────────────── Quick Tools ───────────────────────────────
quick_port_check() {
    local ip="$1"
    local port="$2"
    section "Quick Port Check: $ip:$port"
    
    if timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
        success "${Y}${ip}:${port}${RESET} is ${G}OPEN${RESET}"
        
        # Try banner
        banner=$(echo "" | timeout 3 nc -w 2 "$ip" "$port" 2>/dev/null | head -1 || true)
        [[ -n "$banner" ]] && log "Banner: ${W}${banner}${RESET}"
    else
        warn "${Y}${ip}:${port}${RESET} is ${R}CLOSED/FILTERED${RESET}"
    fi
}

ping_sweep_bash() {
    local range="$1"
    section "Bash Ping Sweep: $range"
    warn "Quick sweep — no service detection. Use full scan for details."
    echo ""
    
    # Extract base from CIDR (only /24 supported in bash sweep)
    base=$(echo "$range" | grep -oP '\d+\.\d+\.\d+(?=\.)' || echo "192.168.1")
    
    log "Sweeping ${Y}${base}.1-254${RESET}..."
    echo ""
    
    count=0
    for i in $(seq 1 254); do
        ip="${base}.${i}"
        if ping -c 1 -W 1 "$ip" &>/dev/null 2>&1; then
            hostname=$(dig -x "$ip" +short 2>/dev/null | head -1 | sed 's/\.$//' || echo "")
            printf "  ${G}[UP]${RESET} ${Y}%-18s${RESET} %s\n" "$ip" "${hostname:-no-hostname}"
            ((count++))
        fi
    done &
    
    wait
    echo ""
    success "Found ${G}${count}${RESET} live hosts"
}

# ─────────────────────── Help ───────────────────────────────────────
show_help() {
    echo ""
    printf "  ${C}${BOLD}PhantomRecon${RESET} — Network Reconnaissance Suite\n\n"
    printf "  ${BOLD}Usage:${RESET}\n"
    printf "    sudo ./phantomrecon.sh [OPTIONS]\n\n"
    printf "  ${BOLD}Options:${RESET}\n"
    printf "    ${Y}-t, --target${RESET} <IP/CIDR>   Scan target (e.g. 192.168.1.0/24)\n"
    printf "    ${Y}-p, --ports${RESET}  <range>      Port range (default: 1-1000)\n"
    printf "    ${Y}-o, --out${RESET}    <dir>        Output directory\n"
    printf "    ${Y}--full${RESET}                   Full scan (all 65535 ports)\n"
    printf "    ${Y}--no-os${RESET}                  Skip OS detection\n"
    printf "    ${Y}--no-banner${RESET}              Skip banner grabbing\n"
    printf "    ${Y}--install${RESET}                Install all dependencies\n"
    printf "    ${Y}--demo${RESET}                   Demo scan on localhost\n"
    printf "    ${Y}--info${RESET}                   Show network interfaces\n"
    printf "    ${Y}--check IP PORT${RESET}          Quick port connectivity check\n"
    printf "    ${Y}-h, --help${RESET}               Show this help\n\n"
    printf "  ${BOLD}Examples:${RESET}\n"
    printf "    sudo ./phantomrecon.sh -t 192.168.1.0/24\n"
    printf "    sudo ./phantomrecon.sh -t 10.0.0.0/24 --full\n"
    printf "    sudo ./phantomrecon.sh -t 192.168.1.1 -p 22,80,443,8080\n"
    printf "    sudo ./phantomrecon.sh --install\n"
    printf "    sudo ./phantomrecon.sh --demo\n\n"
    printf "  ${DIM}For authorized use only. Always obtain permission before scanning.${RESET}\n\n"
}

# ─────────────────────── Version Info ──────────────────────────────
show_version() {
    python3 --version 2>&1 | head -1
    nmap --version 2>&1 | head -1 || echo "nmap: not found"
    arp-scan --version 2>&1 | head -1 || echo "arp-scan: not found"
}

# ─────────────────────── Main ──────────────────────────────────────
main() {
    banner

    # No args → interactive mode
    if [[ $# -eq 0 ]]; then
        check_root
        interactive_mode
        exit 0
    fi

    # Parse arguments
    TARGET=""
    PORTS="1-1000"
    OUT_DIR="./output"
    EXTRA_ARGS=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -p|--ports)
                PORTS="$2"
                shift 2
                ;;
            -o|--out)
                OUT_DIR="$2"
                shift 2
                ;;
            --full)
                PORTS="1-65535"
                shift
                ;;
            --no-os)
                EXTRA_ARGS="$EXTRA_ARGS --no-os"
                shift
                ;;
            --no-banner)
                EXTRA_ARGS="$EXTRA_ARGS --no-banner"
                shift
                ;;
            --no-whois)
                EXTRA_ARGS="$EXTRA_ARGS --no-whois"
                shift
                ;;
            --install)
                if [[ $EUID -ne 0 ]]; then
                    error "Installation requires root: sudo ./phantomrecon.sh --install"
                    exit 1
                fi
                install_dependencies
                exit 0
                ;;
            --demo)
                demo_mode
                exit 0
                ;;
            --info)
                show_network_info > /dev/null
                exit 0
                ;;
            --check)
                quick_port_check "$2" "$3"
                exit 0
                ;;
            --version|-v)
                show_version
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -z "$TARGET" ]]; then
        error "Target required. Use -t 192.168.1.0/24"
        show_help
        exit 1
    fi

    check_root "$@"
    
    mkdir -p "$OUT_DIR"
    run_scan "$TARGET" "$PORTS" "$OUT_DIR" "$EXTRA_ARGS"
}

main "$@"
