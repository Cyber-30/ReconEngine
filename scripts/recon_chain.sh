#!/bin/bash
# ShadowRecon - Automated Reconnaissance Chain Script
set -e
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m' BOLD='\033[1m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/output"
LOGS_DIR="${PROJECT_ROOT}/logs"
VENV_PATH="/home/sourya/Workspace/.venv"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║  ShadowRecon Automated Recon Chain                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

setup_environment() {
    print_status "Setting up environment..."
    mkdir -p "$OUTPUT_DIR" "$LOGS_DIR"
    if [ -d "$VENV_PATH" ]; then
        source "$VENV_PATH/bin/activate"
        print_success "Virtual environment activated"
    else
        print_warning "Virtual environment not found"
    fi
}

check_dependencies() {
    print_status "Checking dependencies..."
    for cmd in python3 curl jq; do
        if ! command -v $cmd &> /dev/null; then
            print_warning "$cmd not found"
        fi
    done
    print_success "Dependencies check complete"
}

run_whois_lookup() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_whois.txt"
    print_status "Running WHOIS lookup on $target..."
    if command -v whois &> /dev/null; then
        whois "$target" > "$output_file" 2>&1
        print_success "WHOIS results saved to $output_file"
    else
        print_warning "whois command not found"
    fi
}

run_dns_enumeration() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_dns.txt"
    print_status "Running DNS enumeration on $target..."
    {
        echo "DNS Records for: $target"
        echo "Generated: $(date)"
        echo "================================"
        echo -e "\n[A Records]"
        (command -v dig &> /dev/null && dig +short A "$target") || (command -v host &> /dev/null && host -t A "$target")
        echo -e "\n[MX Records]"
        (command -v dig &> /dev/null && dig +short MX "$target") || (command -v host &> /dev/null && host -t MX "$target")
        echo -e "\n[NS Records]"
        (command -v dig &> /dev/null && dig +short NS "$target") || (command -v host &> /dev/null && host -t NS "$target")
    } > "$output_file"
    print_success "DNS enumeration saved to $output_file"
}

run_subdomain_enumeration() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_subdomains.txt"
    print_status "Running subdomain enumeration on $target..."
    {
        echo "Subdomains for: $target"
        echo "Generated: $(date)"
        echo "================================"
        echo -e "\n[CRT.sh Results]"
        if command -v curl &> /dev/null && command -v jq &> /dev/null; then
            curl -s "https://crt.sh/?q=${target}&output=json" 2>/dev/null | jq -r '.[].common_name' 2>/dev/null | sed 's/^\*\.//' | sort -u || echo "No results"
        fi
        echo -e "\n[Common Subdomains]"
        for sub in www mail ftp admin test dev staging api blog; do
            (host "${sub}.${target}" &>/dev/null && echo "${sub}.${target}") || true
        done
    } > "$output_file"
    print_success "Subdomain enumeration saved to $output_file"
}

run_port_scan() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_ports.txt"
    print_status "Running port scan on $target..."
    {
        echo "Port Scan for: $target"
        echo "Generated: $(date)"
        echo "================================"
        if command -v nmap &> /dev/null; then
            nmap -F --open -oN - "$target" 2>/dev/null || echo "Nmap scan failed"
        elif command -v nc &> /dev/null; then
            for port in 21 22 23 25 53 80 110 143 443 993 995 3306 3389 5432 8080 8443; do
                timeout 1 nc -z -w 1 "$target" $port 2>/dev/null && echo "Port $port: OPEN"
            done
        else
            echo "Neither nmap nor netcat available"
        fi
    } > "$output_file"
    print_success "Port scan results saved to $output_file"
}

run_wayback_enumeration() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_wayback.txt"
    print_status "Running Wayback Machine enumeration on $target..."
    {
        echo "Wayback Machine snapshots for: $target"
        if command -v curl &> /dev/null && command -v jq &> /dev/null; then
            curl -s "https://web.archive.org/cdx/search/cdx?url=${target}/*&output=json&limit=100" 2>/dev/null | jq -r '.[1:] | .[0] as $first | $first[2] as $last | "\($first[2]) - \($last[2])"' 2>/dev/null || echo "No snapshots"
        fi
    } > "$output_file"
    print_success "Wayback enumeration saved to $output_file"
}

run_ssl_analysis() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_ssl.txt"
    print_status "Running SSL/TLS analysis on $target..."
    {
        echo "SSL/TLS Analysis for: $target"
        if command -v openssl &> /dev/null; then
            echo "" | openssl s_client -connect "${target}:443" -servername "$target" 2>/dev/null | openssl x509 -noout -dates -subject 2>/dev/null || echo "SSL cert retrieval failed"
        fi
    } > "$output_file"
    print_success "SSL analysis saved to $output_file"
}

run_tech_detection() {
    local target=$1
    local output_file="${OUTPUT_DIR}/${target}_tech.txt"
    print_status "Running technology detection on $target..."
    {
        echo "Technology Detection for: $target"
        if command -v curl &> /dev/null; then
            echo "[HTTP Headers]"
            curl -sI "http://${target}" 2>/dev/null | head -10
        fi
    } > "$output_file"
    print_success "Technology detection saved to $output_file"
}

run_passive_recon() {
    local target=$1
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  PASSIVE RECONNAISSANCE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    run_whois_lookup "$target"
    run_dns_enumeration "$target"
    run_subdomain_enumeration "$target"
    run_wayback_enumeration "$target"
    run_ssl_analysis "$target"
    run_tech_detection "$target"
}

run_active_recon() {
    local target=$1
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ACTIVE RECONNAISSANCE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════${NC}"
    run_port_scan "$target"
}

generate_summary() {
    local target=$1
    local summary_file="${OUTPUT_DIR}/${target}_summary_${TIMESTAMP}.txt"
    {
        echo "ShadowRecon Summary Report"
        echo "=========================="
        echo "Target: $target"
        echo "Generated: $(date)"
        echo ""
        echo "Files Generated:"
        ls -la "${OUTPUT_DIR}/${target}_"* 2>/dev/null || echo "No files"
    } > "$summary_file"
    print_success "Summary saved to $summary_file"
}

usage() {
    echo "Usage: $0 [OPTIONS] TARGET"
    echo "Options:"
    echo "  -h, --help              Show help"
    echo "  -p, --passive           Passive recon only"
    echo "  -a, --active            Active recon"
    echo "  -f, --full              Full recon"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 -f example.com"
}

main() {
    MODE="passive"
    TARGET=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) usage; exit 0 ;;
            -p|--passive) MODE="passive"; shift ;;
            -a|--active) MODE="active"; shift ;;
            -f|--full) MODE="full"; shift ;;
            -*) print_error "Unknown option: $1"; exit 1 ;;
            *) TARGET="$1"; shift ;;
        esac
    done
    
    if [ -z "$TARGET" ]; then
        print_error "No target specified"
        usage
        exit 1
    fi
    
    print_banner
    setup_environment
    check_dependencies
    
    print_status "Target: $TARGET"
    print_status "Mode: $MODE"
    
    case $MODE in
        passive) run_passive_recon "$TARGET" ;;
        active) run_active_recon "$TARGET" ;;
        full) run_passive_recon "$TARGET"; run_active_recon "$TARGET" ;;
    esac
    
    generate_summary "$TARGET"
    
    echo ""
    echo -e "${GREEN}Reconnaissance complete! Results in: $OUTPUT_DIR${NC}"
}

main "$@"
