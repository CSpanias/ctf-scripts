#!/bin/bash

# Nmap Scanner for CTF/Pentesting
# Optimized version with concurrency, error handling, and resource management

set -euo pipefail

# Configuration
MAX_CONCURRENT_SCANS=3
SCAN_TIMEOUT=3600
MIN_RATE=1000
MAX_RATE=5000
DEFAULT_TIMING="-T4"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Argument parsing
no_udp=0
ip_list=""
IP=""
concurrent=1
quiet=0
timeout=$SCAN_TIMEOUT
timing=$DEFAULT_TIMING
output_dir="scans"

show_help() {
    cat << EOF
Nmap Scanner - Optimized for CTF and pentesting

Usage: $0 [OPTIONS] <IP-ADDRESS>
       $0 [OPTIONS] -iL <ip-list-file>

OPTIONS:
    -iL <file>           Input list of IP addresses
    --no-udp            Skip UDP scanning
    -j, --jobs <num>    Maximum concurrent scans (default: $MAX_CONCURRENT_SCANS)
    -q, --quiet         Reduce output verbosity
    -t, --timeout <sec> Scan timeout in seconds (default: $SCAN_TIMEOUT)
    --timing <level>    Nmap timing template (default: $DEFAULT_TIMING)
    -o, --output <dir>  Output directory (default: $output_dir)
    -h, --help          Show this help message

EXAMPLES:
    $0 10.10.10.10
    $0 -iL targets.txt -j 5 --no-udp
    $0 -iL targets.txt -j 3 -t 1800 --timing -T3
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-udp)
            no_udp=1
            ;;
        -iL)
            shift
            if [[ -n "$1" && -f "$1" ]]; then
                ip_list="$1"
            else
                echo -e "${RED}ERROR: Invalid or missing input list file after -iL${NC}"
                exit 1
            fi
            ;;
        -j|--jobs)
            shift
            if [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]; then
                concurrent="$1"
            else
                echo -e "${RED}ERROR: Invalid number of jobs: $1${NC}"
                exit 1
            fi
            ;;
        -q|--quiet)
            quiet=1
            ;;
        -t|--timeout)
            shift
            if [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]; then
                timeout="$1"
            else
                echo -e "${RED}ERROR: Invalid timeout value: $1${NC}"
                exit 1
            fi
            ;;
        --timing)
            shift
            timing="$1"
            ;;
        -o|--output)
            shift
            output_dir="$1"
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            if [[ -z "$IP" ]]; then
                IP="$1"
            fi
            ;;
    esac
    shift
done

if [[ -z "$ip_list" && -z "$IP" ]]; then
    echo -e "${RED}ERROR: Missing IP address or input list!${NC}"
    show_help
    exit 1
fi

# Utility functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${BLUE}[$timestamp] INFO: $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}" ;;
        "WARNING") echo -e "${YELLOW}[$timestamp] WARNING: $message${NC}" ;;
        "ERROR") echo -e "${RED}[$timestamp] ERROR: $message${NC}" ;;
    esac
}

check_prerequisites() {
    if ! command -v nmap &> /dev/null; then
        log ERROR "nmap is not installed"
        exit 1
    fi
    
    if ! sudo -n true 2>/dev/null; then
        log WARNING "sudo privileges required for full scan capabilities"
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

scan_single_host() {
    local ip="$1"
    local scan_dir="$2"
    local timestamp="$3"
    
    mkdir -p "$scan_dir"
    
    log INFO "[$ip] Checking host availability..."
    if ! timeout 30 nmap -Pn -sn "$ip" -oG - | grep -q "Status: Up"; then
        log WARNING "[$ip] Host appears down, skipping"
        return 1
    fi
    log SUCCESS "[$ip] Host is up"
    
    log INFO "[$ip] Starting full TCP port scan..."
    if ! timeout "$timeout" sudo nmap -Pn "$timing" -p- --min-rate="$MIN_RATE" --max-rate="$MAX_RATE" \
        -oA "$scan_dir/initial_port-scan_$timestamp" "$ip" > /dev/null 2>&1; then
        log ERROR "[$ip] TCP port scan failed or timed out"
        return 1
    fi
    log SUCCESS "[$ip] Initial TCP scan complete"
    
    local open_ports=""
    if [[ -f "$scan_dir/initial_port-scan_$timestamp.nmap" ]]; then
        open_ports=$(grep -E '^[0-9]+/tcp.*open' "$scan_dir/initial_port-scan_$timestamp.nmap" \
            | cut -d'/' -f1 | paste -sd, -)
    fi
    
    if [[ -z "$open_ports" ]]; then
        log WARNING "[$ip] No open TCP ports found"
    else
        log SUCCESS "[$ip] Open TCP ports: $open_ports"
        
        log INFO "[$ip] Running aggressive scan on open ports..."
        if timeout "$timeout" sudo nmap -Pn "$timing" -A -p "$open_ports" \
            -oA "$scan_dir/aggressive_scan_$timestamp" "$ip" > /dev/null 2>&1; then
            log SUCCESS "[$ip] Aggressive TCP scan completed"
        else
            log WARNING "[$ip] Aggressive scan failed, trying fallback..."
            if timeout "$timeout" sudo nmap -Pn "$timing" -sC -sV -p "$open_ports" \
                -oA "$scan_dir/fallback_scan_$timestamp" "$ip" > /dev/null 2>&1; then
                log SUCCESS "[$ip] Fallback scan completed"
            else
                log ERROR "[$ip] Both aggressive and fallback scans failed"
            fi
        fi
    fi
    
    if [[ $no_udp -eq 0 ]]; then
        log INFO "[$ip] Starting UDP scan (top 1000 ports)..."
        if timeout "$timeout" sudo nmap -Pn -sU -sV --top-ports 1000 "$timing" \
            -oA "$scan_dir/udp_scan_$timestamp" "$ip" > /dev/null 2>&1; then
            log SUCCESS "[$ip] UDP scan completed"
            
            local udp_ports=""
            if [[ -f "$scan_dir/udp_scan_$timestamp.nmap" ]]; then
                udp_ports=$(grep -E '^[0-9]+/udp.*open' "$scan_dir/udp_scan_$timestamp.nmap" \
                    | cut -d'/' -f1 | paste -sd, -)
                if [[ -n "$udp_ports" ]]; then
                    log SUCCESS "[$ip] Open UDP ports: $udp_ports"
                fi
            fi
        else
            log WARNING "[$ip] UDP scan failed or timed out"
        fi
    else
        log INFO "[$ip] UDP scan skipped"
    fi
    
    return 0
}

main() {
    check_prerequisites
    
    local ips_to_scan=()
    if [[ -n "$ip_list" ]]; then
        mapfile -t ips_to_scan < <(grep -Ev '^\s*($|#)' "$ip_list")
    else
        ips_to_scan=("$IP")
    fi
    
    local valid_ips=()
    for ip in "${ips_to_scan[@]}"; do
        if validate_ip "$ip"; then
            valid_ips+=("$ip")
        else
            log WARNING "Invalid IP format: $ip (skipping)"
        fi
    done
    
    if [[ ${#valid_ips[@]} -eq 0 ]]; then
        log ERROR "No valid IP addresses to scan"
        exit 1
    fi
    
    log INFO "Starting scan of ${#valid_ips[@]} host(s) with $concurrent concurrent jobs"
    
    mkdir -p "$output_dir"
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local pids=()
    local completed=0
    local failed=0
    
    for ip in "${valid_ips[@]}"; do
        local scan_dir="$output_dir/$ip"
        
        while [[ ${#pids[@]} -ge $concurrent ]]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}"
                    if [[ $? -eq 0 ]]; then
                        ((completed++))
                    else
                        ((failed++))
                    fi
                    unset "pids[$i]"
                fi
            done
            pids=("${pids[@]}")
            sleep 1
        done
        
        scan_single_host "$ip" "$scan_dir" "$timestamp" &
        pids+=($!)
        
        if [[ $quiet -eq 0 ]]; then
            log INFO "Started scan for $ip (PID: $!)"
        fi
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
        if [[ $? -eq 0 ]]; then
            ((completed++))
        else
            ((failed++))
        fi
    done
    
    echo
    log SUCCESS "Scan completed! Summary:"
    log INFO "  Completed: $completed"
    log INFO "  Failed: $failed"
    log INFO "  Output directory: $output_dir"
    
    if [[ $completed -gt 0 ]]; then
        echo
        log INFO "Quick results preview:"
        for ip in "${valid_ips[@]}"; do
            local scan_dir="$output_dir/$ip"
            if [[ -d "$scan_dir" ]]; then
                local tcp_file=$(find "$scan_dir" -name "*aggressive_scan_$timestamp.nmap" -o -name "*fallback_scan_$timestamp.nmap" | head -1)
                if [[ -n "$tcp_file" ]]; then
                    echo -e "${BLUE}  $ip:${NC} $(grep -c "open" "$tcp_file" 2>/dev/null || echo "0") open TCP ports"
                fi
            fi
        done
    fi
}

main "$@"
