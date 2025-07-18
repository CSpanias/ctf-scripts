#!/bin/bash

# -----------------------------------------------------------------------------
# NMAP-SCAN: Optimized Nmap Scanner for CTF/Pentesting
#
# Author: x7331
# Version: 2.0
#
# Description:
#   Fast, concurrent, and robust Nmap scanning for CTFs, labs, and pentesting.
#   Supports hostnames, IPs, input lists, and both TCP/UDP scans with output
#   management and error handling. Designed for quick recon and automation.
#
# Usage:
#   ./nmap-scan.sh [OPTIONS] <TARGET>
#   ./nmap-scan.sh [OPTIONS] -iL <target-list-file>
#
#   TARGET can be:
#     - IP address (e.g., 192.168.1.1)
#     - Hostname (e.g., charlie, server.local)
#     - FQDN (e.g., www.example.com)
#
#   OPTIONS:
#     -iL <file>          Input list of targets (IPs or hostnames)
#     --no-udp            Skip UDP scanning
#     -j, --jobs <num>    Maximum concurrent scans (default: 3)
#     -q, --quiet         Reduce output verbosity
#     -t, --timeout <sec> Scan timeout in seconds (default: 3600)
#     --timing <level>    Nmap timing template (default: -T4)
#     -o, --output <dir>  Output directory (default: scans)
#     --debug             Enable debug output
#     -h, --help          Show this help message
#
#   EXAMPLES:
#     ./nmap-scan.sh 10.10.10.10
#     ./nmap-scan.sh charlie
#     ./nmap-scan.sh -iL targets.txt -j 5 --no-udp
#     ./nmap-scan.sh -iL targets.txt -j 3 -t 1800 --timing -T3 --debug
#
#   NOTE: This script requires sudo privileges for full scan capabilities.
#         Run with: sudo ./nmap-scan.sh <target>
# -----------------------------------------------------------------------------

set -eo pipefail  # Remove 'u' to allow unbound variables

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
debug=0

show_help() {
    cat << EOF
Nmap Scanner - Optimized for CTF and pentesting

Usage: $0 [OPTIONS] <TARGET>
       $0 [OPTIONS] -iL <target-list-file>

TARGET can be:
    - IP address (e.g., 192.168.1.1)
    - Hostname (e.g., charlie, server.local)
    - FQDN (e.g., www.example.com)

OPTIONS:
    -iL <file>          Input list of targets (IPs or hostnames)
    --no-udp            Skip UDP scanning
    -j, --jobs <num>    Maximum concurrent scans (default: $MAX_CONCURRENT_SCANS)
    -q, --quiet         Reduce output verbosity
    -t, --timeout <sec> Scan timeout in seconds (default: $SCAN_TIMEOUT)
    --timing <level>    Nmap timing template (default: $DEFAULT_TIMING)
    -o, --output <dir>  Output directory (default: $output_dir)
    --debug             Enable debug output
    -h, --help          Show this help message

EXAMPLES:
    $0 10.10.10.10
    $0 charlie
    $0 -iL targets.txt -j 5 --no-udp
    $0 -iL targets.txt -j 3 -t 1800 --timing -T3 --debug

NOTE: This script requires sudo privileges for full scan capabilities.
      Run with: sudo $0 <target>
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
        --debug)
            debug=1
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
    echo -e "${RED}ERROR: Missing target or input list!${NC}"
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
    
    # Check if we're running as root or have sudo privileges
    if [[ $EUID -eq 0 ]]; then
        log SUCCESS "Running as root - full scan capabilities available"
        return 0
    fi
    
    # Test sudo privileges
    if sudo -n true 2>/dev/null; then
        log SUCCESS "Sudo privileges confirmed - full scan capabilities available"
        return 0
    else
        log ERROR "This script requires sudo privileges for full scan capabilities"
        log ERROR "Please run with: sudo $0 $*"
        exit 1
    fi
}

# Debug print function
_debug() {
    if [[ $debug -eq 1 ]]; then
        echo "DEBUG: $*" >&2
    fi
}

# Validate IP address or hostname and resolve to IP
validate_and_resolve_target() {
    local target="$1"
    _debug "validate_and_resolve_target called with: '$target'"
    
    # Check if it's a numeric IP address
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        _debug "Target is numeric IP"
        IFS='.' read -r -a octets <<< "$target"
        for octet in "${octets[@]}"; do
            if [[ ! "$octet" =~ ^[0-9]+$ ]] || [[ "$octet" -lt 0 ]] || [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        echo "$target"
        return 0
    fi
    
    _debug "Target is hostname, trying resolution methods..."
    
    # Try to resolve hostname to IP address using Linux methods
    
    # Method 1: getent hosts (reads /etc/hosts file) - PRIORITY
    if command -v getent &> /dev/null; then
        _debug "Trying getent hosts..."
        local resolved_ip=$(timeout 5 getent hosts "$target" 2>/dev/null | awk '{print $1}')
        _debug "getent hosts result: '$resolved_ip'"
        if [[ -n "$resolved_ip" ]]; then
            echo "$resolved_ip"
            return 0
        fi
    fi
    
    # Method 2: nslookup (with timeout)
    if command -v nslookup &> /dev/null; then
        _debug "Trying nslookup..."
        local resolved_ip=$(timeout 5 nslookup "$target" 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}')
        _debug "nslookup result: '$resolved_ip'"
        if [[ -n "$resolved_ip" && "$resolved_ip" != "NXDOMAIN" ]]; then
            echo "$resolved_ip"
            return 0
        fi
    fi
    
    # Method 3: host command (with timeout)
    if command -v host &> /dev/null; then
        _debug "Trying host command..."
        local resolved_ip=$(timeout 5 host "$target" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
        _debug "host command result: '$resolved_ip'"
        if [[ -n "$resolved_ip" ]]; then
            echo "$resolved_ip"
            return 0
        fi
    fi
    
    _debug "All resolution methods failed"
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
    if ! timeout "$timeout" nmap -Pn "$timing" -p- --min-rate="$MIN_RATE" --max-rate="$MAX_RATE" \
        -oA "$scan_dir/tcp_initial_scan_$timestamp" "$ip" > /dev/null 2>&1; then
        log ERROR "[$ip] TCP port scan failed or timed out"
        return 1
    fi
    log SUCCESS "[$ip] Initial TCP scan complete"
    
    local open_ports=""
    if [[ -f "$scan_dir/tcp_initial_scan_$timestamp.nmap" ]]; then
        open_ports=$(grep -E '^[0-9]+/tcp.*open' "$scan_dir/tcp_initial_scan_$timestamp.nmap" \
            | cut -d'/' -f1 | paste -sd, -)
    fi
    
    if [[ -z "$open_ports" ]]; then
        log WARNING "[$ip] No open TCP ports found"
    else
        log SUCCESS "[$ip] Open TCP ports: $open_ports"
        
        log INFO "[$ip] Running aggressive TCP scan on open ports..."
        if timeout "$timeout" nmap -Pn "$timing" -A -p "$open_ports" \
            -oA "$scan_dir/tcp_aggressive_scan_$timestamp" "$ip" > /dev/null 2>&1; then
            log SUCCESS "[$ip] Aggressive TCP scan completed: cat $scan_dir/tcp_aggressive_scan_$timestamp.nmap"
        else
            log WARNING "[$ip] Aggressive scan failed, trying fallback..."
            if timeout "$timeout" nmap -Pn "$timing" -sC -sV -p "$open_ports" \
                -oA "$scan_dir/tcp_fallback_scan_$timestamp" "$ip" > /dev/null 2>&1; then
                log SUCCESS "[$ip] Fallback scan completed: cat $scan_dir/tcp_fallback_scan_$timestamp.nmap"
            else
                log ERROR "[$ip] Both aggressive and fallback scans failed"
            fi
        fi
    fi
    
    if [[ $no_udp -eq 0 ]]; then
        log INFO "[$ip] Starting initial UDP scan (top 100 ports)..."
        if timeout "$timeout" nmap -Pn -sU -sV --top-ports 100 "$timing" \
            -oA "$scan_dir/udp_scan_$timestamp" "$ip" > /dev/null 2>&1; then
            log SUCCESS "[$ip] Initial UDP scan completed: cat $scan_dir/udp_scan_$timestamp.nmap"
            
            local udp_ports=""
            if [[ -f "$scan_dir/udp_scan_$timestamp.nmap" ]]; then
                udp_ports=$(grep -E '^[0-9]+/udp.*open' "$scan_dir/udp_scan_$timestamp.nmap" \
                    | cut -d'/' -f1 | paste -sd, -)
                if [[ -n "$udp_ports" ]]; then
                    log SUCCESS "[$ip] Open UDP ports: $udp_ports"
                    
                    log INFO "[$ip] Running aggressive UDP scan on open ports..."
                    if timeout "$timeout" nmap -Pn -sU -sV -A -p "$udp_ports" "$timing" \
                        -oA "$scan_dir/udp_aggressive_scan_$timestamp" "$ip" > /dev/null 2>&1; then
                        log SUCCESS "[$ip] Aggressive UDP scan completed: cat $scan_dir/udp_aggressive_scan_$timestamp.nmap"
                    else
                        log WARNING "[$ip] Aggressive UDP scan failed or timed out"
                    fi
                else
                    log INFO "[$ip] No open UDP ports found for aggressive scan"
                fi
            fi
        else
            log WARNING "[$ip] Initial UDP scan failed or timed out"
        fi
    else
        log INFO "[$ip] UDP scan skipped"
    fi
    
    return 0
}

main() {
    check_prerequisites
    
    # Simple approach: process one target at a time
    local target_list=""
    if [[ -n "$ip_list" ]]; then
        target_list=$(grep -Ev '^\s*($|#)' "$ip_list")
    else
        target_list="$IP"
    fi
    
    # Process each target individually
    local targets=()
    local ips=()

    _debug "Starting target processing..."
    while IFS= read -r target; do
        _debug "Processing target: '$target'"
        [[ -z "$target" ]] && continue
        
        _debug "Calling validate_and_resolve_target for '$target'"
        local resolved_ip=$(validate_and_resolve_target "$target")
        _debug "validate_and_resolve_target returned: '$resolved_ip' (exit code: $?)"
        if [[ $? -eq 0 ]]; then
            targets+=("$target")
            ips+=("$resolved_ip")
            if [[ "$target" != "$resolved_ip" ]]; then
                log INFO "Resolved $target to $resolved_ip"
            fi
        else
            log WARNING "Invalid target or cannot resolve: $target (skipping)"
        fi
    done <<< "$target_list"
    _debug "Finished target processing"
    
    # Check if we have any targets
    local target_count="${#targets[@]}"
    if [[ $target_count -eq 0 ]]; then
        log ERROR "No valid targets to scan"
        exit 1
    fi
    
    log INFO "Starting scan of $target_count target(s) with $concurrent concurrent jobs"
    
    mkdir -p "$output_dir"
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local pids=""
    local scan_completed=0
    local scan_failed=0
    
    for ((i=0; i<target_count; i++)); do
        local target="${targets[$i]}"
        local resolved_ip="${ips[$i]}"
        local scan_dir="$output_dir/$target"
        
        # Simple concurrency control
        local current_pid_count=0
        for pid in $pids; do
            if kill -0 "$pid" 2>/dev/null; then
                current_pid_count=$((current_pid_count + 1))
            fi
        done
        
        while [[ $current_pid_count -ge $concurrent ]]; do
            sleep 1
            current_pid_count=0
            local new_pids=""
            for pid in $pids; do
                if kill -0 "$pid" 2>/dev/null; then
                    new_pids="$new_pids $pid"
                    current_pid_count=$((current_pid_count + 1))
                else
                    wait "$pid"
                    if [[ $? -eq 0 ]]; then
                        scan_completed=$((scan_completed + 1))
                    else
                        scan_failed=$((scan_failed + 1))
                    fi
                fi
            done
            pids="$new_pids"
        done
        
        scan_single_host "$resolved_ip" "$scan_dir" "$timestamp" &
        local new_pid=$!
        pids="$pids $new_pid"
        
        if [[ $quiet -eq 0 ]]; then
            log INFO "Started scan for $target ($resolved_ip) (PID: $new_pid)"
        fi
    done
    
    # Wait for remaining processes
    for pid in $pids; do
        wait "$pid"
        if [[ $? -eq 0 ]]; then
            scan_completed=$((scan_completed + 1))
        else
            scan_failed=$((scan_failed + 1))
        fi
    done
    
    echo
    log SUCCESS "Scan completed! Summary:"
    log INFO "  Completed: $scan_completed"
    log INFO "  Failed: $scan_failed"
    log INFO "  Output directory: $output_dir"
    
    if [[ $scan_completed -gt 0 ]]; then
        echo
        log INFO "Quick results preview:"
        for target in "${targets[@]}"; do
            local scan_dir="$output_dir/$target"
            if [[ -d "$scan_dir" ]]; then
                local tcp_file=$(find "$scan_dir" -name "*tcp_aggressive_scan_$timestamp.nmap" -o -name "*tcp_fallback_scan_$timestamp.nmap" | head -1)
                local udp_file=$(find "$scan_dir" -name "*udp_scan_$timestamp.nmap" | head -1)
                local tcp_count=0
                local udp_count=0
                
                if [[ -n "$tcp_file" ]]; then
                    tcp_count=$(grep -c "open" "$tcp_file" 2>/dev/null || echo "0")
                fi
                
                if [[ -n "$udp_file" ]]; then
                    udp_count=$(grep -c "open" "$udp_file" 2>/dev/null || echo "0")
                fi
                
                echo -e "${BLUE}  $target:${NC} $tcp_count open TCP ports, $udp_count open UDP ports"
            fi
        done
    fi
}

main "$@" 