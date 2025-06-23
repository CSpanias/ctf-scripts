#!/bin/bash

# -----------------------------------------------------------------------------
# HTB-CONNECT: Quick OpenVPN profile launcher for Hack The Box
#
# Author: x7331
# Version: 2.0
#
# Description:
#   Easily connect to various Hack The Box VPNs (Academy, CTF, Seasonal, SP)
#   with a single command or interactive menu. Includes status and disconnect.
#
# Usage:
#   ./htb-connect.sh [OPTION]
#
#   OPTION:
#     1   Connect to Academy
#     2   Connect to Capture The Flag
#     3   Connect to Seasonal
#     4   Connect to Starting Point
#     5   Show VPN status
#     6   Disconnect VPN
#     7   Exit
#
#   If no option is provided, an interactive menu will be shown.
# -----------------------------------------------------------------------------

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ASCII Art Header
cat << "EOF"
${BLUE}#-------------------------------------------#
#            HTB-CONNECT by x7331           #
#-------------------------------------------#${NC}
EOF

# Define paths (edit these to your actual .ovpn locations)
ovpn_path="/home/x7331/Documents/htb/ovpn"
acad_file="${ovpn_path}/academy-regular.ovpn"
ctf_file="${ovpn_path}/lab_x7331.ovpn"
comp_file="${ovpn_path}/seasonal-regular.ovpn"
sp_file="${ovpn_path}/starting_point_x7331.ovpn"

# Start OpenVPN in the background
start_openvpn() {
    local profile="$1"
    if [[ ! -f "$profile" ]]; then
        echo -e "${RED}ERROR:${NC} Profile not found: $profile"
        exit 1
    fi
    sudo openvpn --config "$profile" --daemon &>/dev/null
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}OpenVPN started with profile:${NC} $profile"
    else
        echo -e "${RED}Failed to start OpenVPN!${NC}"
        exit 1
    fi
}

# Show tun0 IP address
get_tun0_ip() {
    sleep 3
    local ip=$(ip a show tun0 2>/dev/null | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1)
    if [[ -n "$ip" ]]; then
        echo -e "${GREEN}tun0 IP:${NC} $ip"
    else
        echo -e "${YELLOW}tun0 interface not found. Is VPN up?${NC}"
    fi
}

# Show OpenVPN status
openvpn_status() {
    if pgrep openvpn &>/dev/null; then
        echo -e "${GREEN}OpenVPN is running (PID: $(pgrep openvpn | tr '\n' ' '))${NC}"
        get_tun0_ip
    else
        echo -e "${YELLOW}OpenVPN is not running.${NC}"
    fi
}

# Disconnect OpenVPN
disconnect_vpn() {
    if pgrep openvpn &>/dev/null; then
        sudo pkill openvpn
        sleep 2
        echo -e "${GREEN}OpenVPN disconnected.${NC}"
    else
        echo -e "${YELLOW}No OpenVPN process found.${NC}"
    fi
}

show_usage() {
    echo -e "${BLUE}Usage:${NC} $0 [1|2|3|4|5|6|7]"
    echo "  1 - Academy"
    echo "  2 - Capture The Flag"
    echo "  3 - Seasonal"
    echo "  4 - Starting Point"
    echo "  5 - Status"
    echo "  6 - Disconnect VPN"
    echo "  7 - Exit"
    echo "  (No argument = interactive menu)"
}

# Main logic
run_option() {
    case "$1" in
        1) start_openvpn "$acad_file" && get_tun0_ip ;;
        2) start_openvpn "$ctf_file" && get_tun0_ip ;;
        3) start_openvpn "$comp_file" && get_tun0_ip ;;
        4) start_openvpn "$sp_file" && get_tun0_ip ;;
        5) openvpn_status ;;
        6) disconnect_vpn ;;
        7) echo -e "${YELLOW}Bye!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}"; show_usage; exit 1 ;;
    esac
}

if [[ -n "$1" ]]; then
    run_option "$1"
else
    echo -e "${YELLOW}Available options:${NC}"
    echo "  1 - Academy"
    echo "  2 - Capture The Flag"
    echo "  3 - Seasonal"
    echo "  4 - Starting Point"
    echo "  5 - Status"
    echo "  6 - Disconnect VPN"
    echo "  7 - Exit"
    echo
    read -rp "Choose option (1-7): " opt
    run_option "$opt"
fi
