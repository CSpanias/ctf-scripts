#!/bin/bash

# Display ASCII art
cat << "EOF"
#-------------------------------------------#
#            HTB-CONNECT by x7331           #
#-------------------------------------------#
EOF

# Define paths
ovpn_path="/home/x7331/Documents/htb/ovpn"
acad_file="${ovpn_path}/academy-regular.ovpn"
ctf_file="${ovpn_path}/lab_x7331.ovpn"
comp_file="${ovpn_path}/seasonal-regular.ovpn"
sp_file="${ovpn_path}/starting_point_x7331.ovpn"

# Define function to start OpenVPN
start_openvpn() {
        sudo openvpn --config "${1}" --daemon &>/dev/null
}

# Define function to get tun0 IP address
get_tun0_ip() {
        sleep 4 && echo -e "\nOpenVPN started at tun0 ($(ip a show tun0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1))."
}

# Check if OpenVPN is running
openvpn_status() {
        if pgrep open &>/dev/null; then
                echo "OpenVPN is running: $(pgrep open)"
        else
                echo "OpenVPN is not running."
        fi
}

# Check if an argument has passed
if [[ -n "${1}" ]]; then
        case ${1} in
                1) start_openvpn "${acad_file}" && get_tun0_ip ;;
                2) start_openvpn "${ctf_file}" && get_tun0_ip ;;
                3) start_openvpn "${comp_file}" && get_tun0_ip ;;
                4) start_openvpn "${sp_file}" && get_tun0_ip ;;
                5) openvpn_status ;;
                6) sudo pkill openvpn && get_tun0_ip | grep 'Device' ;;
                7) exit 1 ;;
                *) echo -e "\nInvalid option choosen! Usage: htb-connect.sh [1 | 2 | 3 | 4 | 5]"
                   echo "Example: htb-connect.sh 1"
                   exit 1 ;;
        esac
else
        # List available options
        cat << "EOF"
Available options:
        1 - Academy
        2 - Capture The Flag
        3 - Seasonal
        4 - Starting Point
        5 - Status
        6 - Close VPN
        7 - Exit

EOF

        # Get user input
        read -r -p "Choose option (1-6): " opt

        # Start OpenVPN based on user input
        case "${opt}" in
                1) start_openvpn "${acad_file}" && get_tun0_ip ;;
                2) start_openvpn "${ctf_file}" && get_tun0_ip ;;
                3) start_openvpn "${comp_file}" && get_tun0_ip ;;
                4) start_openvpn "${sp_file}" && get_tun0_ip ;;
                5) openvpn_status ;;
                6) sudo pkill openvpn && get_tun0_ip | grep 'Device' ;;
                7) exit 1 ;;
                *) echo -e "\nInvalid option choosen! Usage: htb-connect.sh [1 | 2 | 3 | 4 | 5 | 6 | 7]"
                   echo "Example: htb-connect.sh 1"
                   exit 1 ;;
        esac
fi
