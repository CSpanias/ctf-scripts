#!/bin/bash

# ──────────────────────────────────────────────
# Step 0: Argument parsing
# ──────────────────────────────────────────────
no_udp=0
ip_list=""
IP=""

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
        echo "❌ Invalid or missing input list file after -iL"
        exit 1
      fi
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
  echo "❌ Missing IP address or input list!"
  echo "💡 Usage:"
  echo "   nmap_scan.sh <IP-ADDRESS>"
  echo "   nmap_scan.sh -iL <ip-list-file>"
  echo "   nmap_scan.sh --no-udp <...>"
  exit 1
fi


# ──────────────────────────────────────────────
# Step 0.5: Populate list of IPs
# ──────────────────────────────────────────────
ips_to_scan=()
if [[ -n "$ip_list" ]]; then
  mapfile -t ips_to_scan < <(grep -Ev '^\s*($|#)' "$ip_list")
else
  ips_to_scan=("$IP")
fi

# ──────────────────────────────────────────────
# Step 1: Loop through IPs
# ──────────────────────────────────────────────
for IP in "${ips_to_scan[@]}"; do
  NOW=$(date +"%Y%m%d_%H%M%S")
  SCAN_DIR="scans/${IP}"

  echo -e "\n🌐 [$IP] Starting scan sequence..."

  echo "📡 [$IP] Checking if host is online (non-ICMP)..."
  nmap -Pn -sn "${IP}" -oG - | grep -q "Status: Up"
  if [[ $? -ne 0 ]]; then
    echo "❌ [$IP] Host appears down. Skipping scan."
    continue
  fi
  echo "✅ [$IP] Host is up."

  echo "📂 [$IP] Preparing output directory..."
  mkdir -p "${SCAN_DIR}"

  echo "🔍 [$IP] Starting full TCP port scan..."
  sudo nmap -Pn -T4 -p- --min-rate=1000 -oA "${SCAN_DIR}/initial_port-scan_${NOW}" "${IP}" > /dev/null
  echo "✅ [$IP] Initial TCP scan complete."

  echo "📦 [$IP] Extracting open TCP ports..."
  grep -E '^[0-9]+/tcp' "${SCAN_DIR}/initial_port-scan_${NOW}.nmap" \
    | awk '{print $1}' \
    | grep -oE '^[0-9]+' \
    | paste -sd, - \
    > "${SCAN_DIR}/open_ports_${NOW}"

  open_ports=$(<"${SCAN_DIR}/open_ports_${NOW}")

  if [[ -z "$open_ports" ]]; then
    echo "❌ [$IP] No open TCP ports found."
  else
    echo "✅ [$IP] Open TCP ports: $open_ports"
    echo "🚀 [$IP] Running aggressive scan on open TCP ports..."

    sudo nmap -Pn -T4 -A -p "$open_ports" -oA "${SCAN_DIR}/aggressive_scan_${NOW}" "${IP}" > /dev/null
    if [[ $? -ne 0 ]]; then
      echo "⚠️ [$IP] Aggressive scan failed. Falling back to service/version scan..."
      sudo nmap -Pn -T4 -sC -sV -p "$open_ports" -oA "${SCAN_DIR}/fallback_scan_${NOW}" "${IP}" > /dev/null
      echo "✅ [$IP] Fallback scan completed."
      echo "💾 [$IP] Fallback TCP scan saved: cat ${SCAN_DIR}/fallback_scan_${NOW}.nmap"
    else
      echo "✅ [$IP] Aggressive TCP scan completed."
      echo "💾 [$IP] TCP scan saved: cat ${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
    fi
  fi

  if [[ $no_udp -eq 1 ]]; then
    echo "⏩ [$IP] Skipping UDP scan as requested."
    continue
  fi

  echo "📡 [$IP] Starting top 1000 UDP port scan..."
  sudo nmap -Pn -sU -sV --top-ports 1000 -T4 -oA "${SCAN_DIR}/udp_scan_${NOW}" "${IP}" > /dev/null
  echo "✅ [$IP] UDP scan complete."

  udp_ports=$(grep -E '^[0-9]+/udp' "${SCAN_DIR}/udp_scan_${NOW}.nmap" \
    | awk '{print $1}' \
    | grep -oE '^[0-9]+' \
    | paste -sd, -)

  if [[ -n "$udp_ports" ]]; then
    echo "✅ [$IP] Open UDP ports: $udp_ports"
  else
    echo "ℹ️ [$IP] No open UDP ports found."
  fi

  echo "💾 [$IP] UDP scan saved: cat ${SCAN_DIR}/udp_scan_${NOW}.nmap"

  echo -e "\n🎉 [$IP] Done. Summary:"
  echo "   📄 TCP port scan:     ${SCAN_DIR}/initial_port-scan_${NOW}.nmap"
  echo "   📄 Open ports file:   ${SCAN_DIR}/open_ports_${NOW}"
  [[ -n "$open_ports" ]] && echo "   📄 TCP scan:          ${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
  [[ -f "${SCAN_DIR}/fallback_scan_${NOW}.nmap" ]] && echo "   📄 Fallback scan:     ${SCAN_DIR}/fallback_scan_${NOW}.nmap"
  echo "   📄 UDP scan:          ${SCAN_DIR}/udp_scan_${NOW}.nmap"

done
