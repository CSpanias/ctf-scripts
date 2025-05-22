#!/bin/bash

# ──────────────────────────────────────────────
# Step 0: Argument parsing
# ──────────────────────────────────────────────
if [[ "$1" == "-iL" && -n "$2" && -f "$2" ]]; then
  ip_list="$2"
else
  IP="$1"
  if [[ -z "$IP" ]]; then
    echo "❌ Missing IP address or input list!"
    echo "💡 Usage:"
    echo "   nmap_scan.sh <IP-ADDRESS>"
    echo "   nmap_scan.sh -iL <ip-list-file>"
    exit 1
  fi
  ip_list=""
fi

# ──────────────────────────────────────────────
# Step 0.5: Populate list of IPs
# ──────────────────────────────────────────────
ips_to_scan=()
if [[ -n "$ip_list" ]]; then
  mapfile -t ips_to_scan < <(grep -Ev '^\s*($|#)' "$ip_list")  # skip empty lines and comments
else
  ips_to_scan=("$IP")
fi

# ──────────────────────────────────────────────
# Step 1: Loop through IPs
# ──────────────────────────────────────────────
for IP in "${ips_to_scan[@]}"; do

  # Timestamp for uniqueness
  NOW=$(date +"%Y%m%d_%H%M%S")
  SCAN_DIR="scans/${IP}"

  echo -e "\n🌐 [$IP] Starting scan sequence..."

  # ──────────────────────────────────────────────
  # Step 2: Check if host is online (non-ICMP)
  # ──────────────────────────────────────────────
  echo "📡 [$IP] Checking if host is online (non-ICMP)..."
  nmap -Pn -sn "${IP}" -oG - | grep -q "Status: Up"
  if [[ $? -ne 0 ]]; then
    echo "❌ [$IP] Host appears down or unreachable. Skipping scan."
    continue
  fi
  echo "✅ [$IP] Host is up (based on TCP ping)."

  # ──────────────────────────────────────────────
  # Step 3: Prepare scan directory
  # ──────────────────────────────────────────────
  echo "📂 [$IP] Preparing output directory..."
  mkdir -p "${SCAN_DIR}"
  echo "✅ [$IP] Output directory: ${SCAN_DIR}"

  # ──────────────────────────────────────────────
  # Step 4: Initial full TCP port scan
  # ──────────────────────────────────────────────
  echo "🔍 [$IP] Starting full TCP port scan..."
  sudo nmap -Pn -T4 -p- --min-rate=5000 -oA "${SCAN_DIR}/initial_port-scan_${NOW}" "${IP}" > /dev/null
  echo "✅ [$IP] Initial TCP scan complete."

  # ──────────────────────────────────────────────
  # Step 5: Extract open TCP ports
  # ──────────────────────────────────────────────
  echo "📦 [$IP] Extracting open TCP ports..."
  grep -E '^[0-9]+/tcp' "${SCAN_DIR}/initial_port-scan_${NOW}.nmap" \
    | awk '{print $1}' \
    | grep -oE '^[0-9]+' \
    | paste -sd, - \
    > "${SCAN_DIR}/open_ports_${NOW}"

  open_ports=$(cat "${SCAN_DIR}/open_ports_${NOW}")

  if [[ -z "$open_ports" ]]; then
    echo "❌ [$IP] No open TCP ports found. Skipping aggressive scan."
  else
    echo "✅ [$IP] Open TCP ports: $open_ports"
    echo "🚀 [$IP] Running aggressive scan on open TCP ports..."
    sudo nmap -Pn -T4 --min-rate=5000 -A -p "$open_ports" -oA "${SCAN_DIR}/aggressive_scan_${NOW}" "${IP}" > /dev/null
    echo "✅ [$IP] Aggressive TCP scan completed."
    
    echo -e "\n📖 [$IP] Preview of aggressive TCP scan results:\n"
    cat "${SCAN_DIR}/aggressive_scan_${NOW}.nmap" | head -n 50
    echo "🔽 [$IP] Full results saved to: ${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
    echo "⏳ [$IP] Proceeding to UDP scan next (this may take a while)..."
  fi

  # ──────────────────────────────────────────────
  # Step 6: Top 1000 UDP port scan
  # ──────────────────────────────────────────────
  echo "📡 [$IP] Starting top 1000 UDP port scan..."
  sudo nmap -Pn -sU --top-ports 1000 -T4 -oA "${SCAN_DIR}/udp_scan_${NOW}" "${IP}" > /dev/null
  echo "✅ [$IP] UDP scan complete."

  # ──────────────────────────────────────────────
  # Step 7: Extract open UDP ports
  # ──────────────────────────────────────────────
  udp_ports=$(grep -E '^[0-9]+/udp' "${SCAN_DIR}/udp_scan_${NOW}.nmap" \
    | awk '{print $1}' \
    | grep -oE '^[0-9]+' \
    | paste -sd, -)

  if [[ -n "$udp_ports" ]]; then
    echo "✅ [$IP] Open UDP ports: $udp_ports"
  else
    echo "ℹ️ [$IP] No open UDP ports detected in top 1000."
  fi

  # ──────────────────────────────────────────────
  # Step 8: Summary
  # ──────────────────────────────────────────────
  echo -e "\n🎉 [$IP] All done! Results saved to:"
  echo "   📄 Initial TCP scan:   ${SCAN_DIR}/initial_port-scan_${NOW}.nmap"
  echo "   📄 Open TCP ports:     ${SCAN_DIR}/open_ports_${NOW}"
  [[ -n "$open_ports" ]] && echo "   📄 Aggressive TCP scan:${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
  echo "   📄 UDP scan:           ${SCAN_DIR}/udp_scan_${NOW}.nmap"

  # ──────────────────────────────────────────────
  # Step 9: Optional view
  # ──────────────────────────────────────────────
  read -rp "👀 [$IP] Do you want to view the aggressive TCP scan results now? [y/N]: " choice
  if [[ "$choice" =~ ^[Yy]$ ]] && [[ -n "$open_ports" ]]; then
    cat "${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
  else
    echo "👍 [$IP] Skipping file view. You can read it later at:"
    [[ -n "$open_ports" ]] && echo "   ${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
  fi

done