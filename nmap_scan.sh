#!/bin/bash

IP="${1}"

if [[ -z "${IP}" ]]; then
  echo "❌ Missing IP address!"
  echo "💡 Usage: nmap_scan.sh <IP-ADDRESS>"
  exit 1
fi

# Timestamp for uniqueness
NOW=$(date +"%Y%m%d_%H%M%S")
SCAN_DIR="scans/${IP}"

# ──────────────────────────────────────────────
# Step 1: Check if host is online (non-ICMP)
# ──────────────────────────────────────────────
echo "📡 [$IP] Checking if host is online (non-ICMP)..."
nmap -Pn -sn "${IP}" -oG - | grep -q "Status: Up"

if [[ $? -ne 0 ]]; then
  echo "❌ [$IP] Host appears down or unreachable. Skipping scan."
  exit 1
fi
echo "✅ [$IP] Host is up (based on TCP ping)."

# ──────────────────────────────────────────────
# Step 2: Prepare scan directory
# ──────────────────────────────────────────────
echo "📂 [$IP] Preparing output directory..."
mkdir -p "${SCAN_DIR}"
echo "✅ [$IP] Output directory: ${SCAN_DIR}"

# ──────────────────────────────────────────────
# Step 3: Initial full TCP port scan
# ──────────────────────────────────────────────
echo "🔍 [$IP] Starting full TCP port scan..."
sudo nmap -Pn -T4 -p- --min-rate=5000 -oA "${SCAN_DIR}/initial_port-scan_${NOW}" "${IP}" > /dev/null
echo "✅ [$IP] Initial TCP scan complete."

# ──────────────────────────────────────────────
# Step 4: Extract open TCP ports
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
fi

# ──────────────────────────────────────────────
# Step 5: Top 1000 UDP port scan
# ──────────────────────────────────────────────
echo "📡 [$IP] Starting top 1000 UDP port scan..."
sudo nmap -Pn -sU --top-ports 1000 -T4 -oA "${SCAN_DIR}/udp_scan_${NOW}" "${IP}" > /dev/null
echo "✅ [$IP] UDP scan complete."

# ──────────────────────────────────────────────
# Step 6: Extract open UDP ports (optional display)
# ──────────────────────────────────────────────
udp_ports=$(grep -E '^[0-9]+/udp' "${SCAN_DIR}/udp_scan_${NOW}.nmap" | awk '{print $1}' | grep -oE '^[0-9]+' | paste -sd, -)

if [[ -n "$udp_ports" ]]; then
  echo "✅ [$IP] Open UDP ports: $udp_ports"
else
  echo "ℹ️ [$IP] No open UDP ports detected in top 1000."
fi

# ──────────────────────────────────────────────
# Step 7: Summary
# ──────────────────────────────────────────────
echo -e "\n🎉 [$IP] All done! Results saved to:"
echo "   📄 Initial TCP scan:   ${SCAN_DIR}/initial_port-scan_${NOW}.nmap"
echo "   📄 Open TCP ports:     ${SCAN_DIR}/open_ports_${NOW}"
[[ -n "$open_ports" ]] && echo "   📄 Aggressive TCP scan:${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
echo "   📄 UDP scan:           ${SCAN_DIR}/udp_scan_${NOW}.nmap"

# ──────────────────────────────────────────────
# Step 8: Optional view
# ──────────────────────────────────────────────
read -rp "👀 [$IP] Do you want to view the aggressive TCP scan results now? [y/N]: " choice
if [[ "$choice" =~ ^[Yy]$ ]] && [[ -n "$open_ports" ]]; then
  cat "${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
else
  echo "👍 [$IP] Skipping file view. You can read it later at:"
  [[ -n "$open_ports" ]] && echo "   ${SCAN_DIR}/aggressive_scan_${NOW}.nmap"
fi
