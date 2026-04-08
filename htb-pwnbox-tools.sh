#!/bin/bash

# HTB Cybernetics Lab Setup Script (CAPE prep)

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}HTB Cybernetics Lab Setup Script${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Install UV
echo -e "${BLUE}[*] Installing UV package manager${NC}"
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv cache clean
echo -e "${GREEN}[✓] UV installed successfully${NC}\n"

# Install Python tools via UV
echo -e "${BLUE}[*] Installing Python tools via UV${NC}"
sudo rm -rf /usr/local/bin/nxc /usr/local/bin/netexec /usr/share/impacket/
hash -r

echo -e "${YELLOW}  → Installing NetExec${NC}"
uv tool install git+https://github.com/Pennyw0rth/NetExec

echo -e "${YELLOW}  → Installing Impacket${NC}"
uv tool install git+https://github.com/fortra/impacket

echo -e "${YELLOW}  → Installing BloodyAD${NC}"
uv tool install git+https://github.com/CravateRouge/bloodyAD

echo -e "${GREEN}[✓] Python tools installed successfully${NC}\n"

# Create tools directory
echo -e "${BLUE}[*] Creating tools directory${NC}"
mkdir -p tools && cd tools
echo -e "${GREEN}[✓] Directory created: $(pwd)${NC}\n"

# Install BloodHound
echo -e "${BLUE}[*] Installing BloodHound${NC}"
wget -q --show-progress https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xzf bloodhound-cli-linux-amd64.tar.gz
rm bloodhound-cli-linux-amd64.tar.gz

echo -e "${YELLOW}  → Starting Docker service${NC}"
sudo systemctl start docker

echo -e "${YELLOW}  → Installing BloodHound via CLI${NC}"
sudo ./bloodhound-cli install

echo -e "${GREEN}[✓] BloodHound installed successfully${NC}\n"

# Download ligolo-ng
echo -e "${BLUE}[*] Downloading ligolo-ng${NC}"

echo -e "${YELLOW}  → Downloading Windows agent${NC}"
wget -q --show-progress https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_agent_0.8.3_windows_amd64.zip

echo -e "${YELLOW}  → Downloading Linux proxy${NC}"
wget -q --show-progress https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz

echo -e "${YELLOW}  → Extracting files${NC}"
unzip -q ligolo-ng_agent_0.8.3_windows_amd64.zip
tar -xzf ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz

echo -e "${YELLOW}  → Cleaning up archives${NC}"
rm ligolo-ng_agent_0.8.3_windows_amd64.zip ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz

echo -e "${GREEN}[✓] ligolo-ng downloaded and extracted${NC}\n"

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Installed tools:${NC}"
echo -e "  • UV package manager"
echo -e "  • NetExec"
echo -e "  • Impacket"
echo -e "  • BloodyAD"
echo -e "  • BloodHound"
echo -e "  • ligolo-ng (proxy + agent)"
echo -e "\n${YELLOW}Tools directory: $(pwd)${NC}\n"
