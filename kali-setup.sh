#!/bin/bash

# --- Kali Linux Custom Setup Script ---

# Description: This script performs a fresh setup and installs tools
#              for a minimal Kali Linux environment. It accepts command-line
#              arguments to specify which sets of tools to install.
#
# Usage:
#   ./kali-setup.sh --core      : Installs only the core tools.
#   ./kali-setup.sh --optional  : Installs only the optional tools.
#   ./kali-setup.sh --all       : Installs both core and optional tools.

# --- Tool Definitions ---
# APT packages for core installation
CORE_APT_TOOLS=(
    "hashcat"
    "wordlists"
    "docker.io" # Bloodhound dependency
)

# Python tools to be installed via uv
PYTHON_TOOLS=(
    "git+https://github.com/Pennyw0rth/NetExec"
    "git+https://github.com/ly4k/Certipy"
    "git+https://github.com/ihebski/DefaultCreds-cheat-sheet"
    "git+https://github.com/brightio/penelope"
    "git+https://github.com/fortra/impacket"
    "git+https://github.com/CravateRouge/bloodyAD"
)

# Placeholder for optional tools
OPTIONAL_TOOLS=()


# --- Function Definitions ---

# Function to create the base directory structure
setup_directories() {
    echo "[+] Creating tool directory structure..."
    mkdir -p "$HOME"/tools/{linux-binaries,linux-scripts,windows-binaries,windows-scripts,cross-platform}
}

# Function to decompress the rockyou wordlist if it hasn't been already
decompress_rockyou() {
    echo "[+] Checking RockYou wordlist..."
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
        if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
            echo "[+] Decompressing rockyou.txt.gz..."
            sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
        else
            echo "[!] rockyou.txt.gz not found. It may have been moved or is not included in this seclists version."
        fi
    else
        echo "[!] rockyou.txt is already decompressed. Skipping."
    fi
}

# Function to install Python tools using uv
install_python_tools() {
    echo "[+] Setting up Python tools with uv..."
    
    # First, install uv if it's not already present
    if ! command -v uv &> /dev/null; then
        echo "[+] Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        
        # The uv installer places the binary in ~/.local/bin.
        # We must add this directory to the PATH for the current script session.
        export PATH="$HOME/.local/bin:$PATH"
    else
        echo "[!] uv is already installed. Skipping installation."
    fi

    echo "[+] Installing Python tools..."
    for tool in "${PYTHON_TOOLS[@]}"; do
        # Using basename to get a cleaner name from the git URL
        local tool_name
        tool_name=$(basename "$tool")
        echo "    -> Installing ${tool_name%.*}" # Removes .git extension
        uv tool install "$tool"
    done
}

# Function to install Ligolo-NG
install_ligolo_ng() {
    echo "[+] Installing Ligolo-NG from GitHub..."
    local LIGOLO_VERSION="0.8.3"
    local INSTALL_DIR="$HOME/tools/cross-platform/ligolo-ng"
    
    if [ -f "$INSTALL_DIR/proxy" ]; then
        echo "[!] Ligolo-NG proxy already found in $INSTALL_DIR. Skipping."
        return
    fi

    mkdir -p "$INSTALL_DIR"
    local AGENT_URL="https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_windows_amd64.zip"
    local PROXY_URL="https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_amd64.tar.gz"

    echo "[+] Downloading Ligolo-NG assets..."
    wget -q --show-progress -O "$INSTALL_DIR/agent.zip" "$AGENT_URL"
    wget -q --show-progress -O "$INSTALL_DIR/proxy.tar.gz" "$PROXY_URL"

    echo "[+] Extracting archives..."
    unzip -o "$INSTALL_DIR/agent.zip" -d "$INSTALL_DIR"
    tar -xzvf "$INSTALL_DIR/proxy.tar.gz" -C "$INSTALL_DIR"
    
    echo "[+] Cleaning up downloaded archives..."
    rm "$INSTALL_DIR/agent.zip" "$INSTALL_DIR/proxy.tar.gz"
    echo "[+] Ligolo-NG has been installed in $INSTALL_DIR"
}

# Function to install Bloodhound-CLI
install_bloodhound_cli() {
    echo "[+] Installing Bloodhound-CLI from GitHub..."
    local INSTALL_DIR="$HOME/tools/cross-platform/bloodhound-cli"

    if [ -f "$INSTALL_DIR/bloodhound-cli" ]; then
        echo "[!] Bloodhound-CLI already found in $INSTALL_DIR. Skipping."
        return
    fi
    
    # Enable and start Docker, a dependency for Bloodhound's backend
    echo "[+] Ensuring Docker service is running..."
    sudo systemctl enable --now docker

    mkdir -p "$INSTALL_DIR"
    local LATEST_URL="https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz"

    echo "[+] Downloading latest Bloodhound-CLI..."
    wget -q --show-progress -O "$INSTALL_DIR/bloodhound.tar.gz" "$LATEST_URL"

    echo "[+] Extracting archive..."
    tar -xzvf "$INSTALL_DIR/bloodhound.tar.gz" -C "$INSTALL_DIR"
    
    echo "[+] Bloodhound-CLI binary is ready at $INSTALL_DIR/bloodhound-cli"
    
    echo "[+] Cleaning up downloaded archive..."
    rm "$INSTALL_DIR/bloodhound.tar.gz"
}

# --- Main Installation Functions ---

install_core_tools() {
    echo "========================================="
    echo "  Starting Core Tool Installation"
    echo "========================================="
    
    setup_directories
    
    echo "[+] Installing CORE tools via apt..."
    sudo apt install -y "${CORE_APT_TOOLS[@]}"
    
    decompress_rockyou
    install_python_tools
    install_ligolo_ng
    install_bloodhound_cli

    echo "========================================="
    echo "  Core Tool Installation Complete"
    echo "========================================="
}

install_optional_tools() {
    echo "[+] Installing OPTIONAL tools..."
    if [ ${#OPTIONAL_TOOLS[@]} -eq 0 ]; then
        echo "[!] Optional tools list is empty. Nothing to install."
    else
        sudo apt install -y "${OPTIONAL_TOOLS[@]}"
    fi
}

# --- Main Script Logic ---

if [ -z "$1" ]; then
    echo "[-] Error: No option selected."
    echo "[-] Please run the script with one of the following options:"
    echo "    --core      : Installs only the core tools."
    echo "    --optional  : Installs only the optional tools."
    echo "    --all       : Installs both core and optional tools."
    exit 1
fi

echo "[+] Starting system update and upgrade..."
sudo apt update && sudo apt upgrade -y
echo "[+] System is now up to date."

case "$1" in
    --core)
        install_core_tools
        ;;
    --optional)
        install_optional_tools
        ;;
    --all)
        install_core_tools
        install_optional_tools
        ;;
    *)
        echo "[-] Error: Invalid option '$1'."
        echo "[-] Please use --core, --optional, or --all."
        exit 1
        ;;
esac

echo "[*] Script execution finished."
