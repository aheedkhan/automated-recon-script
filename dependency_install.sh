#!/bin/bash
# Kali Recon Environment Setup
# Installs all CLI tools + Python libraries required by recon_pipeline.py

set -e  # stop on error
echo "[+] Updating system..."
sudo apt update -y && sudo apt upgrade -y

echo "[+] Installing base packages..."
sudo apt install -y python3 python3-pip python3-venv git curl wget jq nmap masscan whatweb seclists build-essential

echo "[+] Installing Go..."
if ! command -v go &>/dev/null; then
    sudo apt install -y golang
fi

# Set Go environment if not already set
if [ -z "$GOPATH" ]; then
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export PATH=\$PATH:\$GOPATH/bin" >> ~/.bashrc
fi

echo "[+] Installing Go-based tools..."
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/ffuf/ffuf/v2@latest

echo "[+] Ensuring binaries are available..."
sudo cp $HOME/go/bin/* /usr/local/bin/ 2>/dev/null || true

echo "[+] Installing Python packages..."
pip3 install --upgrade pip
pip3 install aiohttp dnspython beautifulsoup4 requests tldextract

echo "[+] Installing optional wordlists (seclists)..."
if [ ! -d "/usr/share/seclists" ]; then
    sudo apt install -y seclists
fi

echo "[+] Creating working directory..."
mkdir -p recon_output

echo "[+] Installation complete!"
echo
echo "All tools and libraries are installed."
echo "You can now run your script with:"
echo " sudo python3 hahahehe.py example.com"
