```
                      .__          _____ .__           .__                  ___    
  _____ _____    ____ |__|____    / ___ \|  |__   ____ |  |__   ____    /\  \  \   
 /     \\__  \  /    \|  \__  \  / / ._\ \  |  \_/ __ \|  |  \_/ __ \   \/   \  \  
|  Y Y  \/ __ \|   |  \  |/ __ \<  \_____/   Y  \  ___/|   Y  \  ___/   /\    )  ) 
|__|_|  (____  /___|  /__(____  /\_____\ |___|  /\___  >___|  /\___  >  \/   /  /  
      \/     \/     \/        \/              \/     \/     \/     \/       /__/    

Recon Automation Script — Passive + Active Enumeration
                                        --by aheedkhan
```

## Project Overview
`hahahehe.py` is a Kali-focused automated reconnaissance pipeline that combines passive OSINT (Amass, Subfinder, crt.sh) with active checks (DNS resolution, asynchronous HTTP probing), fast port discovery, service enumeration, URL harvesting and web fuzzing to build a structured reconnaissance report. Results are saved under `recon_output/` and summarized in `report.md`.

---

## Files
- `hahahehe.py` — main recon script  
- `dependency_install.sh` — installer script to set up dependencies on Kali  make executable: `chmod +x dependency_install.sh`
- `recon_output/` — generated output folder (created by the script)

---

## Features
- Passive subdomain enumeration (Amass, Subfinder, crt.sh)  
- DNS resolution and async HTTP probing (alive check)  
- WHOIS + basic IP geolocation lookup  
- URL harvesting (gau, waybackurls, hakrawler)  
- Fast port discovery (masscan / naabu) and detailed enumeration (nmap)  
- Directory/admin fuzzing with ffuf + SecLists  
- Optional technology fingerprinting (WhatWeb)  
- Outputs structured artifacts (nmap XML, ffuf JSON, URL lists) and `report.md`

---

## Installation 
This script is designed for Kali Linux. To install dependencies, run:

```bash
chmod +x dependency_install.sh
sudo ./dependency_install.sh
````

The installer will:

* install apt packages (git, curl, go, build tools, nmap, masscan, seclists, etc.),
* install Go-based tools (amass, subfinder, httpx, ffuf, gau, waybackurls, hakrawler, etc.),
* attempt to build massdns (optional) and set up a Python venv or install Python packages.

> After installation, ensure `$HOME/go/bin` and `~/.local/bin` are in your PATH:
>
> ```bash
> echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"' >> ~/.bashrc
> source ~/.bashrc
> ```

### Common fix: `#include <pcap.h>` error

If you encounter an error like `#include <pcap.h> missing` (typically when building `naabu` or other pcap-dependent tools), run:

```bash
# update & install build deps (run as root or with sudo)
sudo apt update
sudo apt install -y build-essential pkg-config libpcap-dev

# reinstall naabu as your normal user (not root) so Go writes to $GOPATH/bin
su - "$SUDO_USER" -c 'export GOPATH=$HOME/go; export GOBIN=$HOME/go/bin; mkdir -p $GOPATH $GOBIN; /usr/bin/env go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'
```

---

## Usage

> **Important:** Pass only a domain (no `https://` or path). The script will normalize a full URL to its host, but for best results give `example.com` or `sub.example.com`.

Make the script executable (if needed) and run:

```bash
chmod +x hahahehe.py
python3 hahahehe.py example.com
# or (your playful variant)
sudo python hahahehe.py example.com
```

### Notes on input

* Accepts: `example.com`, `sub.example.com`, or a full URL (script will extract the host).
* Prefer the registered domain (e.g., `example.com`) to enumerate broadly.

---

## Output

By default results are saved under `recon_output/`:

```
recon_output/
├─ amass.txt
├─ subfinder.txt
├─ crtsh.txt
├─ subdomains_all.txt
├─ resolved.txt
├─ alive.json
├─ whois.json
├─ urls.txt
├─ nmap_full.xml
├─ nmap_full.nmap
├─ nmap_full.gnmap
├─ ffuf_<host>.json
└─ report.md
```

Open `recon_output/report.md` for a human-readable summary of findings and remediation suggestions.

---

## Troubleshooting & Tips

* If `masscan` reports `target IP address list empty`, you likely passed a full URL with path — pass the host/domain instead (or use the registered domain).
* If Go tools do not appear in your shell, add to your shell rc:

  ```bash
  echo 'export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"' >> ~/.bashrc
  source ~/.bashrc
  ```
* If Python packages fail inside the venv, install build deps:

  ```bash
  sudo apt install -y build-essential python3-dev libssl-dev
  source ~/.venv_recon/bin/activate
  pip install <failed-package>
  ```
* If a Go `go install` failed while running the installer, try running the failing `go install` command manually as your unprivileged user (not root).

---

## Security & Legal

This tool performs active scanning and fuzzing which can be intrusive and noisy. Only run against systems you own or have explicit permission to test. Unauthorized scanning may be illegal and could have consequences.

---

## Contributing

Contributions are welcome. Open an issue or submit a PR and include tests or a short description of your change.

---


