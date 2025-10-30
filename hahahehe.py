#!/usr/bin/env python3
"""
Full recon automation (passive + active) using CLI tools + Python checks.

Features:
- Subdomain enumeration (amass, subfinder, crt.sh)
- DNS resolution + HTTP alive check (aiohttp + dnspython)
- WHOIS lookup + IP geolocation
- Port scan (masscan + nmap)
- Directory fuzzing (ffuf)
- Technology fingerprinting (whatweb)
- URL harvesting (gau, waybackurls)
- Markdown report generation

Run:
    sudo python3 hahahehe.py example.com
"""

import os
import sys
import json
import shutil
import socket
import asyncio
import argparse
import subprocess
from pathlib import Path
import aiohttp
import dns.resolver
import requests
import tldextract
from bs4 import BeautifulSoup
import whois

# ---------- Config ----------
WORKDIR = Path("recon_output")
WORKDIR.mkdir(exist_ok=True)
AMASS_OUT = WORKDIR / "amass.txt"
SUBFINDER_OUT = WORKDIR / "subfinder.txt"
CRT_OUT = WORKDIR / "crtsh.txt"
SUB_ALL = WORKDIR / "subdomains_all.txt"
RESOLVED = WORKDIR / "resolved.txt"
ALIVE = WORKDIR / "alive.json"
WHOIS_OUT = WORKDIR / "whois.json"
TECH_OUT = WORKDIR / "tech.txt"
URLS_FILE = WORKDIR / "urls.txt"
REPORT_MD = WORKDIR / "report.md"

# Default Kali wordlists
FFUF_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
ADMIN_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/admin-panels.txt"

# ---------- Helpers ----------
# Fancy banner
def print_banner():
    banner = r"""
                      .__          _____ .__           .__                  ___    
  _____ _____    ____ |__|____    / ___ \|  |__   ____ |  |__   ____    /\  \  \   
 /     \\__  \  /    \|  \__  \  / / ._\ \  |  \_/ __ \|  |  \_/ __ \   \/   \  \  
|  Y Y  \/ __ \|   |  \  |/ __ \<  \_____/   Y  \  ___/|   Y  \  ___/   /\    )  ) 
|__|_|  (____  /___|  /__(____  /\_____\ |___|  /\___  >___|  /\___  >  \/   /  /  
      \/     \/     \/        \/              \/     \/     \/     \/       /__/    
    """
    print("\033[1;31m" + banner + "\033[0m")  # red color
    print("Recon Automation Script — Passive + Active Enumeration\n     --by aheedkhan")

print_banner()

def run(cmd, capture=False):
    print(f"[+] Running: {cmd}")
    if capture:
        return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        return subprocess.run(cmd, shell=True)

def safe_read(path):
    if not Path(path).exists():
        return []
    return [line.strip() for line in open(path, "r", errors="ignore") if line.strip()]

# ---------- WHOIS + IP Info ----------
def whois_lookup(domain):
    print("[+] Performing WHOIS lookup...")
    data = {}
    try:
        w = whois.whois(domain)
        data = {k: str(v) for k, v in w.items()}
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"http://ip-api.com/json/{ip}").json()
        data["ip"] = ip
        data["geo"] = geo
        with open(WHOIS_OUT, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("[!] WHOIS lookup failed:", e)
    return data

# ---------- Subdomain Enumeration ----------
def passive_subdomain_enumeration(domain):
    if shutil.which("amass"):
        run(f"amass enum -d {domain} -o {AMASS_OUT}")
    if shutil.which("subfinder"):
        run(f"subfinder -d {domain} -o {SUBFINDER_OUT}")
    # crt.sh
    print("[+] Querying crt.sh...")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
        if r.status_code == 200:
            j = r.json()
            with open(CRT_OUT, "w") as f:
                for it in j:
                    v = it.get("name_value")
                    if v:
                        for s in v.splitlines():
                            s = s.strip().lstrip("*.")
                            f.write(s + "\n")
    except Exception as e:
        print("[!] crt.sh failed:", e)
    # Combine all
    subs = set()
    for p in (AMASS_OUT, SUBFINDER_OUT, CRT_OUT):
        subs.update(safe_read(p))
    subs = [s.lower().strip().lstrip("*.") for s in subs if domain in s]
    with open(SUB_ALL, "w") as f:
        f.write("\n".join(sorted(set(subs))))
    print(f"[+] Found {len(subs)} subdomains.")
    return subs

# ---------- DNS Resolve ----------
async def resolve_host(host):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    try:
        answers = resolver.resolve(host, 'A')
        return host, [str(r) for r in answers]
    except Exception:
        return host, []

async def resolve_all(hosts):
    tasks = [resolve_host(h) for h in hosts]
    results = []
    for t in asyncio.as_completed(tasks):
        results.append(await t)
    return [r for r in results if r[1]]

# ---------- HTTP Alive Check ----------
async def http_check(session, host):
    for scheme in ["https://", "http://"]:
        url = scheme + host
        try:
            async with session.get(url, timeout=10, ssl=False) as resp:
                html = await resp.text()
                soup = BeautifulSoup(html, "html.parser")
                title = soup.title.string.strip() if soup.title else ""
                return {
                    "host": host,
                    "url": url,
                    "status": resp.status,
                    "title": title[:100],
                    "final_url": str(resp.url)
                }
        except Exception:
            continue
    return None

async def check_alive(resolved):
    connector = aiohttp.TCPConnector(limit_per_host=10, ssl=False)
    alive = []
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [http_check(session, h) for h, _ in resolved]
        for t in asyncio.as_completed(tasks):
            r = await t
            if r:
                alive.append(r)
    return alive

# ---------- Technology Detection ----------
def tech_detect(hosts):
    if not shutil.which("whatweb"):
        print("[!] whatweb not installed; skipping tech scan.")
        return
    print("[+] Running WhatWeb...")
    with open(TECH_OUT, "w") as f:
        for h in hosts:
            run(f"whatweb -q {h}", capture=False)
            subprocess.run(f"whatweb -q {h} >> {TECH_OUT}", shell=True)
    print(f"[+] Tech fingerprint saved to {TECH_OUT}")

# ---------- Port Scanning ----------
def port_scan(resolved):
    ips_file = WORKDIR / "ips.txt"
    with open(ips_file, "w") as f:
        for _, ips in resolved:
            f.write("\n".join(ips) + "\n")
    if shutil.which("masscan"):
        run(f"masscan -iL {ips_file} -p1-65535 --rate 1000 -oL {WORKDIR/'masscan.txt'}")
    if shutil.which("nmap"):
        run(f"nmap -iL {ips_file} -sC -sV -oA {WORKDIR/'nmap_full'}")

# ---------- Directory Fuzzing ----------
def run_ffuf(alive):
    if not shutil.which("ffuf"):
        print("[!] ffuf not installed; skipping directory fuzzing.")
        return
    for a in alive:
        host = a["host"]
        out = WORKDIR / f"ffuf_{host}.json"
        run(f"ffuf -u https://{host}/FUZZ -w {FFUF_WORDLIST} -of json -o {out}")

# ---------- URL Harvesting ----------
def gather_urls(domain, alive):
    urls = set()
    hosts_file = WORKDIR / "hosts.txt"
    with open(hosts_file, "w") as f:
        for a in alive:
            f.write(a["host"] + "\n")
    if shutil.which("gau"):
        run(f"gau --input-file {hosts_file} --output {WORKDIR/'gau.txt'}")
        urls.update(safe_read(WORKDIR/'gau.txt'))
    if shutil.which("waybackurls"):
        run(f"waybackurls {domain} > {WORKDIR/'waybackurls.txt'}")
        urls.update(safe_read(WORKDIR/'waybackurls.txt'))
    with open(URLS_FILE, "w") as f:
        f.write("\n".join(sorted(urls)))
    print(f"[+] URLs saved to {URLS_FILE}")

# ---------- Report ----------
def generate_report(domain, subs, resolved, alive, whois_data):
    md = []
    md.append(f"# Recon Report for `{domain}`\n")
    md.append("## WHOIS + IP Info\n")
    md.append("```json\n" + json.dumps(whois_data, indent=2) + "\n```")
    md.append(f"\n## Subdomains ({len(subs)})\n")
    md.append("```\n" + "\n".join(subs[:100]) + "\n```")
    md.append(f"\n## Resolved Hosts ({len(resolved)})\n")
    for h, ips in resolved:
        md.append(f"- {h} -> {', '.join(ips)}")
    md.append(f"\n## Alive Hosts ({len(alive)})\n")
    for a in alive:
        md.append(f"- {a['host']} [{a['status']}] -> {a['final_url']} | {a['title']}")
    md.append("\n## Tools Output\n")
    md.append("- Masscan/Nmap results: recon_output/nmap_full.*")
    md.append("- WhatWeb: recon_output/tech.txt")
    md.append("- URLs: recon_output/urls.txt")
    md.append("- FFUF: recon_output/ffuf_*.json")
    with open(REPORT_MD, "w") as f:
        f.write("\n".join(md))
    print(f"[+] Report saved -> {REPORT_MD}")

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Full recon pipeline (CLI + Python)")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    args = parser.parse_args()

    domain = args.domain
    print(f"=== Starting full recon for {domain} ===")

    whois_data = whois_lookup(domain)
    subs = passive_subdomain_enumeration(domain)
    loop = asyncio.get_event_loop()
    resolved = loop.run_until_complete(resolve_all(subs))
    alive = loop.run_until_complete(check_alive(resolved))
    with open(ALIVE, "w") as f:
        json.dump(alive, f, indent=2)
    port_scan(resolved)
    tech_detect([a["host"] for a in alive])
    run_ffuf(alive)
    gather_urls(domain, alive)
    generate_report(domain, subs, resolved, alive, whois_data)
    print("\n Recon complete! Check recon_output/report.md")

if __name__ == "__main__":
    main()
