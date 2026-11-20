# PhantomRecon 👁️
### Network Reconnaissance & Mapping Suite

> Final Year B.Tech CS/Cybersecurity Project | Open Source | Kali Linux

---

## Overview

**PhantomRecon** is a real-world network reconnaissance and mapping tool built for security professionals and students. It performs active network scanning using industry-standard methods, aggregates results into a structured topology, and generates a rich interactive HTML report — all with zero pip installs required.

It leverages tools already present on Kali Linux (`nmap`, `arp-scan`, `whois`, `dig`) via subprocess, combined with custom Python logic for analysis, banner grabbing, TTL-based OS guessing, vulnerability hinting, and topology building.

---

## Features

| Module | What It Does |
|--------|-------------|
| **ARP Sweep** | Layer 2 host discovery using `arp-scan` — finds hosts even behind firewalls |
| **ICMP Ping Sweep** | `nmap -sn` ping sweep to discover live hosts |
| **Reverse DNS** | PTR record resolution for all discovered IPs |
| **SYN/TCP Port Scan** | `nmap -sS` (root) or `-sT` (non-root) with version detection |
| **OS Fingerprinting** | TTL analysis + `nmap -O` OS detection |
| **Banner Grabbing** | Raw socket banner collection on FTP, SSH, HTTP, Redis, MySQL, etc. |
| **WHOIS Lookup** | Organization and country lookup for non-RFC1918 IPs |
| **Vulnerability Hints** | Per-port risk assessment with actionable recon hints |
| **Topology Builder** | JSON network graph with attacker → gateway → hosts structure |
| **HTML Report** | Interactive vis.js network map + sortable tables + severity badges |

---

## Quick Start

```bash
# 1. Clone / copy to Kali
git clone https://github.com/yourusername/PhantomRecon
cd PhantomRecon

# 2. Install dependencies (one time)
sudo ./phantomrecon.sh --install

# 3. Run a scan
sudo ./phantomrecon.sh -t 192.168.1.0/24

# 4. Interactive mode (prompts for all options)
sudo ./phantomrecon.sh
```

---

## Usage

### Bash Launcher (recommended)

```bash
sudo ./phantomrecon.sh [OPTIONS]

Options:
  -t, --target <IP/CIDR>   Target to scan (required)
  -p, --ports  <range>     Port range (default: 1-1000)
  -o, --out    <dir>       Output directory
  --full                   Scan all 65535 ports
  --no-os                  Skip OS detection
  --no-banner              Skip banner grabbing
  --install                Install all dependencies
  --demo                   Safe demo scan on localhost
  --check <IP> <PORT>      Quick port connectivity check
  --info                   Show local network interfaces
```

### Python Engine (direct)

```bash
sudo python3 phantomrecon.py -t 192.168.1.0/24
sudo python3 phantomrecon.py -t 192.168.1.1 --ports 1-65535 --full
sudo python3 phantomrecon.py -t 10.0.0.0/24 --no-os --ports 22,80,443,3306
```

---

## Example Scans

```bash
# Standard LAN sweep
sudo ./phantomrecon.sh -t 192.168.1.0/24

# Deep scan on a specific host
sudo ./phantomrecon.sh -t 192.168.1.100 -p 1-65535

# Fast scan, no OS detection
sudo ./phantomrecon.sh -t 10.0.0.0/24 --no-os --ports 1-1000

# Demo (safe, scans only localhost)
sudo ./phantomrecon.sh --demo

# Quick port check
./phantomrecon.sh --check 192.168.1.1 22
```

---

## Output

Every scan generates two files in the output directory:

```
output/
├── phantomrecon_20250601_143022.html   ← Interactive report (open in browser)
└── phantomrecon_20250601_143022.json   ← Raw topology data
```

### Report Tabs

- **Overview** — stats summary, risk distribution per host
- **Network Map** — interactive vis.js topology graph (drag, zoom, hover)
- **Hosts** — full host table with MAC, vendor, OS, hostname
- **Ports & Vulns** — all open ports with severity badges and recon hints
- **Raw JSON** — full scan data for further processing

---

## Risk Severity System

| Level | Meaning | Example Services |
|-------|---------|-----------------|
| 🔴 CRITICAL | Unauthenticated access likely | Redis (6379), MongoDB (27017), Telnet (23), SMB (445) |
| 🟠 HIGH | Known CVEs or credential issues | RDP (3389), MySQL (3306), VNC (5900), FTP (21) |
| 🟡 MEDIUM | Exposure requires investigation | SSH (22), SMTP (25), DNS (53), PostgreSQL (5432) |
| 🔵 LOW/INFO | Normal services, verify config | HTTP (80), HTTPS (443), HTTP-Alt (8080) |

---

## Dependencies

All pre-installed on Kali Linux:

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning, service detection, OS fingerprinting |
| `arp-scan` | Layer 2 ARP host discovery |
| `whois` | WHOIS lookups for public IPs |
| `dig` (dnsutils) | DNS resolution |
| `python3` | Core engine (stdlib only — no pip installs) |

---

## Architecture

```
PhantomRecon/
├── phantomrecon.sh      # Bash launcher, installer, interactive mode
├── phantomrecon.py      # Python engine — all 6 scan phases
├── output/              # Generated reports (HTML + JSON)
└── README.md
```

### Scan Phases

```
Phase 1: Host Discovery    → ARP sweep + ICMP ping sweep + rDNS
Phase 2: Port Scanning     → nmap SYN/TCP scan with version detection
Phase 3: OS Detection      → TTL analysis + nmap -O fingerprinting
Phase 4: Banner Grabbing   → Raw socket banners (SSH, HTTP, Redis, MySQL...)
Phase 5: WHOIS / DNS       → PTR records, organization, country
Phase 6: Report Generation → JSON topology + interactive HTML report
```

---

## Academic Notes

This tool was developed as a Final Year B.Tech (CS/Cybersecurity) project. It demonstrates:

- **Active network reconnaissance** techniques used in real penetration testing
- **Multi-phase scanning pipeline** with concurrent execution
- **Structured data aggregation** and JSON topology modeling
- **Risk assessment** based on port exposure and known vulnerability patterns
- **Professional reporting** with interactive visualization

### Legal & Ethical Use

> ⚠️ PhantomRecon is for **authorized use only**. Always obtain explicit written permission before scanning any network or system you do not own. Unauthorized scanning is illegal in most jurisdictions.

---

## License

MIT License — open source, free to use and modify.

---

*Built with ❤️ by Cipher | CT University, Ludhiana | Phantom Series*
