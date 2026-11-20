#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          PHANTOM RECON - Network Reconnaissance Suite         ║
║              Final Year Project | CS/Cybersecurity            ║
║                   github.com/phantom/recon                    ║
╚═══════════════════════════════════════════════════════════════╝

Modules:
  1. Host Discovery       - ARP sweep + ICMP ping sweep
  2. Port Scanner         - SYN/TCP connect scan via nmap
  3. Service Fingerprint  - Banner grabbing + version detection
  4. OS Detection         - TTL analysis + nmap OS fingerprint
  5. Topology Mapper      - Build network graph as JSON
  6. Report Generator     - HTML report with visual map

Usage:
  sudo python3 phantomrecon.py -t 192.168.1.0/24
  sudo python3 phantomrecon.py -t 192.168.1.1 --ports 1-1000
  sudo python3 phantomrecon.py -t 192.168.1.0/24 --full
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ─────────────────────────── ANSI Colors ───────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;196m"
    GREEN   = "\033[38;5;82m"
    YELLOW  = "\033[38;5;220m"
    CYAN    = "\033[38;5;51m"
    MAGENTA = "\033[38;5;201m"
    BLUE    = "\033[38;5;33m"
    ORANGE  = "\033[38;5;208m"
    WHITE   = "\033[38;5;255m"
    GRAY    = "\033[38;5;244m"
    BG_DARK = "\033[48;5;234m"

# ─────────────────────────── Banner ────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{C.RESET}
{C.MAGENTA}{C.BOLD}              ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
              ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
              ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
              ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
              ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
              ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RESET}
{C.GRAY}              Network Reconnaissance & Mapping Suite v1.0
              Final Year Project | Open Source | Kali Linux{C.RESET}
"""

# ─────────────────────────── Logging ───────────────────────────────
class Log:
    _lock = threading.Lock()

    @staticmethod
    def _ts():
        return f"{C.GRAY}[{datetime.now().strftime('%H:%M:%S')}]{C.RESET}"

    @staticmethod
    def info(msg):
        with Log._lock:
            print(f"{Log._ts()} {C.CYAN}[*]{C.RESET} {msg}")

    @staticmethod
    def success(msg):
        with Log._lock:
            print(f"{Log._ts()} {C.GREEN}[+]{C.RESET} {msg}")

    @staticmethod
    def warn(msg):
        with Log._lock:
            print(f"{Log._ts()} {C.YELLOW}[!]{C.RESET} {msg}")

    @staticmethod
    def error(msg):
        with Log._lock:
            print(f"{Log._ts()} {C.RED}[-]{C.RESET} {msg}")

    @staticmethod
    def section(title):
        width = 60
        bar = "─" * width
        with Log._lock:
            print(f"\n{C.CYAN}{bar}{C.RESET}")
            print(f"{C.CYAN}  {C.BOLD}{title}{C.RESET}")
            print(f"{C.CYAN}{bar}{C.RESET}")

    @staticmethod
    def result_table(headers, rows):
        """Print a formatted table."""
        if not rows:
            return
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
        header_row = "|" + "|".join(f" {C.BOLD}{C.CYAN}{h:<{col_widths[i]}}{C.RESET} " for i, h in enumerate(headers)) + "|"

        print(f"\n{C.GRAY}{sep}{C.RESET}")
        print(header_row)
        print(f"{C.GRAY}{sep}{C.RESET}")
        for row in rows:
            colored_cells = []
            for i, cell in enumerate(row):
                cell_str = str(cell)
                if headers[i] == "STATE":
                    color = C.GREEN if "open" in cell_str.lower() else C.RED
                    colored_cells.append(f" {color}{cell_str:<{col_widths[i]}}{C.RESET} ")
                elif headers[i] in ("IP ADDRESS", "HOST"):
                    colored_cells.append(f" {C.YELLOW}{cell_str:<{col_widths[i]}}{C.RESET} ")
                else:
                    colored_cells.append(f" {C.WHITE}{cell_str:<{col_widths[i]}}{C.RESET} ")
            print("|" + "|".join(colored_cells) + "|")
        print(f"{C.GRAY}{sep}{C.RESET}\n")

# ─────────────────────────── Spinner ───────────────────────────────
class Spinner:
    def __init__(self, message):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def _spin(self):
        i = 0
        while self.running:
            frame = self.frames[i % len(self.frames)]
            print(f"\r{C.CYAN}{frame}{C.RESET} {self.message}", end="", flush=True)
            time.sleep(0.1)
            i += 1

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self, success=True):
        self.running = False
        if self.thread:
            self.thread.join()
        icon = f"{C.GREEN}✓{C.RESET}" if success else f"{C.RED}✗{C.RESET}"
        print(f"\r{icon} {self.message}        ")

# ──────────────────────── Dependency Check ─────────────────────────
def check_dependencies():
    """Check for required tools on the system."""
    Log.section("Dependency Check")
    required = {
        "nmap":     "Network scanner (core dependency)",
        "arp-scan": "ARP host discovery",
        "whois":    "WHOIS lookups",
        "dig":      "DNS resolution",
    }
    optional = {
        "masscan":  "Ultra-fast port scanning (optional)",
        "netdiscover": "Passive ARP discovery (optional)",
    }

    all_ok = True
    for tool, desc in required.items():
        path = shutil.which(tool)
        if path:
            Log.success(f"{C.BOLD}{tool:<15}{C.RESET} {C.GREEN}FOUND{C.RESET}  {C.GRAY}{desc}{C.RESET}")
        else:
            Log.error(f"{C.BOLD}{tool:<15}{C.RESET} {C.RED}MISSING{C.RESET} {desc}")
            all_ok = False

    for tool, desc in optional.items():
        path = shutil.which(tool)
        status = f"{C.YELLOW}OPTIONAL{C.RESET}" if not path else f"{C.GREEN}FOUND{C.RESET}"
        Log.info(f"{C.BOLD}{tool:<15}{C.RESET} {status}  {C.GRAY}{desc}{C.RESET}")

    if not all_ok:
        Log.error("Missing required tools. Run: sudo apt install nmap arp-scan whois dnsutils")
        sys.exit(1)

    return True

# ──────────────────────── Host Discovery ───────────────────────────
class HostDiscovery:
    def __init__(self, target):
        self.target = target
        self.discovered = {}  # ip -> {mac, hostname, method}

    def arp_sweep(self):
        """Use arp-scan for Layer 2 host discovery (most reliable on LAN)."""
        Log.info(f"Running ARP sweep on {C.YELLOW}{self.target}{C.RESET}...")
        try:
            result = subprocess.run(
                ["arp-scan", "--localnet", self.target, "--retry=3"],
                capture_output=True, text=True, timeout=60
            )
            # Also try without --localnet flag for specific ranges
            if result.returncode != 0:
                result = subprocess.run(
                    ["arp-scan", self.target, "--retry=3"],
                    capture_output=True, text=True, timeout=60
                )

            lines = result.stdout.strip().split("\n")
            count = 0
            for line in lines:
                # Match lines like: 192.168.1.1   aa:bb:cc:dd:ee:ff   Vendor
                match = re.match(
                    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
                    r"([0-9a-f:]{17})\s*(.*)",
                    line.strip(), re.IGNORECASE
                )
                if match:
                    ip, mac, vendor = match.groups()
                    self.discovered[ip] = {
                        "mac": mac.upper(),
                        "vendor": vendor.strip() or "Unknown",
                        "method": "ARP",
                        "hostname": "",
                        "os_guess": "",
                        "ports": [],
                        "services": {},
                    }
                    Log.success(f"  ARP: {C.YELLOW}{ip:<18}{C.RESET} {C.GRAY}{mac}  {vendor.strip()}{C.RESET}")
                    count += 1
            Log.info(f"ARP sweep complete: {C.GREEN}{count}{C.RESET} hosts found")
            return count
        except subprocess.TimeoutExpired:
            Log.warn("ARP sweep timed out")
            return 0
        except FileNotFoundError:
            Log.warn("arp-scan not available, skipping ARP sweep")
            return 0

    def ping_sweep(self):
        """ICMP ping sweep via nmap -sn."""
        Log.info(f"Running ICMP ping sweep on {C.YELLOW}{self.target}{C.RESET}...")
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--open",
                 "--reason", self.target, "-oX", "-"],
                capture_output=True, text=True, timeout=120
            )
            # Parse nmap XML output
            ip_pattern = re.findall(r'addr="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"', result.stdout)
            hostname_pattern = re.findall(r'hostname name="([^"]+)"', result.stdout)

            hosts_in_xml = re.findall(
                r'<host[^>]*>.*?</host>', result.stdout, re.DOTALL
            )
            count = 0
            for host_xml in hosts_in_xml:
                ip_m = re.search(r'addr="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"', host_xml)
                hn_m = re.search(r'hostname name="([^"]+)"', host_xml)
                state_m = re.search(r'<status state="([^"]+)"', host_xml)
                if ip_m and state_m and state_m.group(1) == "up":
                    ip = ip_m.group(1)
                    hostname = hn_m.group(1) if hn_m else ""
                    if ip not in self.discovered:
                        self.discovered[ip] = {
                            "mac": "N/A",
                            "vendor": "Unknown",
                            "method": "ICMP",
                            "hostname": hostname,
                            "os_guess": "",
                            "ports": [],
                            "services": {},
                        }
                        Log.success(f"  PING: {C.YELLOW}{ip:<18}{C.RESET} {C.GRAY}{hostname or 'no hostname'}{C.RESET}")
                        count += 1
                    elif hostname and not self.discovered[ip]["hostname"]:
                        self.discovered[ip]["hostname"] = hostname

            Log.info(f"Ping sweep complete: {C.GREEN}{count}{C.RESET} new hosts found")
            return count
        except subprocess.TimeoutExpired:
            Log.warn("Ping sweep timed out")
            return 0

    def resolve_hostnames(self):
        """Reverse DNS resolution for all discovered hosts."""
        Log.info("Resolving hostnames via reverse DNS...")
        def resolve(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return ip, hostname
            except Exception:
                return ip, ""

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(resolve, ip): ip for ip in self.discovered}
            for future in as_completed(futures):
                ip, hostname = future.result()
                if hostname and not self.discovered[ip]["hostname"]:
                    self.discovered[ip]["hostname"] = hostname

    def run(self):
        Log.section("Phase 1: Host Discovery")
        arp_count = self.arp_sweep()
        ping_count = self.ping_sweep()
        self.resolve_hostnames()

        total = len(self.discovered)
        Log.success(f"Total live hosts discovered: {C.GREEN}{C.BOLD}{total}{C.RESET}")

        if total == 0:
            Log.warn("No hosts found. Check your target range and network interface.")
            return self.discovered

        headers = ["IP ADDRESS", "MAC", "VENDOR", "HOSTNAME", "METHOD"]
        rows = [
            [ip,
             info["mac"],
             info["vendor"][:20],
             info["hostname"][:30] or "-",
             info["method"]]
            for ip, info in sorted(self.discovered.items(),
                                   key=lambda x: socket.inet_aton(x[0]))
        ]
        Log.result_table(headers, rows)
        return self.discovered

# ──────────────────────── Port Scanner ─────────────────────────────
class PortScanner:
    def __init__(self, hosts, port_range="1-1000", scan_type="tcp"):
        self.hosts = hosts
        self.port_range = port_range
        self.scan_type = scan_type

    def scan_host(self, ip):
        """Run nmap port scan on a single host."""
        flags = ["-sS"] if os.geteuid() == 0 else ["-sT"]  # SYN if root else TCP connect
        cmd = [
            "nmap", *flags,
            "-T4",
            "--open",
            "-p", self.port_range,
            "--version-intensity", "5",
            ip, "-oX", "-"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return ip, result.stdout
        except subprocess.TimeoutExpired:
            Log.warn(f"Scan of {ip} timed out")
            return ip, ""
        except Exception as e:
            Log.error(f"Scan of {ip} failed: {e}")
            return ip, ""

    def parse_nmap_xml(self, xml_output):
        """Parse nmap XML and return list of port dicts."""
        ports = []
        port_blocks = re.findall(r'<port[^>]*>.*?</port>', xml_output, re.DOTALL)
        for block in port_blocks:
            proto_m  = re.search(r'protocol="([^"]+)"', block)
            portid_m = re.search(r'portid="([^"]+)"', block)
            state_m  = re.search(r'<state state="([^"]+)"', block)
            name_m   = re.search(r'name="([^"]+)"', block)
            prod_m   = re.search(r'product="([^"]*)"', block)
            ver_m    = re.search(r'version="([^"]*)"', block)
            extra_m  = re.search(r'extrainfo="([^"]*)"', block)

            if portid_m and state_m and state_m.group(1) == "open":
                port_info = {
                    "port":     int(portid_m.group(1)),
                    "protocol": proto_m.group(1) if proto_m else "tcp",
                    "state":    state_m.group(1),
                    "service":  name_m.group(1) if name_m else "unknown",
                    "product":  prod_m.group(1) if prod_m else "",
                    "version":  ver_m.group(1) if ver_m else "",
                    "info":     extra_m.group(1) if extra_m else "",
                }
                ports.append(port_info)
        return ports

    def run(self):
        Log.section("Phase 2: Port Scanning & Service Detection")
        Log.info(f"Scanning {C.YELLOW}{len(self.hosts)}{C.RESET} hosts | "
                 f"Ports: {C.YELLOW}{self.port_range}{C.RESET} | "
                 f"Mode: {C.YELLOW}{'SYN (root)' if os.geteuid() == 0 else 'TCP Connect'}{C.RESET}")

        all_open_rows = []

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(self.scan_host, ip): ip for ip in self.hosts}
            for future in as_completed(futures):
                ip, xml = future.result()
                if not xml:
                    continue
                ports = self.parse_nmap_xml(xml)
                if ports:
                    self.hosts[ip]["ports"] = ports
                    Log.success(f"{C.YELLOW}{ip}{C.RESET} — {C.GREEN}{len(ports)}{C.RESET} open port(s)")
                    for p in ports:
                        svc = f"{p['product']} {p['version']}".strip() or p['service']
                        all_open_rows.append([
                            ip,
                            str(p["port"]),
                            p["protocol"].upper(),
                            "OPEN",
                            svc[:40],
                        ])
                        # Store service info on host
                        self.hosts[ip]["services"][p["port"]] = p
                else:
                    Log.warn(f"{C.YELLOW}{ip}{C.RESET} — no open ports in range {self.port_range}")

        if all_open_rows:
            all_open_rows.sort(key=lambda r: (r[0], int(r[1])))
            Log.result_table(["HOST", "PORT", "PROTO", "STATE", "SERVICE/VERSION"], all_open_rows)

        return self.hosts

# ──────────────────────── OS Detection ─────────────────────────────
class OSDetector:
    """OS fingerprinting via nmap -O and TTL analysis."""

    TTL_MAP = {
        (60, 70):   ("Linux",   "TTL≈64"),
        (124, 130): ("Windows", "TTL≈128"),
        (252, 256): ("Cisco/Network Device", "TTL≈255"),
        (30, 40):   ("Linux (behind NAT)", "TTL≈32-64 (hop-reduced)"),
    }

    def detect_ttl(self, ip):
        """Ping the host and analyze TTL value."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=5
            )
            ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                for (low, high), (os_name, note) in self.TTL_MAP.items():
                    if low <= ttl <= high:
                        return os_name, note, ttl
                return "Unknown", f"TTL={ttl}", ttl
        except Exception:
            pass
        return "Unknown", "No response", 0

    def detect_nmap_os(self, ip):
        """nmap OS fingerprinting (requires root)."""
        if os.geteuid() != 0:
            return "Root required for nmap OS detection"
        try:
            result = subprocess.run(
                ["nmap", "-O", "--osscan-guess", "-T4", ip, "-oX", "-"],
                capture_output=True, text=True, timeout=60
            )
            # Try to extract OS match
            os_match = re.search(r'<osmatch name="([^"]+)"[^/]*/>', result.stdout)
            if os_match:
                return os_match.group(1)
            # Fallback: osclass
            os_class = re.search(r'osfamily="([^"]+)"', result.stdout)
            if os_class:
                return os_class.group(1)
        except Exception:
            pass
        return ""

    def run(self, hosts):
        Log.section("Phase 3: OS Detection")
        rows = []
        for ip, info in hosts.items():
            os_ttl, note, ttl = self.detect_ttl(ip)
            os_nmap = self.detect_nmap_os(ip)
            os_final = os_nmap if os_nmap and os_nmap != "Root required for nmap OS detection" else os_ttl
            hosts[ip]["os_guess"] = os_final
            hosts[ip]["ttl"] = ttl
            rows.append([ip, os_final[:35], note, f"TTL={ttl}" if ttl else "N/A"])
            Log.success(f"{C.YELLOW}{ip}{C.RESET} → {C.MAGENTA}{os_final}{C.RESET} {C.GRAY}({note}){C.RESET}")

        Log.result_table(["HOST", "OS GUESS", "METHOD", "TTL"], rows)
        return hosts

# ──────────────────────── Banner Grabbing ──────────────────────────
class BannerGrabber:
    """Grab raw banners from open ports for extra intel."""

    GRAB_PORTS = {
        21: ("FTP",   b""),
        22: ("SSH",   b""),
        25: ("SMTP",  b"EHLO phantom\r\n"),
        80: ("HTTP",  b"HEAD / HTTP/1.0\r\n\r\n"),
        110:("POP3",  b""),
        443:("HTTPS", b"HEAD / HTTP/1.0\r\n\r\n"),
        445:("SMB",   b""),
        3306:("MySQL",b""),
        5432:("PgSQL",b""),
        6379:("Redis",b"INFO\r\n"),
        8080:("HTTP-Alt", b"HEAD / HTTP/1.0\r\n\r\n"),
    }

    def grab(self, ip, port):
        """Attempt raw banner grab."""
        probe = self.GRAB_PORTS.get(port, (None, b""))[1]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            if probe:
                sock.send(probe)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            return banner[:200]
        except Exception:
            return ""

    def run(self, hosts):
        Log.section("Phase 4: Banner Grabbing")
        for ip, info in hosts.items():
            open_ports = [p["port"] for p in info.get("ports", [])]
            for port in open_ports:
                if port in self.GRAB_PORTS:
                    banner = self.grab(ip, port)
                    if banner:
                        hosts[ip]["services"][port]["banner"] = banner
                        service_name = self.GRAB_PORTS[port][0]
                        Log.success(
                            f"{C.YELLOW}{ip}:{port}{C.RESET} {C.GRAY}({service_name}){C.RESET} "
                            f"→ {C.WHITE}{banner[:60].replace(chr(10),' ').replace(chr(13),' ')}{C.RESET}"
                        )
        return hosts

# ──────────────────────── WHOIS Lookup ─────────────────────────────
class WHOISLookup:
    def run(self, hosts):
        Log.section("Phase 5: WHOIS & DNS Intel")
        for ip in hosts:
            # Reverse DNS
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                hosts[ip]["ptr"] = ptr
                Log.success(f"{C.YELLOW}{ip}{C.RESET} PTR → {C.CYAN}{ptr}{C.RESET}")
            except Exception:
                hosts[ip]["ptr"] = ""

            # Only do WHOIS for routable IPs
            if not ipaddress.ip_address(ip).is_private:
                try:
                    result = subprocess.run(
                        ["whois", ip],
                        capture_output=True, text=True, timeout=15
                    )
                    # Extract key WHOIS fields
                    org = re.search(r"(?:OrgName|org-name|Organization):\s*(.+)", result.stdout)
                    country = re.search(r"(?:Country|country):\s*(.+)", result.stdout)
                    hosts[ip]["whois_org"] = org.group(1).strip() if org else ""
                    hosts[ip]["whois_country"] = country.group(1).strip() if country else ""
                    if org:
                        Log.success(f"{C.YELLOW}{ip}{C.RESET} ORG → {C.CYAN}{org.group(1).strip()}{C.RESET}")
                except Exception:
                    pass
        return hosts

# ──────────────────────── Vulnerability Hints ──────────────────────
VULN_HINTS = {
    21:  ("FTP",   "HIGH",   "Check for anonymous login: ftp {ip} → user: anonymous"),
    22:  ("SSH",   "MEDIUM", "Check SSH version for known CVEs; test weak credentials"),
    23:  ("Telnet","CRITICAL","Telnet sends credentials in plaintext — immediate remediation"),
    25:  ("SMTP",  "MEDIUM", "Test for open relay: VRFY/EXPN commands"),
    53:  ("DNS",   "MEDIUM", "Test zone transfer: dig axfr @{ip}"),
    80:  ("HTTP",  "INFO",   "Run full web scan: nikto -h http://{ip}"),
    110: ("POP3",  "MEDIUM", "Cleartext authentication exposure"),
    135: ("RPC",   "HIGH",   "MS-RPC exposure — check for EternalBlue"),
    139: ("NetBIOS","HIGH",  "NetBIOS exposure — SMB reconnaissance possible"),
    443: ("HTTPS", "INFO",   "Check SSL/TLS config: sslscan {ip}:443"),
    445: ("SMB",   "CRITICAL","SMBv1 may be vulnerable to EternalBlue (MS17-010)"),
    1433:("MSSQL", "HIGH",   "MS SQL Server — default SA account check"),
    3306:("MySQL", "HIGH",   "MySQL accessible — check for empty root password"),
    3389:("RDP",   "HIGH",   "RDP exposed — BlueKeep if unpatched (CVE-2019-0708)"),
    5432:("PgSQL", "MEDIUM", "PostgreSQL — check for default credentials"),
    5900:("VNC",   "HIGH",   "VNC exposed — weak auth common"),
    6379:("Redis", "CRITICAL","Redis often unauthenticated — immediate remediation"),
    8080:("HTTP-Alt","INFO", "Alternate HTTP — may expose admin panels"),
    9200:("Elastic","CRITICAL","Elasticsearch often unauthenticated"),
    27017:("MongoDB","CRITICAL","MongoDB — often no auth in default config"),
}

# ──────────────────────── Topology Builder ─────────────────────────
def build_topology(hosts, target, scan_meta):
    """Build a JSON network topology for visualization."""
    nodes = []
    edges = []

    # Attacker node
    attacker_ip = get_local_ip()
    nodes.append({
        "id": "attacker",
        "label": f"PhantomRecon\n{attacker_ip}",
        "type": "attacker",
        "ip": attacker_ip,
    })

    # Gateway (first hop usually .1)
    try:
        gw = get_default_gateway()
        if gw:
            nodes.append({"id": "gw", "label": f"Gateway\n{gw}", "type": "gateway", "ip": gw})
            edges.append({"from": "attacker", "to": "gw", "label": ""})
    except Exception:
        gw = None

    for ip, info in hosts.items():
        vuln_ports = []
        risk = "LOW"
        for p in info.get("ports", []):
            pnum = p["port"]
            if pnum in VULN_HINTS:
                severity = VULN_HINTS[pnum][1]
                vuln_ports.append({"port": pnum, "service": VULN_HINTS[pnum][0], "severity": severity,
                                   "hint": VULN_HINTS[pnum][2].replace("{ip}", ip)})
                if severity == "CRITICAL": risk = "CRITICAL"
                elif severity == "HIGH" and risk not in ("CRITICAL",): risk = "HIGH"
                elif severity == "MEDIUM" and risk not in ("CRITICAL","HIGH"): risk = "MEDIUM"

        node = {
            "id": ip,
            "label": f"{ip}\n{info.get('hostname','') or info.get('vendor','') or ''}",
            "type": "host",
            "ip": ip,
            "mac": info.get("mac",""),
            "vendor": info.get("vendor",""),
            "hostname": info.get("hostname",""),
            "os": info.get("os_guess",""),
            "ports": info.get("ports",[]),
            "services": {str(k): v for k,v in info.get("services",{}).items()},
            "risk": risk,
            "vuln_hints": vuln_ports,
            "ttl": info.get("ttl", 0),
            "method": info.get("method",""),
        }
        nodes.append(node)
        src = "gw" if gw else "attacker"
        edges.append({"from": src, "to": ip, "label": f"{len(info.get('ports',[]))} ports"})

    return {
        "meta": scan_meta,
        "nodes": nodes,
        "edges": edges,
    }

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_default_gateway():
    try:
        result = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

# ──────────────────────── HTML Report Generator ────────────────────
def generate_report(topology, output_path):
    """Generate a full HTML report with interactive network map."""
    meta = topology["meta"]
    nodes = topology["nodes"]
    edges = topology["edges"]

    host_nodes = [n for n in nodes if n["type"] == "host"]
    total_open_ports = sum(len(n.get("ports",[])) for n in host_nodes)
    critical_hosts = [n for n in host_nodes if n.get("risk") == "CRITICAL"]
    high_hosts     = [n for n in host_nodes if n.get("risk") == "HIGH"]

    # Build port rows
    port_rows_html = ""
    for node in host_nodes:
        for p in node.get("ports", []):
            pnum = p["port"]
            hint = ""
            severity = "INFO"
            if pnum in VULN_HINTS:
                severity = VULN_HINTS[pnum][1]
                hint = VULN_HINTS[pnum][2].replace("{ip}", node["ip"])
            svc = f"{p.get('product','')} {p.get('version','')}".strip() or p.get("service","?")
            banner = node.get("services",{}).get(str(pnum),{}).get("banner","")
            sev_class = {"CRITICAL":"sev-critical","HIGH":"sev-high",
                         "MEDIUM":"sev-medium","LOW":"sev-low","INFO":"sev-info"}.get(severity,"sev-info")
            port_rows_html += f"""
            <tr>
                <td class="ip-cell">{node['ip']}</td>
                <td>{pnum}/{p.get('protocol','tcp')}</td>
                <td><span class="state-open">OPEN</span></td>
                <td>{svc}</td>
                <td><span class="{sev_class}">{severity}</span></td>
                <td class="hint-cell">{hint}</td>
                <td class="banner-cell">{banner[:80] if banner else '-'}</td>
            </tr>"""

    # Build host summary rows
    host_rows_html = ""
    for node in host_nodes:
        risk_class = {"CRITICAL":"sev-critical","HIGH":"sev-high",
                      "MEDIUM":"sev-medium","LOW":"sev-low"}.get(node.get("risk","LOW"),"sev-low")
        ports_str = ", ".join(str(p["port"]) for p in node.get("ports",[])[:10])
        if len(node.get("ports",[])) > 10:
            ports_str += f" +{len(node['ports'])-10} more"
        host_rows_html += f"""
        <tr>
            <td class="ip-cell">{node['ip']}</td>
            <td>{node.get('mac','-')}</td>
            <td>{node.get('hostname','-') or '-'}</td>
            <td>{node.get('vendor','-') or '-'}</td>
            <td>{node.get('os','-') or '-'}</td>
            <td>{node.get('method','-')}</td>
            <td><span class="{risk_class}">{node.get('risk','LOW')}</span></td>
            <td>{ports_str or 'None found'}</td>
        </tr>"""

    # Topology JSON for vis.js
    vis_nodes = []
    for n in nodes:
        color_map = {
            "attacker": "#00ff9d",
            "gateway":  "#ff9500",
            "host":     {
                "CRITICAL": "#ff2255",
                "HIGH":     "#ff6600",
                "MEDIUM":   "#ffcc00",
                "LOW":      "#33aaff",
            }.get(n.get("risk","LOW"), "#33aaff")
        }
        color = color_map if isinstance(color_map, str) else color_map.get(n["type"], "#33aaff")
        shape = "diamond" if n["type"] == "attacker" else ("triangle" if n["type"] == "gateway" else "dot")
        vis_nodes.append({
            "id": n["id"],
            "label": n["label"],
            "color": {"background": color, "border": "#ffffff22"},
            "shape": shape,
            "size": 25 if n["type"] in ("attacker","gateway") else 18,
            "font": {"color": "#e0e0e0", "size": 11, "face": "monospace"},
            "title": (f"<b>{n.get('ip','')}</b><br>"
                      f"OS: {n.get('os','?')}<br>"
                      f"Ports: {len(n.get('ports',[]))}<br>"
                      f"Risk: {n.get('risk','?')}")
        })

    vis_edges = []
    for e in edges:
        vis_edges.append({
            "from": e["from"], "to": e["to"],
            "label": e.get("label",""),
            "color": {"color": "#ffffff33"},
            "font": {"color": "#888", "size": 9},
            "smooth": {"type": "curvedCW", "roundness": 0.1}
        })

    topology_json = json.dumps({"nodes": vis_nodes, "edges": vis_edges})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhantomRecon Report — {meta['target']}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

  :root {{
    --bg:        #0a0c12;
    --bg2:       #10131d;
    --bg3:       #161a27;
    --border:    #1e2535;
    --accent:    #00e5ff;
    --accent2:   #7b2fff;
    --green:     #00ff9d;
    --red:       #ff2255;
    --orange:    #ff6600;
    --yellow:    #ffcc00;
    --text:      #cdd6f4;
    --muted:     #6c7086;
    --font-mono: 'Share Tech Mono', monospace;
    --font-main: 'Exo 2', sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-main);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* HEADER */
  header {{
    background: linear-gradient(135deg, #0d0f1a 0%, #111827 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px;
    position: relative;
    overflow: hidden;
  }}
  header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 29px,
      #ffffff05 29px, #ffffff05 30px
    ),
    repeating-linear-gradient(
      90deg, transparent, transparent 29px,
      #ffffff04 29px, #ffffff04 30px
    );
  }}
  .header-inner {{ position: relative; z-index: 1; }}
  .brand {{
    font-family: var(--font-mono);
    font-size: 28px;
    color: var(--accent);
    letter-spacing: 6px;
    text-transform: uppercase;
    text-shadow: 0 0 30px var(--accent);
  }}
  .brand span {{ color: var(--accent2); }}
  .subtitle {{
    font-size: 12px;
    color: var(--muted);
    letter-spacing: 3px;
    margin-top: 4px;
    text-transform: uppercase;
  }}
  .meta-pills {{
    display: flex;
    gap: 12px;
    margin-top: 16px;
    flex-wrap: wrap;
  }}
  .pill {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px 12px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--muted);
  }}
  .pill span {{ color: var(--accent); }}

  /* NAV TABS */
  nav {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    display: flex;
    padding: 0 40px;
    gap: 0;
  }}
  .tab {{
    padding: 14px 24px;
    cursor: pointer;
    font-size: 12px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
    user-select: none;
  }}
  .tab:hover {{ color: var(--text); }}
  .tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}

  /* CONTENT */
  .content {{ display: none; padding: 32px 40px; max-width: 1400px; }}
  .content.active {{ display: block; }}

  /* STAT CARDS */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent);
  }}
  .stat-card.red::before   {{ background: var(--red); }}
  .stat-card.orange::before {{ background: var(--orange); }}
  .stat-card.green::before  {{ background: var(--green); }}
  .stat-card.purple::before {{ background: var(--accent2); }}
  .stat-value {{
    font-family: var(--font-mono);
    font-size: 36px;
    font-weight: 700;
    color: var(--accent);
    line-height: 1;
  }}
  .stat-card.red   .stat-value {{ color: var(--red); }}
  .stat-card.orange .stat-value {{ color: var(--orange); }}
  .stat-card.green  .stat-value {{ color: var(--green); }}
  .stat-label {{
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 6px;
  }}

  /* SECTION TITLES */
  .section-title {{
    font-family: var(--font-mono);
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--accent);
    margin: 32px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* TABLES */
  .table-wrap {{ overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{
    background: var(--bg3);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  td {{
    padding: 10px 16px;
    border-bottom: 1px solid #ffffff08;
    font-family: var(--font-mono);
    font-size: 12px;
    vertical-align: top;
  }}
  tr:hover td {{ background: #ffffff05; }}
  tr:last-child td {{ border-bottom: none; }}
  .ip-cell   {{ color: var(--yellow, #ffcc00); }}
  .hint-cell {{ color: var(--muted); font-size: 11px; }}
  .banner-cell {{ color: #888; font-size: 10px; word-break: break-all; max-width: 200px; }}

  /* BADGES */
  .state-open {{ color: var(--green); }}
  .sev-critical {{ background: #ff002244; color: #ff5577; padding: 2px 8px; border-radius: 3px; font-size: 10px; letter-spacing: 1px; }}
  .sev-high     {{ background: #ff660022; color: var(--orange); padding: 2px 8px; border-radius: 3px; font-size: 10px; letter-spacing: 1px; }}
  .sev-medium   {{ background: #ffcc0022; color: var(--yellow); padding: 2px 8px; border-radius: 3px; font-size: 10px; letter-spacing: 1px; }}
  .sev-low      {{ background: #33aaff22; color: #33aaff; padding: 2px 8px; border-radius: 3px; font-size: 10px; letter-spacing: 1px; }}
  .sev-info     {{ background: #ffffff11; color: var(--muted); padding: 2px 8px; border-radius: 3px; font-size: 10px; letter-spacing: 1px; }}

  /* NETWORK MAP */
  #network-map {{
    width: 100%;
    height: 580px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  .map-legend {{
    display: flex; gap: 20px; flex-wrap: wrap;
    margin-top: 12px; font-size: 11px; color: var(--muted);
  }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; }}
  .legend-dot {{
    width: 10px; height: 10px; border-radius: 50%;
  }}

  /* FOOTER */
  footer {{
    margin-top: 60px;
    padding: 24px 40px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--muted);
    font-family: var(--font-mono);
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}

  /* SCROLLBAR */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="brand">PHANTOM<span>RECON</span></div>
    <div class="subtitle">Network Reconnaissance &amp; Mapping Suite v1.0</div>
    <div class="meta-pills">
      <div class="pill">TARGET <span>{meta['target']}</span></div>
      <div class="pill">STARTED <span>{meta['start_time']}</span></div>
      <div class="pill">DURATION <span>{meta['duration']}</span></div>
      <div class="pill">PORTS <span>{meta['port_range']}</span></div>
      <div class="pill">SCANNER <span>{meta['scanner_ip']}</span></div>
    </div>
  </div>
</header>

<nav>
  <div class="tab active" onclick="switchTab('overview')">Overview</div>
  <div class="tab" onclick="switchTab('topology')">Network Map</div>
  <div class="tab" onclick="switchTab('hosts')">Hosts</div>
  <div class="tab" onclick="switchTab('ports')">Ports &amp; Vulns</div>
  <div class="tab" onclick="switchTab('raw')">Raw JSON</div>
</nav>

<!-- OVERVIEW TAB -->
<div class="content active" id="tab-overview">
  <div class="stats-grid">
    <div class="stat-card green">
      <div class="stat-value">{len(host_nodes)}</div>
      <div class="stat-label">Live Hosts</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{total_open_ports}</div>
      <div class="stat-label">Open Ports</div>
    </div>
    <div class="stat-card red">
      <div class="stat-value">{len(critical_hosts)}</div>
      <div class="stat-label">Critical Risk</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-value">{len(high_hosts)}</div>
      <div class="stat-label">High Risk</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-value">{meta['port_range']}</div>
      <div class="stat-label">Port Range</div>
    </div>
  </div>

  <div class="section-title">// Executive Summary</div>
  <p style="color:var(--muted); line-height:1.8; max-width:800px;">
    PhantomRecon conducted an active network reconnaissance sweep against <strong style="color:var(--text)">{meta['target']}</strong>
    on <strong style="color:var(--text)">{meta['start_time']}</strong>.
    The scan discovered <strong style="color:var(--green)">{len(host_nodes)} live hosts</strong> with a total of
    <strong style="color:var(--accent)">{total_open_ports} open ports</strong> detected.
    {f'<strong style="color:var(--red)">{len(critical_hosts)} host(s) are at CRITICAL risk</strong> due to exposure of services with known unauthenticated access patterns.' if critical_hosts else ''}
    {f'<strong style="color:var(--orange)">{len(high_hosts)} host(s) are at HIGH risk.</strong>' if high_hosts else ''}
    Immediate remediation is recommended for all CRITICAL and HIGH severity findings.
  </p>

  <div class="section-title">// Risk Distribution</div>
  <div class="stats-grid">
    {"".join(f'<div class="stat-card {"red" if n.get("risk")=="CRITICAL" else "orange" if n.get("risk")=="HIGH" else ""}"><div class="stat-value" style="font-size:16px;">{n["ip"]}</div><div class="stat-label">{n.get("os","?") or "Unknown OS"} · {len(n.get("ports",[]))} ports · <span style="color:{"var(--red)" if n.get("risk")=="CRITICAL" else "var(--orange)" if n.get("risk")=="HIGH" else "var(--accent)"}">{"⚠ " if n.get("risk") in ("CRITICAL","HIGH") else ""}{n.get("risk","LOW")}</span></div></div>' for n in host_nodes)}
  </div>
</div>

<!-- TOPOLOGY TAB -->
<div class="content" id="tab-topology">
  <div class="section-title">// Interactive Network Topology</div>
  <p style="color:var(--muted);font-size:12px;margin-bottom:12px;">
    Drag nodes to rearrange. Hover over a node for details. Scroll to zoom.
    Node color indicates risk level.
  </p>
  <div id="network-map"></div>
  <div class="map-legend">
    <div class="legend-item"><div class="legend-dot" style="background:#00ff9d"></div> Attacker (You)</div>
    <div class="legend-item"><div class="legend-dot" style="background:#ff9500"></div> Gateway</div>
    <div class="legend-item"><div class="legend-dot" style="background:#33aaff"></div> Low Risk</div>
    <div class="legend-item"><div class="legend-dot" style="background:#ffcc00"></div> Medium Risk</div>
    <div class="legend-item"><div class="legend-dot" style="background:#ff6600"></div> High Risk</div>
    <div class="legend-item"><div class="legend-dot" style="background:#ff2255"></div> Critical Risk</div>
  </div>
</div>

<!-- HOSTS TAB -->
<div class="content" id="tab-hosts">
  <div class="section-title">// Discovered Hosts</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>IP Address</th><th>MAC</th><th>Hostname</th><th>Vendor</th>
          <th>OS Guess</th><th>Discovery</th><th>Risk</th><th>Open Ports</th>
        </tr>
      </thead>
      <tbody>{host_rows_html}</tbody>
    </table>
  </div>
</div>

<!-- PORTS TAB -->
<div class="content" id="tab-ports">
  <div class="section-title">// Open Ports, Services &amp; Vulnerability Hints</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Host</th><th>Port</th><th>State</th><th>Service / Version</th>
          <th>Severity</th><th>Recon Hint</th><th>Banner</th>
        </tr>
      </thead>
      <tbody>{port_rows_html if port_rows_html else '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:24px;">No open ports found in scanned range</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- RAW JSON TAB -->
<div class="content" id="tab-raw">
  <div class="section-title">// Raw Scan Data (JSON)</div>
  <pre style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;
              padding:24px;overflow:auto;font-size:11px;color:var(--muted);
              font-family:var(--font-mono);max-height:600px;">{json.dumps(topology, indent=2, default=str)}</pre>
</div>

<footer>
  <span>PhantomRecon v1.0 · Final Year Project · CT University</span>
  <span>Generated: {meta['start_time']} · Target: {meta['target']}</span>
  <span>For authorized use only · <a href="#">github.com/phantom/recon</a></span>
</footer>

<script>
function switchTab(name) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'topology') initMap();
}}

let mapInit = false;
function initMap() {{
  if (mapInit) return;
  mapInit = true;
  const data = {topology_json};
  const container = document.getElementById('network-map');
  const options = {{
    nodes: {{
      borderWidth: 1,
      shadow: {{ enabled: true, color: 'rgba(0,229,255,0.3)', size: 15 }},
    }},
    edges: {{
      width: 1.5,
      shadow: false,
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.5 }} }},
    }},
    physics: {{
      enabled: true,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {{ gravitationalConstant: -60, springLength: 120, springConstant: 0.05 }},
      stabilization: {{ iterations: 150 }},
    }},
    interaction: {{
      hover: true,
      tooltipDelay: 100,
      navigationButtons: true,
    }},
    background: {{ color: 'transparent' }},
  }};
  new vis.Network(container, {{
    nodes: new vis.DataSet(data.nodes),
    edges: new vis.DataSet(data.edges),
  }}, options);
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    Log.success(f"HTML report saved: {C.CYAN}{output_path}{C.RESET}")

# ──────────────────────── JSON Save ────────────────────────────────
def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    Log.success(f"JSON data saved:   {C.CYAN}{path}{C.RESET}")

# ──────────────────────── Main ─────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="PhantomRecon — Network Reconnaissance & Mapping Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 phantomrecon.py -t 192.168.1.0/24
  sudo python3 phantomrecon.py -t 192.168.1.1 --ports 1-65535
  sudo python3 phantomrecon.py -t 192.168.1.0/24 --full --out /tmp/recon
  sudo python3 phantomrecon.py -t 10.0.0.0/24 --no-os --ports 80,443,8080,8443
        """
    )
    parser.add_argument("-t", "--target",   required=True,
                        help="Target IP, CIDR range, or hostname")
    parser.add_argument("-p", "--ports",    default="1-1000",
                        help="Port range (default: 1-1000). E.g. 22,80,443 or 1-65535")
    parser.add_argument("--full",           action="store_true",
                        help="Full scan: ports 1-65535 + OS detection + banners (slow)")
    parser.add_argument("--no-os",          action="store_true",
                        help="Skip OS detection phase")
    parser.add_argument("--no-banner",      action="store_true",
                        help="Skip banner grabbing phase")
    parser.add_argument("--no-whois",       action="store_true",
                        help="Skip WHOIS/DNS lookup phase")
    parser.add_argument("--out", "-o",      default="./phantomrecon_output",
                        help="Output directory (default: ./phantomrecon_output)")
    parser.add_argument("--threads",        type=int, default=5,
                        help="Parallel host scan threads (default: 5)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    if os.geteuid() != 0:
        Log.warn("Not running as root. SYN scan and OS detection will be limited.")
        Log.warn("For best results: sudo python3 phantomrecon.py ...")

    # Setup output dir
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    port_range = "1-65535" if args.full else args.ports

    check_dependencies()

    start_time = datetime.now()
    Log.info(f"Scan target:  {C.YELLOW}{args.target}{C.RESET}")
    Log.info(f"Port range:   {C.YELLOW}{port_range}{C.RESET}")
    Log.info(f"Output dir:   {C.YELLOW}{out_dir}{C.RESET}")
    Log.info(f"Threads:      {C.YELLOW}{args.threads}{C.RESET}")

    # ── Phase 1: Host Discovery ──
    discovery = HostDiscovery(args.target)
    hosts = discovery.run()

    if not hosts:
        Log.error("No hosts discovered. Exiting.")
        sys.exit(0)

    # ── Phase 2: Port Scanning ──
    scanner = PortScanner(hosts, port_range=port_range)
    hosts = scanner.run()

    # ── Phase 3: OS Detection ──
    if not args.no_os:
        detector = OSDetector()
        hosts = detector.run(hosts)

    # ── Phase 4: Banner Grabbing ──
    if not args.no_banner:
        grabber = BannerGrabber()
        hosts = grabber.run(hosts)

    # ── Phase 5: WHOIS/DNS ──
    if not args.no_whois:
        whois = WHOISLookup()
        hosts = whois.run(hosts)

    # ── Build Topology & Reports ──
    Log.section("Phase 6: Generating Reports")
    end_time = datetime.now()
    duration = str(end_time - start_time).split(".")[0]

    scan_meta = {
        "target":      args.target,
        "port_range":  port_range,
        "start_time":  start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time":    end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration":    duration,
        "scanner_ip":  get_local_ip(),
        "total_hosts": len(hosts),
        "tool":        "PhantomRecon v1.0",
    }

    topology = build_topology(hosts, args.target, scan_meta)

    report_path = out_dir / f"phantomrecon_{timestamp}.html"
    json_path   = out_dir / f"phantomrecon_{timestamp}.json"

    generate_report(topology, str(report_path))
    save_json(topology, str(json_path))

    # ── Final Summary ──
    Log.section("Scan Complete")
    print(f"""
  {C.CYAN}╔══════════════════════════════════════════════════╗{C.RESET}
  {C.CYAN}║{C.RESET}  {C.BOLD}PHANTOMRECON SCAN SUMMARY{C.RESET}                       {C.CYAN}║{C.RESET}
  {C.CYAN}╠══════════════════════════════════════════════════╣{C.RESET}
  {C.CYAN}║{C.RESET}  Target    : {C.YELLOW}{args.target:<36}{C.RESET} {C.CYAN}║{C.RESET}
  {C.CYAN}║{C.RESET}  Duration  : {C.WHITE}{duration:<36}{C.RESET} {C.CYAN}║{C.RESET}
  {C.CYAN}║{C.RESET}  Hosts     : {C.GREEN}{len(hosts):<36}{C.RESET} {C.CYAN}║{C.RESET}
  {C.CYAN}║{C.RESET}  Open Ports: {C.GREEN}{sum(len(h.get("ports",[])) for h in hosts.values()):<36}{C.RESET} {C.CYAN}║{C.RESET}
  {C.CYAN}║{C.RESET}  Report    : {C.CYAN}{str(report_path):<36}{C.RESET} {C.CYAN}║{C.RESET}
  {C.CYAN}╚══════════════════════════════════════════════════╝{C.RESET}
    """)

    Log.info(f"Open report: {C.BOLD}firefox {report_path} &{C.RESET}")


if __name__ == "__main__":
    main()
