#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     BUGHUNTER RECON SUITE v3.0                             ║
║           Advanced Bug Bounty Reconnaissance & Enumeration Tool            ║
║                                                                            ║
║  Automates: WHOIS · Nmap · Recon-ng · DNS · Subdomain Enum · Report Gen   ║
║  Author   : BugHunter Recon Suite                                          ║
║  License  : MIT — For authorized security testing only                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    sudo python3 bughunter_recon.py -t example.com
    sudo python3 bughunter_recon.py -t example.com -o report.txt --fast
    sudo python3 bughunter_recon.py -t example.com --all --threads 100

Requirements:
    pip install python-nmap python-whois dnspython requests
    apt install nmap whois  (Kali/Ubuntu)
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

# ─── Dependency Check & Install ──────────────────────────────────────────────

REQUIRED_PACKAGES = {
    "nmap": "python-nmap",
    "whois": "python-whois",
    "dns.resolver": "dnspython",
    "requests": "requests",
}

def check_and_install_deps():
    """Auto-install missing Python packages."""
    missing = []
    for module, pip_name in REQUIRED_PACKAGES.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing
        )
        print("[+] Dependencies installed successfully.")

check_and_install_deps()

import nmap
import whois
import dns.resolver
import requests

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

class C:
    """ANSI color codes for terminal output."""
    R = "\033[91m"   # Red
    G = "\033[92m"   # Green
    Y = "\033[93m"   # Yellow
    B = "\033[94m"   # Blue
    M = "\033[95m"   # Magenta
    CY = "\033[96m"  # Cyan
    W = "\033[97m"   # White
    BOLD = "\033[1m"
    DIM = "\033[2m"
    X = "\033[0m"    # Reset

# ─── Utility Functions ───────────────────────────────────────────────────────

LOCK = threading.Lock()
RESULTS = {
    "target": "",
    "scan_start": "",
    "scan_end": "",
    "whois": {},
    "dns_records": {},
    "subdomains": [],
    "nmap_hosts": [],
    "emails": [],
    "technologies": [],
    "vulnerabilities": [],
    "reverse_dns": {},
    "http_headers": {},
}

def banner():
    """Print the tool banner."""
    print(f"""
{C.CY}{C.BOLD}
 ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.X}
{C.G}    ╔═══════════════════════════════════════════════════════════╗
    ║    Advanced Bug Bounty Recon Suite v3.0                  ║
    ║    WHOIS · Nmap · Recon-ng · DNS · Subdomain Enum        ║
    ║    Fast. Efficient. Automated.                           ║
    ╚═══════════════════════════════════════════════════════════╝{C.X}
""")

def log(msg, level="info"):
    """Thread-safe colored logging."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {
        "info": C.B,
        "success": C.G,
        "warning": C.Y,
        "error": C.R,
        "task": C.M,
        "data": C.CY,
    }
    c = colors.get(level, C.W)
    symbols = {
        "info": "ℹ",
        "success": "✓",
        "warning": "⚠",
        "error": "✗",
        "task": "►",
        "data": "◆",
    }
    sym = symbols.get(level, "·")
    with LOCK:
        print(f"  {C.DIM}[{ts}]{C.X} {c}{sym}{C.X} {msg}")

def separator(title=""):
    """Print a visual separator."""
    width = 70
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n  {C.DIM}{'─' * pad} {C.CY}{C.BOLD}{title}{C.X}{C.DIM} {'─' * pad}{C.X}")
    else:
        print(f"  {C.DIM}{'─' * width}{C.X}")

def resolve_target(target):
    """Resolve domain to IP address."""
    try:
        ip = socket.gethostbyname(target)
        log(f"Resolved {C.BOLD}{target}{C.X} → {C.G}{ip}{C.X}", "success")
        return ip
    except socket.gaierror:
        log(f"Could not resolve {target}", "error")
        return None

def check_tool(name):
    """Check if external tool is available on PATH."""
    return shutil.which(name) is not None

# ─── WHOIS Module ────────────────────────────────────────────────────────────

def run_whois(target):
    """Perform WHOIS lookup using python-whois with CLI fallback."""
    separator("WHOIS LOOKUP")
    log(f"Running WHOIS lookup on {C.BOLD}{target}{C.X}", "task")
    data = {}

    try:
        w = whois.whois(target)
        fields = {
            "domain_name": "Domain Name",
            "registrar": "Registrar",
            "whois_server": "WHOIS Server",
            "creation_date": "Created",
            "expiration_date": "Expires",
            "updated_date": "Updated",
            "name_servers": "Name Servers",
            "status": "Status",
            "dnssec": "DNSSEC",
            "org": "Organization",
            "state": "State",
            "country": "Country",
            "emails": "Emails",
            "registrant": "Registrant",
            "admin_email": "Admin Email",
        }
        for key, label in fields.items():
            val = getattr(w, key, None)
            if val:
                if isinstance(val, list):
                    val = list(set(str(v) for v in val))
                    data[label] = val
                    for v in val:
                        log(f"  {label}: {C.CY}{v}{C.X}", "data")
                else:
                    data[label] = str(val)
                    log(f"  {label}: {C.CY}{val}{C.X}", "data")

        # Extract emails for later use
        emails_found = []
        if w.emails:
            emails_found = w.emails if isinstance(w.emails, list) else [w.emails]
        RESULTS["emails"].extend(emails_found)

        # Domain age calculation
        if w.creation_date:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            age_days = (datetime.datetime.now() - created).days
            age_years = age_days / 365.25
            data["Domain Age"] = f"{age_days} days ({age_years:.1f} years)"
            log(f"  Domain Age: {C.CY}{age_days} days ({age_years:.1f} years){C.X}", "data")

    except Exception as e:
        log(f"python-whois failed: {e}", "warning")
        # Fallback to CLI whois
        if check_tool("whois"):
            log("Falling back to CLI whois...", "info")
            try:
                result = subprocess.run(
                    ["whois", target],
                    capture_output=True, text=True, timeout=30
                )
                data["raw_whois"] = result.stdout
                # Parse key fields from raw output
                for line in result.stdout.splitlines():
                    line = line.strip()
                    for keyword in ["Registrar:", "Creation Date:", "Registry Expiry",
                                    "Name Server:", "DNSSEC:", "Registrant Org"]:
                        if line.lower().startswith(keyword.lower()):
                            key, _, val = line.partition(":")
                            data[key.strip()] = val.strip()
                            log(f"  {key.strip()}: {C.CY}{val.strip()}{C.X}", "data")
            except subprocess.TimeoutExpired:
                log("CLI whois timed out", "error")
        else:
            log("whois command not found on system", "error")

    RESULTS["whois"] = data
    log(f"WHOIS complete — {len(data)} fields collected", "success")
    return data

# ─── DNS Enumeration Module ─────────────────────────────────────────────────

def run_dns_enum(target):
    """Enumerate DNS records for the target domain."""
    separator("DNS ENUMERATION")
    log(f"Enumerating DNS records for {C.BOLD}{target}{C.X}", "task")

    record_types = [
        "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME",
        "SRV", "CAA", "PTR", "DMARC", "SPF"
    ]
    dns_data = {}

    for rtype in record_types:
        query_name = target
        if rtype == "DMARC":
            query_name = f"_dmarc.{target}"
            rtype_actual = "TXT"
        elif rtype == "SPF":
            rtype_actual = "TXT"
        else:
            rtype_actual = rtype

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            answers = resolver.resolve(query_name, rtype_actual)
            records = []
            for rdata in answers:
                record_str = str(rdata)
                records.append(record_str)
                # Extract emails from TXT/SOA records
                email_matches = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    record_str
                )
                RESULTS["emails"].extend(email_matches)
            if records:
                dns_data[rtype] = records
                for rec in records:
                    log(f"  {rtype:6s} → {C.CY}{rec}{C.X}", "data")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.NoNameservers:
            log(f"  {rtype}: No nameservers available", "warning")
        except Exception:
            pass

    # Reverse DNS for main IP
    try:
        ip = socket.gethostbyname(target)
        rev = dns.reversename.from_address(ip)
        reverse_name = str(dns.resolver.resolve(rev, "PTR")[0])
        dns_data["Reverse DNS"] = [f"{ip} → {reverse_name}"]
        RESULTS["reverse_dns"][ip] = reverse_name
        log(f"  rDNS  → {C.CY}{ip} → {reverse_name}{C.X}", "data")
    except Exception:
        pass

    RESULTS["dns_records"] = dns_data
    log(f"DNS enumeration complete — {sum(len(v) for v in dns_data.values())} records found", "success")
    return dns_data

# ─── Subdomain Enumeration Module ───────────────────────────────────────────

def run_subdomain_enum(target, threads=50):
    """Multi-threaded subdomain enumeration using multiple sources."""
    separator("SUBDOMAIN ENUMERATION")
    log(f"Enumerating subdomains for {C.BOLD}{target}{C.X}", "task")

    subdomains = set()

    # ── Source 1: crt.sh (Certificate Transparency) ──
    log("Querying crt.sh (Certificate Transparency logs)...", "info")
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            timeout=20,
            headers={"User-Agent": "BugHunter-Recon/3.0"}
        )
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{target}") or sub == target:
                        if "*" not in sub:
                            subdomains.add(sub)
            log(f"  crt.sh returned {C.G}{len(subdomains)}{C.X} subdomains", "success")
    except Exception as e:
        log(f"  crt.sh query failed: {e}", "warning")

    # ── Source 2: HackerTarget API ──
    log("Querying HackerTarget API...", "info")
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={target}",
            timeout=15
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            before = len(subdomains)
            for line in resp.text.strip().splitlines():
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(f".{target}") or sub == target:
                        subdomains.add(sub)
            log(f"  HackerTarget added {C.G}{len(subdomains) - before}{C.X} new subdomains", "success")
    except Exception as e:
        log(f"  HackerTarget query failed: {e}", "warning")

    # ── Source 3: ThreatMiner API ──
    log("Querying ThreatMiner API...", "info")
    try:
        resp = requests.get(
            f"https://api.threatminer.org/v2/domain.php?q={target}&rt=5",
            timeout=15
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("results"):
                before = len(subdomains)
                for sub in data["results"]:
                    sub = sub.strip().lower()
                    if sub.endswith(f".{target}") or sub == target:
                        subdomains.add(sub)
                log(f"  ThreatMiner added {C.G}{len(subdomains) - before}{C.X} new subdomains", "success")
    except Exception as e:
        log(f"  ThreatMiner query failed: {e}", "warning")

    # ── Source 4: AlienVault OTX ──
    log("Querying AlienVault OTX...", "info")
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
            timeout=15,
            headers={"User-Agent": "BugHunter-Recon/3.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            before = len(subdomains)
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(f".{target}") or hostname == target:
                    subdomains.add(hostname)
            log(f"  AlienVault added {C.G}{len(subdomains) - before}{C.X} new subdomains", "success")
    except Exception as e:
        log(f"  AlienVault query failed: {e}", "warning")

    # ── Source 5: DNS Bruteforce ──
    log(f"DNS bruteforce with {C.BOLD}{threads}{C.X} threads...", "info")
    wordlist = [
        "www", "mail", "ftp", "admin", "blog", "dev", "staging", "api",
        "app", "beta", "cdn", "cloud", "cms", "cpanel", "dashboard",
        "db", "demo", "dns", "docs", "email", "files", "forum", "git",
        "gitlab", "help", "home", "host", "hub", "internal", "intranet",
        "jenkins", "jira", "lab", "login", "m", "manage", "media",
        "mobile", "monitor", "mx", "mysql", "new", "news", "ns", "ns1",
        "ns2", "old", "panel", "portal", "prod", "proxy", "remote",
        "repo", "search", "secure", "server", "shop", "smtp", "sql",
        "ssh", "ssl", "stage", "static", "status", "store", "support",
        "test", "testing", "v1", "v2", "vault", "vpn", "web", "webmail",
        "wiki", "wp", "www2", "autodiscover", "autoconfig", "exchange",
        "owa", "sso", "auth", "oauth", "accounts", "assets", "backup",
        "ci", "deploy", "docker", "elastic", "grafana", "graphql",
        "kafka", "kibana", "kubernetes", "k8s", "ldap", "log", "logs",
        "metrics", "minio", "mongo", "nginx", "node", "payments",
        "postgres", "rabbitmq", "redis", "registry", "s3", "sandbox",
        "sentry", "sonar", "splunk", "swagger", "traefik", "uat",
    ]

    def resolve_subdomain(sub_prefix):
        fqdn = f"{sub_prefix}.{target}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(fqdn)
            return fqdn
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, prefix): prefix
            for prefix in wordlist
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)

    brute_count = len(subdomains)
    log(f"  Bruteforce completed", "success")

    # ── Resolve all subdomains to IPs ──
    log("Resolving subdomain IPs...", "info")
    resolved = {}

    def resolve_ip(sub):
        try:
            ip = socket.gethostbyname(sub)
            return (sub, ip)
        except Exception:
            return (sub, "N/A")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(resolve_ip, sub) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            sub, ip = future.result()
            resolved[sub] = ip
            log(f"  {sub} → {C.CY}{ip}{C.X}", "data")

    RESULTS["subdomains"] = [
        {"subdomain": sub, "ip": ip} for sub, ip in sorted(resolved.items())
    ]

    log(f"Subdomain enumeration complete — {C.G}{C.BOLD}{len(subdomains)}{C.X} unique subdomains found", "success")
    return resolved

# ─── HTTP Header Analysis ───────────────────────────────────────────────────

def run_http_analysis(target):
    """Analyze HTTP headers and detect technologies."""
    separator("HTTP HEADER ANALYSIS")
    log(f"Analyzing HTTP headers for {C.BOLD}{target}{C.X}", "task")

    headers_data = {}
    tech_detected = []

    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(
                url, timeout=10, allow_redirects=True,
                headers={"User-Agent": "BugHunter-Recon/3.0"},
                verify=False
            )
            headers_data[scheme] = dict(resp.headers)
            log(f"  {scheme.upper()} Status: {C.CY}{resp.status_code}{C.X}", "data")
            log(f"  Final URL: {C.CY}{resp.url}{C.X}", "data")

            # Security headers check
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "X-XSS-Protection": "XSS Protection",
                "Referrer-Policy": "Referrer Policy",
                "Permissions-Policy": "Permissions Policy",
                "Cross-Origin-Opener-Policy": "COOP",
                "Cross-Origin-Resource-Policy": "CORP",
            }
            missing_security = []
            for header, name in security_headers.items():
                if header.lower() in {k.lower() for k in resp.headers}:
                    log(f"  {C.G}✓{C.X} {name}: Present", "success")
                else:
                    missing_security.append(name)
                    log(f"  {C.R}✗{C.X} {name}: {C.R}MISSING{C.X}", "warning")

            if missing_security:
                RESULTS["vulnerabilities"].append({
                    "type": "Missing Security Headers",
                    "severity": "MEDIUM",
                    "details": f"Missing: {', '.join(missing_security)}",
                    "url": url,
                })

            # Technology detection from headers
            server = resp.headers.get("Server", "")
            if server:
                tech_detected.append(f"Server: {server}")
                log(f"  Server: {C.CY}{server}{C.X}", "data")

            powered_by = resp.headers.get("X-Powered-By", "")
            if powered_by:
                tech_detected.append(f"Powered-By: {powered_by}")
                log(f"  X-Powered-By: {C.CY}{powered_by}{C.X}", "data")

            # Detect tech from HTML
            body = resp.text[:10000].lower()
            tech_signatures = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Drupal": ["drupal", "sites/default"],
                "Joomla": ["joomla", "/media/system"],
                "React": ["react", "_reactroot", "__next"],
                "Angular": ["ng-version", "angular"],
                "Vue.js": ["vue.js", "__vue__"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "Cloudflare": ["cloudflare"],
                "Nginx": ["nginx"],
                "Apache": ["apache"],
                "Laravel": ["laravel", "csrf-token"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "ASP.NET": ["__viewstate", "asp.net"],
                "PHP": [".php", "x-powered-by: php"],
            }
            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if sig in body or sig in str(resp.headers).lower():
                        if tech not in tech_detected:
                            tech_detected.append(tech)
                            log(f"  Technology: {C.CY}{tech}{C.X}", "data")
                        break

            break  # If HTTPS works, skip HTTP
        except requests.exceptions.SSLError:
            if scheme == "https":
                RESULTS["vulnerabilities"].append({
                    "type": "SSL/TLS Issue",
                    "severity": "HIGH",
                    "details": "SSL certificate error detected",
                    "url": url,
                })
                log(f"  {C.R}SSL Error on {url}{C.X}", "warning")
        except Exception as e:
            log(f"  {scheme.upper()} failed: {e}", "warning")

    RESULTS["http_headers"] = headers_data
    RESULTS["technologies"] = tech_detected
    log(f"HTTP analysis complete — {len(tech_detected)} technologies detected", "success")
    return headers_data

# ─── Nmap Module ─────────────────────────────────────────────────────────────

def run_nmap(target, ports="1-10000", speed="4", scripts=True):
    """Run Nmap SYN scan with service detection and NSE scripts."""
    separator("NMAP PORT SCAN")
    log(f"Running Nmap scan on {C.BOLD}{target}{C.X}", "task")
    log(f"  Ports: {ports} | Speed: T{speed} | Scripts: {scripts}", "info")

    if not check_tool("nmap"):
        log("nmap is not installed! Install with: apt install nmap", "error")
        return {}

    try:
        nm = nmap.PortScanner()

        # Build scan arguments
        args = f"-sS -sV -O -T{speed} --open -Pn"
        if scripts:
            args += " --script=default,vuln,ssl-enum-ciphers,http-headers"
            args += ",http-title,http-server-header,banner"

        log(f"  Command: nmap {args} -p {ports} {target}", "info")
        log("  Scanning... (this may take a few minutes)", "info")

        nm.scan(target, ports, arguments=args)

        hosts_data = []
        for host in nm.all_hosts():
            host_info = {
                "host": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "os_matches": [],
                "ports": [],
            }

            log(f"\n  Host: {C.G}{host}{C.X} ({nm[host].hostname()}) [{nm[host].state()}]", "success")

            # OS Detection
            if "osmatch" in nm[host]:
                for osmatch in nm[host]["osmatch"][:3]:
                    os_info = f"{osmatch['name']} ({osmatch['accuracy']}% confidence)"
                    host_info["os_matches"].append(os_info)
                    log(f"  OS: {C.CY}{os_info}{C.X}", "data")

            # Port results
            for proto in nm[host].all_protocols():
                ports_list = sorted(nm[host][proto].keys())
                for port in ports_list:
                    svc = nm[host][proto][port]
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": svc["state"],
                        "service": svc.get("name", "unknown"),
                        "version": f"{svc.get('product', '')} {svc.get('version', '')}".strip(),
                        "extra": svc.get("extrainfo", ""),
                        "scripts": {},
                    }

                    # NSE script results
                    if "script" in svc:
                        port_info["scripts"] = dict(svc["script"])
                        for script_name, output in svc["script"].items():
                            # Check for vulnerabilities
                            if "VULNERABLE" in output.upper() or "vuln" in script_name:
                                RESULTS["vulnerabilities"].append({
                                    "type": f"Nmap Script: {script_name}",
                                    "severity": "HIGH",
                                    "details": output[:200],
                                    "port": port,
                                })

                    host_info["ports"].append(port_info)

                    version_str = port_info["version"] or "unknown"
                    state_color = C.G if svc["state"] == "open" else C.R
                    log(
                        f"  {state_color}{port:>5}/{proto}{C.X}  "
                        f"{svc['state']:<8} {svc.get('name', 'unknown'):<15} {version_str}",
                        "data"
                    )

            hosts_data.append(host_info)

        RESULTS["nmap_hosts"] = hosts_data
        total_ports = sum(len(h["ports"]) for h in hosts_data)
        log(f"\nNmap scan complete — {C.G}{C.BOLD}{total_ports}{C.X} open ports found", "success")
        return hosts_data

    except nmap.PortScannerError as e:
        log(f"Nmap error (are you running as root?): {e}", "error")
        log("Try: sudo python3 bughunter_recon.py -t target.com", "info")
        return {}
    except Exception as e:
        log(f"Nmap scan failed: {e}", "error")
        return {}

# ─── Recon-ng Module ─────────────────────────────────────────────────────────

def run_reconng(target):
    """Run recon-ng modules if available, otherwise use API-based recon."""
    separator("RECON-NG / OSINT RECON")
    log(f"Running OSINT reconnaissance on {C.BOLD}{target}{C.X}", "task")

    # Check if recon-ng is installed
    if check_tool("recon-ng"):
        log("recon-ng detected — running modules...", "info")
        try:
            # Create a recon-ng resource script
            rc_content = f"""workspaces create bughunter_{target.replace('.','_')}
db insert domains domain={target}
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-hosts/certificate_transparency
run
modules load recon/hosts-hosts/resolve
run
show hosts
exit
"""
            rc_path = f"/tmp/bughunter_reconng_{os.getpid()}.rc"
            with open(rc_path, "w") as f:
                f.write(rc_content)

            result = subprocess.run(
                ["recon-ng", "-r", rc_path],
                capture_output=True, text=True, timeout=120
            )

            # Parse recon-ng output
            for line in result.stdout.splitlines():
                line = line.strip()
                if target in line and line:
                    log(f"  {C.CY}{line}{C.X}", "data")

            # Clean up
            os.remove(rc_path)
            log("recon-ng modules completed", "success")

        except subprocess.TimeoutExpired:
            log("recon-ng timed out after 120 seconds", "warning")
        except Exception as e:
            log(f"recon-ng error: {e}", "warning")
    else:
        log("recon-ng not installed — using API-based OSINT instead", "warning")
        log("Install recon-ng: apt install recon-ng", "info")

    # ── Additional OSINT regardless of recon-ng ──

    # Wayback Machine URLs
    log("Querying Wayback Machine for archived URLs...", "info")
    try:
        resp = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{target}&output=json&fl=original&collapse=urlkey&limit=100",
            timeout=15
        )
        if resp.status_code == 200:
            urls = resp.json()
            if len(urls) > 1:  # First row is header
                unique_urls = set()
                for row in urls[1:]:
                    unique_urls.add(row[0])
                log(f"  Found {C.G}{len(unique_urls)}{C.X} archived URLs", "success")
                # Check for interesting files
                interesting = [u for u in unique_urls if any(
                    ext in u.lower() for ext in
                    [".sql", ".bak", ".env", ".git", ".config", ".xml",
                     ".json", ".yml", ".yaml", ".log", ".zip", ".tar",
                     "admin", "backup", "debug", "phpinfo", "wp-config",
                     ".key", ".pem", "password", "secret", "token"]
                )]
                if interesting:
                    log(f"  {C.R}⚠ Found {len(interesting)} potentially sensitive URLs:{C.X}", "warning")
                    for url in interesting[:20]:
                        log(f"    {C.Y}{url}{C.X}", "warning")
                        RESULTS["vulnerabilities"].append({
                            "type": "Sensitive URL in Wayback",
                            "severity": "MEDIUM",
                            "details": url,
                        })
    except Exception as e:
        log(f"  Wayback Machine query failed: {e}", "warning")

    # ── Email harvesting from multiple sources ──
    log("Harvesting emails...", "info")
    try:
        # Search engine scraping for emails
        resp = requests.get(
            f"https://api.hackertarget.com/pagelinks/?q={target}",
            timeout=15
        )
        if resp.status_code == 200:
            emails = set(re.findall(
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                resp.text
            ))
            for email in emails:
                if target in email or not any(x in email for x in ["example.com", "test.com"]):
                    RESULTS["emails"].append(email)
                    log(f"  Email: {C.CY}{email}{C.X}", "data")
    except Exception:
        pass

    # Deduplicate emails
    RESULTS["emails"] = list(set(RESULTS["emails"]))
    log(f"OSINT recon complete — {len(RESULTS['emails'])} emails collected", "success")

# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(target, output_file):
    """Generate comprehensive .txt report."""
    separator("GENERATING REPORT")
    log(f"Writing report to {C.BOLD}{output_file}{C.X}", "task")

    RESULTS["scan_end"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Deduplicate
    RESULTS["emails"] = list(set(RESULTS["emails"]))

    lines = []
    w = lines.append  # shorthand

    w("=" * 80)
    w("    BUGHUNTER RECON SUITE v3.0 — RECONNAISSANCE REPORT")
    w("=" * 80)
    w("")
    w(f"  Target       : {target}")
    w(f"  Scan Started : {RESULTS['scan_start']}")
    w(f"  Scan Ended   : {RESULTS['scan_end']}")
    w(f"  Generated    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    w(f"  System       : {platform.system()} {platform.release()}")
    w("")

    # ── Executive Summary ──
    w("─" * 80)
    w("  EXECUTIVE SUMMARY")
    w("─" * 80)
    total_ports = sum(len(h.get("ports", [])) for h in RESULTS["nmap_hosts"])
    total_subs = len(RESULTS["subdomains"])
    total_vulns = len(RESULTS["vulnerabilities"])
    total_emails = len(RESULTS["emails"])
    total_tech = len(RESULTS["technologies"])

    risk = "LOW"
    if total_vulns >= 5:
        risk = "CRITICAL"
    elif total_vulns >= 3:
        risk = "HIGH"
    elif total_vulns >= 1:
        risk = "MEDIUM"

    w(f"  Overall Risk    : {risk}")
    w(f"  Open Ports      : {total_ports}")
    w(f"  Subdomains      : {total_subs}")
    w(f"  Vulnerabilities : {total_vulns}")
    w(f"  Emails Found    : {total_emails}")
    w(f"  Technologies    : {total_tech}")
    w("")

    # ── WHOIS ──
    w("─" * 80)
    w("  WHOIS INFORMATION")
    w("─" * 80)
    for key, val in RESULTS["whois"].items():
        if key == "raw_whois":
            continue
        if isinstance(val, list):
            w(f"  {key}:")
            for v in val:
                w(f"    · {v}")
        else:
            w(f"  {key:20s}: {val}")
    w("")

    # ── DNS Records ──
    w("─" * 80)
    w("  DNS RECORDS")
    w("─" * 80)
    for rtype, records in RESULTS["dns_records"].items():
        w(f"  {rtype}:")
        for rec in records:
            w(f"    · {rec}")
    w("")

    # ── Subdomains ──
    w("─" * 80)
    w(f"  SUBDOMAINS ({total_subs} found)")
    w("─" * 80)
    w(f"  {'Subdomain':<45} {'IP Address':<20}")
    w(f"  {'─'*44} {'─'*19}")
    for entry in RESULTS["subdomains"]:
        w(f"  {entry['subdomain']:<45} {entry['ip']:<20}")
    w("")

    # ── Nmap Results ──
    w("─" * 80)
    w(f"  NMAP SCAN RESULTS ({total_ports} open ports)")
    w("─" * 80)
    for host in RESULTS["nmap_hosts"]:
        w(f"  Host: {host['host']} ({host.get('hostname', '')}) — {host['state']}")
        if host.get("os_matches"):
            w(f"  OS Detection:")
            for os_match in host["os_matches"]:
                w(f"    · {os_match}")
        w("")
        w(f"  {'Port':<10} {'State':<10} {'Service':<15} {'Version':<35}")
        w(f"  {'─'*9} {'─'*9} {'─'*14} {'─'*34}")
        for port in host["ports"]:
            w(f"  {port['port']:<10} {port['state']:<10} {port['service']:<15} {port['version']:<35}")
            if port.get("scripts"):
                for script_name, output in port["scripts"].items():
                    w(f"    [NSE] {script_name}:")
                    for script_line in output.splitlines()[:5]:
                        w(f"      {script_line}")
        w("")

    # ── Technologies ──
    w("─" * 80)
    w(f"  TECHNOLOGIES DETECTED ({total_tech})")
    w("─" * 80)
    for tech in RESULTS["technologies"]:
        w(f"  · {tech}")
    w("")

    # ── Emails ──
    w("─" * 80)
    w(f"  EMAILS HARVESTED ({total_emails})")
    w("─" * 80)
    for email in sorted(RESULTS["emails"]):
        w(f"  · {email}")
    w("")

    # ── HTTP Headers ──
    w("─" * 80)
    w("  HTTP HEADERS")
    w("─" * 80)
    for scheme, headers in RESULTS["http_headers"].items():
        w(f"  [{scheme.upper()}]")
        for key, val in headers.items():
            w(f"    {key}: {val}")
        w("")

    # ── Vulnerabilities ──
    w("─" * 80)
    w(f"  VULNERABILITIES & FINDINGS ({total_vulns})")
    w("─" * 80)
    if RESULTS["vulnerabilities"]:
        for i, vuln in enumerate(RESULTS["vulnerabilities"], 1):
            severity = vuln.get("severity", "INFO")
            w(f"  [{i}] [{severity}] {vuln['type']}")
            w(f"      Details: {vuln['details']}")
            if "url" in vuln:
                w(f"      URL: {vuln['url']}")
            if "port" in vuln:
                w(f"      Port: {vuln['port']}")
            w("")
    else:
        w("  No vulnerabilities detected in automated scan.")
        w("  Manual testing recommended for logic flaws, auth bypass, etc.")
    w("")

    # ── Recommendations ──
    w("─" * 80)
    w("  RECOMMENDATIONS & NEXT STEPS")
    w("─" * 80)
    recommendations = [
        "1. Manual testing for OWASP Top 10 vulnerabilities (SQLi, XSS, CSRF, SSRF)",
        "2. Test authentication and authorization mechanisms",
        "3. Check for IDOR and broken access control",
        "4. Fuzz API endpoints for parameter injection",
        "5. Test file upload functionality for RCE",
        "6. Check for sensitive data exposure in responses",
        "7. Test for subdomain takeover on discovered subdomains",
        "8. Review JavaScript files for API keys and secrets",
        "9. Check for open redirects and CORS misconfigurations",
        "10. Test for rate limiting and brute force protection",
    ]
    for rec in recommendations:
        w(f"  {rec}")
    w("")

    w("=" * 80)
    w("  END OF REPORT — Generated by BugHunter Recon Suite v3.0")
    w("=" * 80)

    report = "\n".join(lines)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    file_size = os.path.getsize(output_file)
    log(f"Report saved: {C.G}{C.BOLD}{output_file}{C.X} ({file_size:,} bytes)", "success")
    return report

# ─── Main ────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="BugHunter Recon Suite v3.0 — Automated Bug Bounty Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              sudo python3 bughunter_recon.py -t example.com
              sudo python3 bughunter_recon.py -t example.com -o report.txt --fast
              sudo python3 bughunter_recon.py -t example.com -p 1-65535 --threads 100
              sudo python3 bughunter_recon.py -t example.com --skip-nmap
              sudo python3 bughunter_recon.py -t example.com --all
        """)
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: <target>_recon.txt)")
    parser.add_argument("-p", "--ports", default="1-10000", help="Port range (default: 1-10000)")
    parser.add_argument("--speed", default="4", choices=["1","2","3","4","5"], help="Nmap timing (T1-T5, default: T4)")
    parser.add_argument("--threads", type=int, default=50, help="Subdomain bruteforce threads (default: 50)")
    parser.add_argument("--fast", action="store_true", help="Fast mode: top 1000 ports, T5, skip bruteforce")
    parser.add_argument("--all", action="store_true", help="Full scan: all 65535 ports, all modules")
    parser.add_argument("--skip-whois", action="store_true", help="Skip WHOIS lookup")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip Nmap scan")
    parser.add_argument("--skip-reconng", action="store_true", help="Skip Recon-ng / OSINT")
    parser.add_argument("--skip-dns", action="store_true", help="Skip DNS enumeration")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP header analysis")
    parser.add_argument("--skip-subs", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return parser.parse_args()

def main():
    """Main entry point."""
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    banner()
    args = parse_args()

    target = args.target.strip().lower()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    output_file = args.output or f"{target.replace('.', '_')}_recon.txt"

    if args.fast:
        args.ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443,8888"
        args.speed = "5"

    if args.all:
        args.ports = "1-65535"
        args.threads = 100

    RESULTS["target"] = target
    RESULTS["scan_start"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    separator("TARGET INFORMATION")
    log(f"Target:  {C.BOLD}{C.CY}{target}{C.X}", "info")
    log(f"Output:  {output_file}", "info")
    log(f"Ports:   {args.ports}", "info")
    log(f"Speed:   T{args.speed}", "info")
    log(f"Threads: {args.threads}", "info")

    ip = resolve_target(target)
    if not ip:
        log("Cannot resolve target. Aborting.", "error")
        sys.exit(1)

    start_time = time.time()

    # ── Run modules ──
    if not args.skip_whois:
        run_whois(target)

    if not args.skip_dns:
        run_dns_enum(target)

    if not args.skip_subs:
        run_subdomain_enum(target, threads=args.threads)

    if not args.skip_http:
        run_http_analysis(target)

    if not args.skip_nmap:
        run_nmap(target, ports=args.ports, speed=args.speed, scripts=True)

    if not args.skip_reconng:
        run_reconng(target)

    # ── Generate report ──
    report = generate_report(target, output_file)

    elapsed = time.time() - start_time
    separator("SCAN COMPLETE")
    log(f"Total time: {C.BOLD}{elapsed:.1f} seconds{C.X}", "success")
    log(f"Report:     {C.BOLD}{C.G}{output_file}{C.X}", "success")

    # Print summary
    total_ports = sum(len(h.get("ports", [])) for h in RESULTS["nmap_hosts"])
    print(f"""
  {C.G}╔══════════════════════════════════════════════════╗
  ║              SCAN SUMMARY                        ║
  ╠══════════════════════════════════════════════════╣
  ║  Subdomains      : {len(RESULTS['subdomains']):<5}                        ║
  ║  Open Ports      : {total_ports:<5}                        ║
  ║  Emails          : {len(RESULTS['emails']):<5}                        ║
  ║  Technologies    : {len(RESULTS['technologies']):<5}                        ║
  ║  DNS Records     : {sum(len(v) for v in RESULTS['dns_records'].values()):<5}                        ║
  ║  Vulnerabilities : {len(RESULTS['vulnerabilities']):<5}                        ║
  ║  Scan Time       : {elapsed:<5.1f}s                       ║
  ╠══════════════════════════════════════════════════╣
  ║  Report: {output_file:<40}║
  ╚══════════════════════════════════════════════════╝{C.X}
""")

if __name__ == "__main__":
    # Check for root/sudo (needed for SYN scan)
    if os.geteuid() != 0:
        print(f"\n  {C.Y}⚠ Warning: Running without root privileges.{C.X}")
        print(f"  {C.Y}  Nmap SYN scan (-sS) and OS detection (-O) require root.{C.X}")
        print(f"  {C.Y}  Run with: sudo python3 {sys.argv[0]} {' '.join(sys.argv[1:])}{C.X}\n")
    main()
