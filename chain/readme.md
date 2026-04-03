 CLI Arguments
Flag	Default	Description
-t, --target	Required	Target domain (e.g., example.com)
-o, --output	<target>_recon.txt	Output report filename
-p, --ports	1-10000	Port range for Nmap
--speed	4	Nmap timing template (T1-T5)
--threads	50	Subdomain bruteforce threads
--fast	off	Quick scan: top ports, T5 speed
--all	off	Full scan: 65535 ports, 100 threads
--skip-whois	off	Skip WHOIS lookup
--skip-nmap	off	Skip Nmap scan
--skip-reconng	off	Skip Recon-ng / OSINT
--skip-dns	off	Skip DNS enumeration
--skip-http	off	Skip HTTP header analysis
--skip-subs	off	Skip subdomain enumeration
-v, --verbose	off	Verbose output


Install Python Dependencies
pip3 install python-nmap python-whois dnspython requests

💡 The script will auto-install missing packages on first run.

3
Download & Run
# Download the script (or use the button above)

chmod +x bughunter_recon.py

# Basic scan

sudo python3 bughunter_recon.py -t target.com

# Fast scan (top ports, T5 speed)

sudo python3 bughunter_recon.py -t target.com --fast

# Full scan (all 65535 ports)

sudo python3 bughunter_recon.py -t target.com --all

# Custom output file

sudo python3 bughunter_recon.py -t target.com -o my_report.txt

# Skip specific modules

sudo python3 bughunter_recon.py -t target.com --skip-nmap --skip-reconng

# Custom port range with high threads

sudo python3 bughunter_recon.py -t target.com -p 1-65535 --threads 100

4
Review Results
# View the report

cat target_com_recon.txt

# Search for vulnerabilities

grep -i "vuln\|critical\|high" target_com_recon.txt

# Extract subdomains only

grep -A 1000 "SUBDOMAINS" target_com_recon.txt | head -100

💡 Pro Tips for Bug Bounty
Speed First
Use --fast for initial recon, then --all on interesting targets. Time is money in bug bounties.

Chain Tools
Feed subdomains into tools like httpx, nuclei, and ffuf for deeper testing.

Check Wayback URLs
The script flags sensitive URLs from Wayback Machine — these are goldmines for finding exposed configs.

Missing Security Headers
CORS misconfigs, missing CSP, and absent HSTS are quick wins for reports.

Subdomain Takeover
Check subdomains resolving to NXDOMAIN or pointing to unclaimed cloud resources.

Run as Root
SYN scan (-sS) and OS detection (-O) require root/sudo. Without it, Nmap falls back to TCP connect scan.
