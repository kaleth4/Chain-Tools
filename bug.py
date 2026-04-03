#!/usr/bin/env python3
"""
Bug Bounty Recon Automation (Authorized Use Only)

Automates reconnaissance + enumeration for bug bounty scopes using:
  - whois
  - nmap
  - recon-ng

Exports all results to a .txt report for rapid triage.

Requirements:
  - whois CLI
  - nmap CLI
  - recon-ng CLI

Usage:
  python3 bugbounty_recon.py --target example.com --output report.txt
"""

import argparse
import datetime
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_command(command, timeout=300):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"[!] Timeout after {timeout}s", 124


def run_whois(target):
    stdout, stderr, code = run_command(["whois", target], timeout=60)
    return {
        "tool": "whois",
        "command": f"whois {target}",
        "stdout": stdout,
        "stderr": stderr,
        "code": code,
    }


def run_nmap(target):
    # Fast, reliable: SYN scan, service + version detection, top 1000 ports
    cmd = ["nmap", "-sS", "-sV", "-Pn", "--top-ports", "1000", "-T4", target]
    stdout, stderr, code = run_command(cmd, timeout=900)
    return {
        "tool": "nmap",
        "command": " ".join(cmd),
        "stdout": stdout,
        "stderr": stderr,
        "code": code,
    }


def run_reconng(target):
    # Run recon-ng in a temporary workspace using a resource script
    workspace = f"bb_recon_{target.replace('.', '_')}"
    resource_script = f"""
    workspaces create {workspace}
    modules load recon/domains-hosts/google_site_web
    options set SOURCE {target}
    run
    modules load recon/domains-hosts/bing_domain_web
    options set SOURCE {target}
    run
    modules load recon/domains-hosts/brute_hosts
    options set SOURCE {target}
    run
    modules load recon/hosts-hosts/resolve
    options set SOURCE {target}
    run
    show hosts
    show domains
    show contacts
    show credentials
    exit
    """

    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(resource_script)
        tmp_path = tmp.name

    stdout, stderr, code = run_command(["recon-ng", "-r", tmp_path], timeout=1200)
    os.unlink(tmp_path)
    return {
        "tool": "recon-ng",
        "command": f"recon-ng -r {tmp_path}",
        "stdout": stdout,
        "stderr": stderr,
        "code": code,
    }


def format_block(title, result):
    line = "=" * 80
    block = [line, f"{title}", line]
    block.append(f"Command: {result['command']}")
    block.append(f"Exit Code: {result['code']}")
    block.append("
[STDOUT]
")
    block.append(result["stdout"] or "<empty>")
    if result["stderr"]:
        block.append("
[STDERR]
")
        block.append(result["stderr"])
    block.append("
")
    return "
".join(block)


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Recon Automation")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--output", default="recon_report.txt", help="Output report file")
    args = parser.parse_args()

    target = args.target.strip()
    output = Path(args.output)

    for tool in ("whois", "nmap", "recon-ng"):
        if not command_exists(tool):
            print(f"[!] Missing required tool: {tool}")
            sys.exit(1)

    start = datetime.datetime.utcnow()
    print(f"[*] Starting recon for {target} at {start} UTC")

    results = []
    results.append(run_whois(target))
    results.append(run_nmap(target))
    results.append(run_reconng(target))

    end = datetime.datetime.utcnow()
    duration = end - start

    header = [
        "BUG BOUNTY RECON REPORT",
        f"Target: {target}",
        f"Start: {start} UTC",
        f"End: {end} UTC",
        f"Duration: {duration}",
        "
",
    ]

    report = "
".join(header)
    for result in results:
        report += format_block(result["tool"].upper(), result)

    output.write_text(report, encoding="utf-8")
    print(f"[+] Report written to {output.resolve()}")


if __name__ == "__main__":
    main()
