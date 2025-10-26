#!/usr/bin/env python3
"""
local_attack.py
Safe local attack surface snapshot generator.

- defaults to scannin only localhost (127.0.0.1).
- enumerates open TCP ports (configurable range), attempts to show listening socket info (netstat/ss),
  lists running processes (psutil if available), and lists installed Python packages
- generates a markdown report to stdout (so you can redirect to a file).

notes to self - possibly tidy, abit long and hard to read abit

usage examples:
    python local_attack.py > report.md
    python local_attack.py --start-port 1 --end-port 1024 > report.md
    python local_attack.py --host 127.0.0.1 --allow-remote --start-port 1 --end-port 1024
"""

from __future__ import annotations
import argparse
import socket
import sys
import platform
import subprocess
import datetime
import json
import shutil
from typing import List, Dict, Optional

# optional dependency
try:
    import psutil
except Exception:
    psutil = None

# safety stuff
DEFAULT_HOST = "127.0.0.1"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_TIMEOUT = 0.15  # seconds per port (adjust for speed/accuracy tradeoff (possibly chanhge))

# common ports
COMMON_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    139: "NetBIOS-SSN",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "Postgres",
    27017: "MongoDB",
    6379: "Redis",
    5985: "WinRM-HTTP",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Local attack surface snapshot (safe-by-default)."
    )
    p.add_argument("--host", "-H", default=DEFAULT_HOST,
                   help=f"Target host to scan (default {DEFAULT_HOST}). Must be localhost unless --allow-remote is set.")
    p.add_argument("--allow-remote", action="store_true",
                   help="Allow non-localhost targets. Use ONLY on hosts you own or have permission to test.")
    p.add_argument("--start-port", type=int, default=DEFAULT_START_PORT,
                   help=f"Start port for TCP scan (default {DEFAULT_START_PORT}).")
    p.add_argument("--end-port", type=int, default=DEFAULT_END_PORT,
                   help=f"End port for TCP scan (default {DEFAULT_END_PORT}).")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"Per-port socket timeout in seconds (default {DEFAULT_TIMEOUT}). Lower is faster but less reliable.")
    p.add_argument("--no-system-listening", action="store_true",
                   help="Skip capturing system listening sockets (netstat/ss) output.")
    p.add_argument("--include-pip", action="store_true",
                   help="Attempt to include installed Python packages via pip freeze.")
    return p.parse_args()


def safety_check(host: str, allow_remote: bool) -> None:
    if host not in ALLOWED_HOSTS and not allow_remote:
        print("ERROR: Tool is safe-by-default and only scans localhost (127.0.0.1).")
        print("If you are sure you own the target and understand the risks, re-run with --allow-remote.")
        sys.exit(2)


def scan_ports(host: str, start: int, end: int, timeout: float) -> List[int]:

    #basic tcp
    #returnns
    
    open_ports: List[int] = []
    # iterate
    for port in range(start, end + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, port))
                if res == 0:
                    open_ports.append(port)
        except KeyboardInterrupt:
            raise
        except Exception:
            continue
    return open_ports


def capture_system_listening() -> Optional[str]:
    #compatibility checkj
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL)
            return out
        else:
            # prefer ss, fallback to netstat
            if shutil.which("ss"):
                try:
                    out = subprocess.check_output(["ss", "-lntp"], text=True, stderr=subprocess.DEVNULL)
                    return out
                except Exception:
                    pass
            if shutil.which("netstat"):
                out = subprocess.check_output(["netstat", "-tlnp"], text=True, stderr=subprocess.DEVNULL)
                return out
    except Exception:
        return None
    return None


def get_process_list(sample_limit: int = 50):

    #returns a list describin runnin processes

    if psutil:
        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "exe", "username"]):
            try:
                info = p.info
                procs.append(info)
            except Exception:
                continue
        # sort small to large pid for determinism and truncate
        procs = sorted(procs, key=lambda x: x.get("pid", 0))[:sample_limit]
        return procs
    else:
        # fallback: give some tasklist/ps output context
        try:
            if platform.system() == "Windows" and shutil.which("tasklist"):
                out = subprocess.check_output(["tasklist", "/FO", "CSV"], text=True)
                return {"tasklist_head": out.splitlines()[:sample_limit]}
            elif shutil.which("ps"):
                out = subprocess.check_output(["ps", "-eo", "pid,comm,args"], text=True)
                return {"ps_head": out.splitlines()[:sample_limit]}
        except Exception:
            return {"note": "psutil not installed and system utilities unavailable."}
    return {"note": "unknown"}


def get_python_packages() -> List[str]:
    # packages stuff
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True, stderr=subprocess.DEVNULL)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def risk_flags_for_ports(open_ports: List[int]) -> List[str]:
    flags: List[str] = []
    if 3389 in open_ports:
        flags.append("RDP (3389) open - high risk if externally reachable.")
    for p in (22, 445, 3306, 5432):
        if p in open_ports:
            flags.append(f"{COMMON_PORTS.get(p, str(p))} ({p}) open - review access control & config.")
    return flags


def format_markdown_report(
    host: str,
    start_port: int,
    end_port: int,
    open_ports: List[int],
    listening_raw: Optional[str],
    procs,
    pkgs: List[str],
    ) -> str:

    now = datetime.datetime.utcnow().isoformat() + "Z"
    hostname = platform.node()
    osinfo = f"{platform.system()} {platform.release()} ({platform.machine()})"

    report_lines: List[str] = []
    report_lines.append(f"# Local Attack Surface Snapshot\n")
    report_lines.append(f"**Generated:** {now}\n")
    report_lines.append(f"**Target:** `{host}`  \n**Host:** `{hostname}`  \n**OS:** {osinfo}\n")
    report_lines.append("## Summary\n")

    flags = risk_flags_for_ports(open_ports)
    if flags:
        report_lines.append("**Potential issues detected:**\n")
        for f in flags:
            report_lines.append(f"- {f}\n")
    else:
        report_lines.append("No obvious high-risk services detected on localhost (quick scan)\n")

    report_lines.append("\n## Open ports (TCP)\n")
    if open_ports:
        report_lines.append("| Port | Service | Note |\n|---:|---|---|\n")
        for p in sorted(open_ports):
            svc = COMMON_PORTS.get(p, "")
            note = "Common" if p in COMMON_PORTS else ""
            report_lines.append(f"| {p} | {svc} | {note} |\n")
    else:
        report_lines.append("No open TCP ports detected by quick connect scan.\n")

    report_lines.append(f"\n(Scanned ports {start_port}-{end_port} with timeout per-port)\n")

    report_lines.append("\n## Listening sockets (system output, truncated)\n")
    if listening_raw:
        report_lines.append("```\n")
        lr_lines = listening_raw.splitlines()
        report_lines.extend(lr_lines[:60])
        report_lines.append("\n```\n")
    else:
        report_lines.append("Could not retrieve system listening sockets output (permission/tool missing).\n")

    report_lines.append("\n## Running processes (sample)\n")
    report_lines.append("```\n")
    try:
        report_lines.append(json.dumps(procs[:50], indent=2) + "\n")
    except Exception:
        report_lines.append(str(procs) + "\n")
    report_lines.append("```\n")

    report_lines.append("\n## Python packages (top 40)\n")
    if pkgs:
        report_lines.append("```\n")
        for p in pkgs[:40]:
            report_lines.append(p + "\n")
        report_lines.append("```\n")
    else:
        report_lines.append("No Python packages found / pip not available or skipped.\n")

    report_lines.append("\n## Suggested remediation / next steps\n")
    report_lines.append("- If a port corresponds to an unexpected service, investigate the owning process and disable or reconfigure the service if unnecessary.\n")
    report_lines.append("- Ensure exposed services are protected by authentication and firewall rules where appropriate.\n")
    report_lines.append("- Keep software updated and consider automatic updates for critical packages.\n")
    report_lines.append("- For further triage, run targeted tools against specific services (e.g., curl, ssh -v, database clients) or use forensic process inspection tools.\n")

    return "\n".join(report_lines)


def main():
    args = parse_args()
    safety_check(args.host, args.allow_remote)

    # sanity checks on port range
    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        print("Invalid port range. Ports must be 1-65535 and start <= end.")
        sys.exit(3)

    # catch system listening output
    listening_raw = None
    if not args.no_system_listening:
        listening_raw = capture_system_listening()

    # tcp connect scan
    print(f"Scanning {args.host} ports {args.start_port}-{args.end_port} (timeout {args.timeout}s) ...", file=sys.stderr)
    open_ports = scan_ports(args.host, args.start_port, args.end_port, args.timeout)

    # processes & packages
    procs = get_process_list()
    pkgs = get_python_packages() if args.include_pip else []

    # generate markdown
    md = format_markdown_report(
        host=args.host,
        start_port=args.start_port,
        end_port=args.end_port,
        open_ports=open_ports,
        listening_raw=listening_raw,
        procs=procs,
        pkgs=pkgs,
    )

    # print to stdout (so can redirect
    print(md)


if __name__ == "__main__":
    main()
