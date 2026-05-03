"""
display.py — Colors, banners, output helpers for NullScan
"""

import os
import sys

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDER   = "\033[4m"
    RESET   = "\033[0m"

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    clear()
    print(f"""
{C.CYAN}{C.BOLD}
███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║██║   ██║██║     ██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██║   ██║██║     ██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║╚██████╔╝███████╗███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.GRAY}         NullScan v1.0  |  by durachok  |  Authorized use only{C.RESET}
""")

def menu():
    print(f"""{C.BOLD}{C.WHITE}
  ╔══════════════════════════════════════════╗
  ║              NULLSCAN  TOOLS               ║
  ╠══════════════════════════════════════════╣
  ║  {C.CYAN}[1]{C.WHITE}  IP Lookup & Geolocation           ║
  ║  {C.CYAN}[2]{C.WHITE}  Subdomain Enumerator              ║
  ║  {C.CYAN}[3]{C.WHITE}  Port Scanner                      ║
  ║  {C.CYAN}[4]{C.WHITE}  WHOIS + DNS Recon                 ║
  ║  {C.CYAN}[5]{C.WHITE}  HTTP Header Analyzer              ║
  ║  {C.CYAN}[6]{C.WHITE}  Reverse IP Lookup                 ║
  ║  {C.CYAN}[7]{C.WHITE}  Full Auto Recon  {C.YELLOW}[runs 1+3+4+5]{C.WHITE}   ║
  ╠══════════════════════════════════════════╣
  ║  {C.GRAY}[8]{C.WHITE}  View Saved Reports                ║
  ║  {C.RED}[0]{C.WHITE}  Exit                              ║
  ╚══════════════════════════════════════════╝{C.RESET}
""")

def divider(title="", width=52):
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{C.CYAN}{'─'*pad} {C.BOLD}{title}{C.RESET}{C.CYAN} {'─'*pad}{C.RESET}")
    else:
        print(f"{C.GRAY}{'─'*width}{C.RESET}")

def ok(label, value, label_w=24):
    print(f"  {C.GREEN}✔{C.RESET}  {C.WHITE}{label:<{label_w}}{C.RESET}{C.YELLOW}{value}{C.RESET}")

def flag(label, value, label_w=24):
    """Red flag — for suspicious/dangerous findings."""
    print(f"  {C.RED}⚑{C.RESET}  {C.WHITE}{label:<{label_w}}{C.RESET}{C.RED}{value}{C.RESET}")

def warn(msg):
    print(f"  {C.RED}✖{C.RESET}  {C.GRAY}{msg}{C.RESET}")

def info(msg):
    print(f"  {C.BLUE}➜{C.RESET}  {msg}")

def success(msg):
    print(f"  {C.GREEN}✔{C.RESET}  {C.GREEN}{msg}{C.RESET}")

def progress(current, total, label="Progress"):
    sys.stdout.write(f"\r  {C.GRAY}{label}: {current}/{total}{C.RESET}   ")
    sys.stdout.flush()

def section(title):
    divider(title)
    print()
