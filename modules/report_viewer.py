"""
report_viewer.py — Browse and view saved JSON reports in the terminal
"""

import json
import os
from modules.display import C, divider, ok, warn, info, section
from modules.reporter import list_reports, load_report


def view_reports():
    section("SAVED REPORTS")
    reports = list_reports()

    if not reports:
        warn("No reports found. Run a scan first.")
        return

    print(f"  {C.GREEN}Found {len(reports)} report(s):{C.RESET}\n")
    for i, path in enumerate(reports, 1):
        fname = os.path.basename(path)
        size  = os.path.getsize(path)
        mtime = os.path.getmtime(path)
        import datetime
        dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        print(f"  {C.CYAN}[{i}]{C.RESET}  {C.WHITE}{fname:<55}{C.RESET}{C.GRAY}{dt}  {size}B{C.RESET}")

    print(f"\n  {C.CYAN}[0]{C.RESET}  Back to menu\n")
    choice = input(f"  {C.CYAN}Select report to view:{C.RESET} ").strip()

    if choice == "0" or not choice:
        return

    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(reports):
            warn("Invalid selection.")
            return
        data = load_report(reports[idx])
    except (ValueError, FileNotFoundError):
        warn("Could not load report.")
        return

    divider("REPORT CONTENTS")
    ok("Tool",      data.get("tool", "?"))
    ok("Target",    data.get("target", "?"))
    ok("Timestamp", data.get("timestamp", "?"))
    print()
    print(json.dumps(data.get("results", {}), indent=4))
    print()
