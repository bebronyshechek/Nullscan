"""
reporter.py — Save and load scan results as JSON reports
"""

import json
import os
from datetime import datetime

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")

def save_report(tool_name: str, target: str, data: dict) -> str:
    """Save a report to output/ and return the file path."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
    filename = f"{tool_name}_{safe_target}_{timestamp}.json"
    path = os.path.join(REPORT_DIR, filename)

    report = {
        "tool":      tool_name,
        "target":    target,
        "timestamp": datetime.now().isoformat(),
        "results":   data
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return path

def list_reports() -> list:
    """Return list of saved report file paths sorted by date (newest first)."""
    if not os.path.isdir(REPORT_DIR):
        return []
    files = [
        os.path.join(REPORT_DIR, f)
        for f in os.listdir(REPORT_DIR)
        if f.endswith(".json")
    ]
    return sorted(files, key=os.path.getmtime, reverse=True)

def load_report(path: str) -> dict:
    """Load a saved JSON report."""
    with open(path) as f:
        return json.load(f)
