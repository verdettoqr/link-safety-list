#!/usr/bin/env python3
"""Turn new rows of the report form into cases. The responses sheet publishes one tab as CSV (timestamp, category,
scanned text, where found, warnings shown, versions; never the description or the email); its address is the
FORM_FEED_URL secret. Each row becomes a report id from its timestamp; a row whose id already appears in a case is
skipped; the rest are dispatched to the case workflow.

  python tools/intake.py            # FORM_FEED_URL in the environment; needs gh"""
from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import sys
import urllib.request

KINDS = {
    "A link, Wi-Fi network, payment address, or phone number that looks like a scam": "s",
    "The app read a code wrong, or could not read it": "r",
    "Product, book, medicine, or other details were wrong": "d",
    "Something else: a mistake in the app, a translation, a suggestion": "o",
    "My site or link is listed by mistake": "m",
}


def report_id(stamp: str) -> str:
    return "report-" + re.sub(r"[^A-Za-z0-9]+", "-", stamp.strip()).strip("-")


def existing(rid: str) -> bool:
    out = subprocess.run(["gh", "issue", "list", "--state", "all", "--search", f"{rid} in:body", "--json", "number", "--jq", "length"],
                         check=True, capture_output=True, text=True).stdout.strip()
    return out not in ("", "0")


def main() -> int:
    url = os.environ.get("FORM_FEED_URL", "").strip()
    if not url:
        print("FORM_FEED_URL is not set; nothing to read", file=sys.stderr)
        return 0
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "link-safety-list-intake/1.0"}), timeout=60) as r:
        text = r.read().decode("utf-8-sig", errors="replace")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        print("empty feed")
        return 0
    header = [h.strip() for h in rows[0]]
    dispatched = skipped = feedback = 0
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        cells = dict(zip(header, [c.strip() for c in row]))
        stamp = row[0].strip()
        rid = report_id(stamp)
        kind = KINDS.get(cells.get("What are you reporting?", ""), "o")
        content = next((v for k, v in cells.items() if k.startswith("What was scanned")), "")[:1500]
        if not content and kind in ("r", "d", "o"):
            feedback += 1
            continue
        if existing(rid):
            skipped += 1
            continue
        found = next((v for k, v in cells.items() if k.startswith("Where did you find")), "")[:300]
        warnings = next((v for k, v in cells.items() if k.startswith("Warnings the app showed")), "")[:300]
        versions = next((v for k, v in cells.items() if k.startswith("App version") or k.startswith("App, list")), "")[:200]
        subprocess.run(["gh", "workflow", "run", "case.yml", "-f", f"kind={kind}", "-f", f"content={content}", "-f", f"found={found}",
                        "-f", f"warnings={warnings}", "-f", f"versions={versions}", "-f", f"report_id={rid[len('report-'):]}"], check=True)
        dispatched += 1
    print(f"rows {len(rows) - 1}: dispatched {dispatched}, already cased {skipped}, feedback without content {feedback}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
