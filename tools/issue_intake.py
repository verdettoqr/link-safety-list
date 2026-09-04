#!/usr/bin/env python3
"""Turn a report issue into a case (report-issue.yml runs this). A connector such as Power Automate or Zapier opens an
issue in this repository for every form response, with a body of `key: value` lines:

    kind: s            (s scam-looking, r misread, d wrong details, o other, m listed by mistake; or the category text)
    content: <the scanned text>
    found: <where the code was found>
    warnings: <warnings the app showed>
    versions: <app, list, and phone>
    report_id: <the response timestamp>

The script dispatches the case workflow with those fields and closes the report issue with a note. Only issues opened
by the repository owner's connector are handled (the workflow checks the author), so nobody else can drive the
pipeline by opening issues. The email cell must never be put in the issue; the connector template does not carry it."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

KINDS = {
    "A link, Wi-Fi network, payment address, or phone number that looks like a scam": "s",
    "The app read a code wrong, or could not read it": "r",
    "Product, book, medicine, or other details were wrong": "d",
    "Something else: a mistake in the app, a translation, a suggestion": "o",
    "My site or link is listed by mistake": "m",
}
FIELDS = ("kind", "content", "found", "warnings", "versions", "report_id")


def parse(body: str) -> dict:
    out: dict[str, str] = {}
    for line in body.splitlines():
        m = re.match(r"^\s*(kind|content|found|warnings|versions|report_id)\s*:\s*(.*)$", line, re.I)
        if m and m.group(1).lower() not in out:
            out[m.group(1).lower()] = m.group(2).strip()
    k = out.get("kind", "")
    out["kind"] = k if k in ("s", "r", "d", "o", "m") else KINDS.get(k, "o")
    out["report_id"] = re.sub(r"[^A-Za-z0-9]+", "-", out.get("report_id", "")).strip("-") or "issue"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--issue", required=True)
    args = ap.parse_args()
    data = json.loads(subprocess.run(["gh", "issue", "view", args.issue, "--json", "body,title"], check=True, capture_output=True, text=True).stdout)
    p = parse(data.get("body") or "")
    content = p.get("content", "")[:1500]
    if not content and p["kind"] in ("r", "d", "o"):
        subprocess.run(["gh", "issue", "comment", args.issue, "--body", "Feedback without scanned content: kept for the digest, no case opened."], check=True)
        subprocess.run(["gh", "issue", "close", args.issue, "--reason", "completed"], check=True)
        print("feedback, no case")
        return 0
    subprocess.run(["gh", "workflow", "run", "case.yml", "-f", f"kind={p['kind']}", "-f", f"content={content}", "-f", f"found={p.get('found', '')[:300]}",
                    "-f", f"warnings={p.get('warnings', '')[:300]}", "-f", f"versions={p.get('versions', '')[:200]}", "-f", f"report_id={p['report_id']}"], check=True)
    subprocess.run(["gh", "issue", "comment", args.issue, "--body", f"Case workflow dispatched for report-{p['report_id']}; the case issue follows within a minute."], check=True)
    subprocess.run(["gh", "issue", "close", args.issue, "--reason", "completed"], check=True)
    print("dispatched", p["report_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
