#!/usr/bin/env python3
"""Decide a case from its evidence, by fixed conservative rules, and apply the decision as a label.

  python tools/decide.py --evidence case/evidence.json --issue 12 [--three-reports] [--apply]

Precision is absolute: a false listing is worse than a missed one, so every listing rule needs page evidence
(a credential or card form, or a form posting elsewhere) AND a domain or brand indicator, from a page the runner
actually reached. A popular site is never host-listed; a shared host or a shortener is never host-listed. A
mistaken-listing request is unlisted only when the fetched page is clean and the domain is old. Anything else is
"needs-another-look", and the daily sweep closes such a case without listing after seven days."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

PAGE_FLAGS = {"password_field", "card_field", "form_posts_elsewhere"}
LEXICAL = {"brand_in_wrong_place", "digit_lookalike", "punycode_host"}
HOSTING = {"shared_hosting", "shortener"}
RULES = {
    "a": "already listed by the bundle or the own files",
    "b": "mistaken-listing request: the fetched page is clean and the domain is old",
    "c": "address with three independent reports",
    "d": "the runner did not reach a page, so nothing is listed",
    "e": "page evidence (a credential or card form, or a form posting elsewhere) plus a domain or brand indicator",
    "f": "a whole domain that exists for the scam: fresh, brand look-alike, with page evidence",
    "g": "no decisive evidence",
}


def decide(case: dict, three_reports: bool = False) -> tuple[str, str, str]:
    """(label, rule letter, reason)."""
    inds = {i["name"]: i for i in case.get("indicators", [])}
    kind = case.get("kind")
    cls = case.get("class")
    status = (case.get("fetch") or {}).get("status")
    age = inds.get("domain_age_days", {}).get("value")
    page = any(n in inds for n in PAGE_FLAGS)
    lexical = any(n in inds for n in LEXICAL)
    hosting = any(n in inds for n in HOSTING)
    popular = "popular_host" in inds
    young60 = age is not None and age < 60
    young30 = age is not None and age < 30
    brand_in_registrable = "in the registrable domain" in str(inds.get("brand_in_wrong_place", {}).get("value", ""))

    if case.get("already"):
        return "already", "a", RULES["a"]
    if kind == "m":
        clean = status == 200 and not page and not lexical and age is not None and age >= 180
        if clean:
            return "unlist", "b", RULES["b"]
        why = "page not reached" if status != 200 else "page shows a credential or card form" if page else "a brand or look-alike indicator" if lexical else "the domain is under 180 days old or its age is unknown"
        return "needs-another-look", "g", f"mistaken-listing request not unlisted: {why}"
    if cls == "address":
        if three_reports and kind == "s":
            return "list:address", "c", RULES["c"]
        return "needs-another-look", "g", "an address is listed only with three independent reports"
    if cls not in ("url", "host"):
        return "needs-another-look", "g", "not a URL, host, or address"
    if status != 200:
        return "needs-another-look", "d", RULES["d"]
    if kind not in ("s", "o"):
        return "needs-another-look", "g", "a misread or wrong-details report is not a listing"
    list_url = page and (lexical or young60 or hosting) and (not popular or lexical)
    if not list_url:
        missing = "no credential or card form on the page" if not page else "no domain or brand indicator beside the page evidence" if not (lexical or young60 or hosting) else "popular site without a brand indicator"
        return "needs-another-look", "g", f"{RULES['g']}: {missing}"
    whole_domain = (not popular and not hosting and young30 and (brand_in_registrable or "digit_lookalike" in inds or "punycode_host" in inds))
    if whole_domain:
        return "list:host", "f", RULES["f"]
    return "list:url", "e", RULES["e"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--issue", required=True)
    ap.add_argument("--three-reports", action="store_true")
    ap.add_argument("--apply", action="store_true", help="add the label and a comment through gh (otherwise print only)")
    args = ap.parse_args()
    with open(args.evidence, encoding="utf-8") as f:
        case = json.load(f)
    label, rule, reason = decide(case, args.three_reports)
    print(f"{label} (rule {rule}): {reason}")
    if args.apply:
        subprocess.run(["gh", "issue", "comment", args.issue, "--body", f"Decided by rule {rule}: {reason}. Label `{label}`."], check=True)
        subprocess.run(["gh", "issue", "edit", args.issue, "--add-label", label], check=True)
        if label.startswith("list:") or label in ("unlist", "not-a-phish", "already"):
            subprocess.run(["gh", "workflow", "run", "label.yml", "-f", f"issue={args.issue}", "-f", f"label={label}"], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
