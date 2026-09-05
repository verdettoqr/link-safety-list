#!/usr/bin/env python3
"""Build a case from one report: canonicalize, check what we already list, compute the indicators, fetch the page
from this runner, and write the case as Markdown plus a JSON evidence file. Automation gathers; a person decides.

  python tools/case.py --payload payload.json --out case      # payload: the report's fields (see PAYLOAD_KEYS)

Nothing here lists anything. The case's proposed entry is a line a person turns into an own-file entry by labelling
the case issue (see .github/workflows/label.yml)."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from build_list import ADDRESS_PREFIX, HOST_PREFIX, URL_PREFIX, normalize, normalize_address, normalize_host, prefix  # noqa: E402
from verify import listed, load_bin, psl_registrable  # noqa: E402

RELEASE = "https://github.com/verdettoqr/link-safety-list/releases/download/current"
PAYLOAD_KEYS = ("kind", "content", "found", "warnings", "versions", "report_id", "reported_at", "email_given")
KINDS = {"s": "scam-looking link, network, address, or number", "r": "the app read a code wrong", "d": "details were wrong",
         "o": "something else", "m": "listed by mistake (review request)"}
BROWSER_UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Mobile Safari/537.36"
TIMEOUT = 20
MAX_HOPS = 8
MAX_BYTES = 2_000_000
PATH_WORDS = ("login", "signin", "sign-in", "verify", "verification", "account", "update", "secure", "wallet", "claim",
              "invoice", "parcel", "delivery", "unlock", "suspend", "confirm", "password", "billing", "payment", "prize")
HOSTING = ("sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "github.io", "pages.dev", "netlify.app",
           "vercel.app", "weebly.com", "wixsite.com", "webflow.io", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app",
           "trycloudflare.com", "notion.site", "carrd.co", "blogspot.com", "wordpress.com", "000webhostapp.com",
           "firebaseapp.com", "web.app", "ipfs.io", "r2.dev", "workers.dev", "surge.sh", "duckdns.org", "no-ip.org")
DIGIT_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})


def fetch_bytes(url: str, ua: str = BROWSER_UA, accept: str = "*/*") -> tuple[int, dict, bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept": accept, "Accept-Language": "en-US,en;q=0.8"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.status, dict(r.headers), r.read(MAX_BYTES), r.geturl()


def get_json(url: str, ua: str = "link-safety-list-case/1.0 (+https://verdettoqr.com)"):
    status, headers, body, _ = fetch_bytes(url, ua, "application/json")
    return json.loads(body.decode("utf-8", errors="replace"))


def rdap_registration(domain: str) -> dict:
    """Registration date and the abuse contact from the registry's RDAP record, through the rdap.org bootstrap."""
    try:
        data = get_json(f"https://rdap.org/domain/{domain}")
    except Exception as e:  # noqa: BLE001 - any failure is just a missing indicator
        return {"error": f"{type(e).__name__}: {str(e)[:100]}"}
    out: dict = {}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            out["registered"] = ev["eventDate"][:10]
    for ent in data.get("entities", []):
        if "abuse" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1] or []:
                if item and item[0] == "email":
                    out["abuse_email"] = item[3]
    return out


def crtsh_first_certificate(domain: str) -> dict:
    try:
        rows = get_json(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json")
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {str(e)[:100]}"}
    dates = sorted(r.get("not_before", "")[:10] for r in rows if r.get("not_before"))
    return {"first_certificate": dates[0], "certificates": len(rows)} if dates else {"certificates": 0}


def days_since(iso_day: str | None, today: datetime) -> int | None:
    if not iso_day:
        return None
    try:
        return (today.date() - datetime.strptime(iso_day, "%Y-%m-%d").date()).days
    except ValueError:
        return None


class PageScan(HTMLParser):
    """What a fetched page contains that matters: a title, password or card fields, forms posting elsewhere."""

    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self.password_fields = 0
        self.card_fields = 0
        self.form_actions: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "input":
            t = (a.get("type") or "").lower()
            name = ((a.get("name") or "") + " " + (a.get("autocomplete") or "") + " " + (a.get("id") or "")).lower()
            if t == "password":
                self.password_fields += 1
            if "cc-" in name or "card" in name or "cvv" in name or "cvc" in name:
                self.card_fields += 1
        elif tag == "form":
            self.form_actions.append(a.get("action") or "")
        elif tag == "script":
            self.scripts += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def public_host(host: str) -> bool:
    """True when every address the host resolves to is a public one. A literal or resolved private, loopback,
    link-local, multicast or reserved address is refused, so a report does not make the runner fetch its own
    network or a cloud metadata service (169.254.169.254) and publish the answer in a case. The name is resolved
    here and again by urlopen, so a host that changes its answer between the two (DNS rebinding) is not caught;
    the runner holds nothing of ours, and a pinned-address fetch is filed as the closing step."""
    if not host:
        return False
    try:
        addresses = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except (socket.gaierror, UnicodeError, ValueError):
            return False
    return bool(addresses) and all(a.is_global and not a.is_multicast for a in addresses)


def fetch_chain(url: str) -> dict:
    """Follow redirects by hand so the chain is recorded; keep the final page's bytes. Every hop is checked with
    public_host before it is fetched."""
    chain = []
    current = url
    for _ in range(MAX_HOPS):
        host = urllib.parse.urlsplit(current).hostname or ""
        if not public_host(host):
            chain.append({"url": current, "error": "not a public address; not fetched"})
            return {"chain": chain, "final_url": current, "status": None, "body": b"", "error": "not a public address"}
        req = urllib.request.Request(current, headers={"User-Agent": BROWSER_UA, "Accept": "text/html,*/*;q=0.8"})
        opener = urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                status, body, ctype = r.status, r.read(MAX_BYTES), r.headers.get("Content-Type", "")
                chain.append({"url": current, "status": status})
                return {"chain": chain, "final_url": current, "status": status, "content_type": ctype, "body": body}
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            chain.append({"url": current, "status": e.code})
            if e.code in (301, 302, 303, 307, 308) and loc:
                current = urllib.parse.urljoin(current, loc)
                continue
            body = e.read(MAX_BYTES) if e.fp else b""
            return {"chain": chain, "final_url": current, "status": e.code, "content_type": e.headers.get("Content-Type", ""), "body": body}
        except Exception as e:  # noqa: BLE001
            chain.append({"url": current, "error": f"{type(e).__name__}: {str(e)[:120]}"})
            return {"chain": chain, "final_url": current, "status": None, "body": b""}
    return {"chain": chain, "final_url": current, "status": None, "body": b"", "error": "too many redirects"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_release_assets(out_dir: str) -> dict:
    """The current bundle and the reference lists, so the case is checked against what phones have."""
    assets: dict = {}
    try:
        _, _, data, _ = fetch_bytes(f"{RELEASE}/list.bin")
        path = os.path.join(out_dir, "list.bin")
        with open(path, "wb") as f:
            f.write(data)
        assets["bin"] = load_bin(path)[1]   # [urls, hosts, addresses], sorted prefixes
        for name in ("psl", "brands", "shorteners"):
            _, _, gz, _ = fetch_bytes(f"{RELEASE}/{name}.txt.gz")
            assets[name] = gzip.decompress(gz).decode("utf-8").splitlines()
    except Exception as e:  # noqa: BLE001
        assets["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    return assets


def psl_sets(lines: list[str]):
    rules, wildcards, exceptions = set(), set(), set()
    for l in lines:
        if l.startswith("!"):
            exceptions.add(l[1:])
        elif l.startswith("*."):
            wildcards.add(l[2:])
        elif l:
            rules.add(l)
    return rules, wildcards, exceptions


def own_lookup(entry: str) -> list[str]:
    """Which own files already carry this exact entry (plain text, before hashing)."""
    hits = []
    own = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "own")
    for name in ("urls.txt", "hosts.txt", "addresses.txt", "allow.txt"):
        path = os.path.join(own, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.split("#")[0].strip() == entry:
                        hits.append(name)
    return hits


def brand_tokens(brands: list[str], top: int = 3000) -> dict[str, str]:
    """Brand name -> its domain, from the top of the list: paypal -> paypal.com. Short and generic names left out."""
    out: dict[str, str] = {}
    generic = {"google", "apple", "amazon", "live", "mail", "news", "cloud", "shop", "online", "store", "bank", "home", "free",
               "accounts", "secure", "portal", "support", "service", "services", "static", "media", "images", "email", "search",
               "world", "group", "global", "official", "mobile", "business", "network", "digital", "internet", "download"}
    for d in brands[:top]:
        labels = d.split(".")
        name = labels[0]
        if len(labels) > 2 and len(labels[1]) >= 5:   # login.microsoftonline.com: the brand is the registrable name
            name = labels[1]
        if len(name) >= 5 and name not in generic and name not in PATH_WORDS and name not in out:
            out[name] = d
    return out


def indicators_for(canonical: str, host: str, registrable: str, assets: dict, today: datetime) -> list[dict]:
    """Each indicator is a fact in one line. They are shown, not summed."""
    found: list[dict] = []
    parsed = urllib.parse.urlsplit(canonical)
    labels = host.split(".")
    reg_name = registrable.split(".")[0]

    rdap = rdap_registration(registrable) if registrable and not host.replace(".", "").isdigit() else {}
    age = days_since(rdap.get("registered"), today)
    if age is not None:
        found.append({"name": "domain_age_days", "value": age, "line": f"Domain registered {rdap['registered']} ({age} days ago)", "flag": age < 30})
    crt = crtsh_first_certificate(registrable) if registrable else {}
    cert_age = days_since(crt.get("first_certificate"), today)
    if cert_age is not None:
        found.append({"name": "certificate_age_days", "value": cert_age, "line": f"First certificate {crt['first_certificate']} ({cert_age} days ago), {crt.get('certificates')} certificates logged", "flag": cert_age < 7})

    brands = brand_tokens(assets.get("brands", [])) if assets.get("brands") else {}
    where = []
    for name, domain in brands.items():
        if registrable == domain or registrable.endswith("." + domain):
            continue
        if name in reg_name:
            where.append(f"{name} in the registrable domain ({registrable}, not {domain})")
        elif any(name in l for l in labels[:-len(registrable.split('.'))] if labels):
            where.append(f"{name} in a subdomain of {registrable}, not {domain}")
        elif name in parsed.path.lower():
            where.append(f"{name} in the path on {registrable}, not {domain}")
    for w in where[:3]:
        found.append({"name": "brand_in_wrong_place", "value": w, "line": "Brand in the wrong place: " + w, "flag": True})

    if any(l.startswith("xn--") for l in labels):
        found.append({"name": "punycode_host", "value": host, "line": f"Punycode host: {host}", "flag": True})
    swapped = reg_name.translate(DIGIT_LOOKALIKE)
    if swapped != reg_name and swapped in brands:
        found.append({"name": "digit_lookalike", "value": swapped, "line": f"Digits for letters: {reg_name} reads as {swapped} ({brands[swapped]})", "flag": True})
    words = [w for w in PATH_WORDS if w in parsed.path.lower() or w in (parsed.query or "").lower()]
    if words:
        found.append({"name": "path_vocabulary", "value": words, "line": "Path words: " + ", ".join(words), "flag": len(words) >= 2})
    if any(host == h or host.endswith("." + h) for h in HOSTING):
        found.append({"name": "shared_hosting", "value": host, "line": f"Hosted on a shared platform ({host}): list the full URL, never the host", "flag": True})
    if host in set(assets.get("shorteners", [])):
        found.append({"name": "shortener", "value": host, "line": f"Shortener host ({host}): the destination is what matters", "flag": True})
    if parsed.scheme == "http":
        found.append({"name": "plain_http", "value": True, "line": "Plain http, no encryption", "flag": True})
    popular = set(assets.get("brands", []))
    if registrable and registrable in popular:
        found.append({"name": "popular_host", "value": registrable, "line": f"Popular site ({registrable}): only an exact URL with strong page evidence is ever listed, never the host", "flag": False})
    if len(labels) - len(registrable.split(".")) >= 3:
        found.append({"name": "deep_subdomains", "value": len(labels), "line": f"{len(labels)} labels in the host", "flag": False})
    if rdap.get("abuse_email"):
        found.append({"name": "abuse_contact", "value": rdap["abuse_email"], "line": f"Registrar abuse contact: {rdap['abuse_email']}", "flag": False})
    return found


def page_indicators(fetch: dict) -> list[dict]:
    out: list[dict] = []
    body = fetch.get("body") or b""
    if fetch.get("status") is None:
        out.append({"name": "fetch_failed", "value": fetch.get("chain", [])[-1:], "line": "The page could not be fetched from the runner (down, geo-fenced, or blocking)", "flag": False})
        return out
    if len(fetch.get("chain", [])) > 1:
        out.append({"name": "redirects", "value": [c.get("url") for c in fetch["chain"]], "line": f"{len(fetch['chain']) - 1} redirect(s), landing on {fetch['final_url']}", "flag": False})
    if b"<" in body[:2000]:
        scan = PageScan()
        try:
            scan.feed(body.decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            pass
        if scan.title.strip():
            out.append({"name": "title", "value": scan.title.strip()[:120], "line": f"Title: {scan.title.strip()[:120]}", "flag": False})
        if scan.password_fields:
            out.append({"name": "password_field", "value": scan.password_fields, "line": f"{scan.password_fields} password field(s) on the page", "flag": True})
        if scan.card_fields:
            out.append({"name": "card_field", "value": scan.card_fields, "line": f"{scan.card_fields} card or CVV field(s) on the page", "flag": True})
        final_host = urllib.parse.urlsplit(fetch["final_url"]).hostname or ""
        elsewhere = [a for a in scan.form_actions if a.startswith("http") and (urllib.parse.urlsplit(a).hostname or "") != final_host]
        if elsewhere:
            out.append({"name": "form_posts_elsewhere", "value": elsewhere[:3], "line": "A form posts to another host: " + ", ".join(elsewhere[:3]), "flag": True})
    out.append({"name": "page_sha256", "value": hashlib.sha256(body).hexdigest(), "line": f"Page {len(body)} bytes, sha256 {hashlib.sha256(body).hexdigest()[:16]}…", "flag": False})
    return out


def upstream_drafts(canonical: str, registrable: str, abuse_email: str | None) -> dict:
    enc = urllib.parse.quote(canonical, safe="")
    return {
        "google_phishing_report": f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={enc}",
        "phishtank_submit": "https://phishtank.org/add_web_phish.php",
        "abuse_mail_to": abuse_email or f"abuse@{registrable}" if registrable else "",
        "abuse_mail_body": (f"Hello, the page at {canonical} is a phishing or scam page (evidence attached: the case at "
                            f"github.com/verdettoqr/link-safety-list). Please take it down. Thank you. Verdetto, support@verdettoqr.com"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True, help="JSON file with the report fields")
    ap.add_argument("--out", default="case")
    args = ap.parse_args()
    with open(args.payload, encoding="utf-8") as f:
        p = json.load(f)
    p = {k: (str(p.get(k, "")) if p.get(k) is not None else "") for k in PAYLOAD_KEYS}
    os.makedirs(args.out, exist_ok=True)
    today = datetime.now(timezone.utc)
    content = p["content"].strip()

    canonical = normalize(content) if "://" in content else None
    cls = "url" if canonical else None
    host = registrable = ""
    if not canonical:
        h = normalize_host(content)
        a = normalize_address(content)
        if a and not h:
            canonical, cls = a, "address"
        elif h:
            canonical, cls = h, "host"
    if not canonical:
        case = {"key": hashlib.sha256(content.encode()).hexdigest()[:12], "class": None, "kind": p["kind"], "content": content[:500],
                "note": "Not a URL, host, or address: nothing to list; handled by the app's rules or as feedback"}
        json.dump(case, open(os.path.join(args.out, "evidence.json"), "w", encoding="utf-8"), indent=2)
        with open(os.path.join(args.out, "case.md"), "w", encoding="utf-8") as f:
            f.write(f"## Case {case['key']}\n\nKind: {KINDS.get(p['kind'], p['kind'])}\n\n{case['note']}\n\n```\n{content[:500]}\n```\n")
        print(case["key"])
        return 0

    key = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    assets = load_release_assets(args.out)
    if cls == "url":
        host = urllib.parse.urlsplit(canonical).hostname or ""
    elif cls == "host":
        host = canonical
    if host and "psl" in assets:
        registrable = psl_registrable(host, *psl_sets(assets["psl"]))
    elif host:
        registrable = ".".join(host.split(".")[-2:])

    already: list[str] = []
    if "bin" in assets:
        urls_arr, hosts_arr, addr_arr = assets["bin"][0], assets["bin"][1], assets["bin"][2]
        if cls == "url" and listed(urls_arr, prefix(canonical, URL_PREFIX)):
            already.append("bundle: exact URL")
        if host:
            labels = host.split(".")
            for i in range(len(labels)):
                parent = ".".join(labels[i:])
                if listed(hosts_arr, prefix(parent, HOST_PREFIX)):
                    already.append(f"bundle: host {parent}")
                    break
        if cls == "address" and listed(addr_arr, prefix(canonical, ADDRESS_PREFIX)):
            already.append("bundle: address")
    already += [f"own/{n}" for n in own_lookup(canonical)]

    inds: list[dict] = []
    fetch: dict = {}
    if cls in ("url", "host"):
        inds = indicators_for(canonical if cls == "url" else f"https://{host}/", host, registrable, assets, today)
        fetch = fetch_chain(canonical if cls == "url" else f"https://{host}/")
        inds += page_indicators(fetch)
        if fetch.get("body"):
            with open(os.path.join(args.out, "page.html"), "wb") as f:
                f.write(fetch["body"])
    flags = [i for i in inds if i.get("flag")]
    abuse = next((i["value"] for i in inds if i["name"] == "abuse_contact"), None)
    shared = any(i["name"] in ("shared_hosting", "shortener") for i in inds)
    proposed_class = "url" if cls == "url" and (shared or registrable in ("", host) or True) else cls
    if cls == "url" and not shared and registrable and any(i["name"] in ("brand_in_wrong_place", "digit_lookalike", "punycode_host") for i in inds) and (next((i["value"] for i in inds if i["name"] == "domain_age_days"), 999) < 30):
        proposed_class = "host"
    proposed_entry = canonical if proposed_class != "host" else registrable
    evidence_line = "; ".join(i["line"] for i in flags)[:300] or "no indicator flagged; review the page"
    case = {
        "key": key, "class": cls, "kind": p["kind"], "kind_text": KINDS.get(p["kind"], p["kind"]), "canonical": canonical, "host": host,
        "registrable": registrable, "already": already, "indicators": inds, "flag_count": len(flags),
        "fetch": {k: v for k, v in fetch.items() if k != "body"}, "proposed": {"class": proposed_class, "entry": proposed_entry, "evidence": evidence_line},
        "upstream": upstream_drafts(canonical if cls == "url" else f"https://{host}/", registrable, abuse) if cls != "address" else {},
        "report": {k: p[k] for k in ("found", "warnings", "versions", "report_id", "reported_at", "email_given")},
        "built_at": today.isoformat(timespec="seconds"), "assets_error": assets.get("error"),
    }
    with open(os.path.join(args.out, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, ensure_ascii=False)

    lines = [f"## Case {key}", "", f"Report id: report-{p['report_id'] or 'manual'}. Kind: {case['kind_text']}. Class: {cls}. Reported {p['reported_at'] or 'now'}"
             + (f", from the app ({p['versions']})" if p["versions"] else "") + (f". Found: {p['found']}" if p["found"] else "") + ".", "",
             f"Canonical: `{canonical}`" + (f"  (host `{host}`, registrable `{registrable}`)" if host else ""), ""]
    if p["warnings"]:
        lines += [f"The app showed: {p['warnings']}", ""]
    lines += ["### Already listed", "", ("- " + "\n- ".join(already)) if already else "Not in the current bundle or the own files.", ""]
    lines += ["### Indicators (facts, not a score)", ""]
    lines += [("- **" if i.get("flag") else "- ") + i["line"] + ("**" if i.get("flag") else "") for i in inds] or ["- none computed"]
    lines += ["", f"{len(flags)} flagged.", ""]
    if fetch.get("chain"):
        lines += ["### Fetch from the runner", "", "```", *[f"{c.get('status', c.get('error'))}  {c.get('url')}" for c in fetch["chain"]], "```", ""]
    lines += ["### Proposed entry (a label applies it; nothing is listed until then)", "", "```",
              f"ENTRY: {proposed_class} {proposed_entry}  # {today.date().isoformat()} case-{key} {evidence_line}", "```", "",
              "Labels: `list:url`, `list:host`, `list:address` to list the proposed entry as that class; `unlist` to add it to own/allow.txt; "
              "`not-a-phish`, `already`, or `needs-another-look` to close or hold.", ""]
    if case["upstream"]:
        u = case["upstream"]
        lines += ["### Upstream reports (drafts; sent by the operator)", "", f"- Google: {u['google_phishing_report']}", f"- PhishTank: {u['phishtank_submit']}",
                  f"- Abuse mail to {u['abuse_mail_to'] or 'the host'}: {u['abuse_mail_body']}", ""]
    with open(os.path.join(args.out, "case.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
