#!/usr/bin/env python3
"""Compile open safety data into a small bundle a phone can check offline.

Blocklist sources, each switchable with --skip:
  phishtank    PhishTank's verified, online phishes (full URLs). An application key raises the download limit.
  urlhaus      abuse.ch URLhaus, online malware URLs (full URLs, CC0).
  threatfox    abuse.ch ThreatFox, recent malware and botnet URLs (full URLs).
  certpl       CERT Polska's warning list of dangerous domains (hosts; an entry covers its subdomains).
  scamsniffer  ScamSniffer's crypto-scam domains (hosts) and scam wallet addresses.

Reference data, always built:
  psl          Mozilla's Public Suffix List (MPL 2.0), so the phone computes registrable domains correctly.
  shorteners   URL shortener hosts (PeterDaveHello/url-shorteners).
  confusables  Unicode confusables, kept to the mappings whose target is ASCII, for lookalike detection.
  brands       The top 10,000 domains from the Tranco list, for "popular site" notes and lookalike targets.

Output (in --out): list.bin (LSL2: sorted SHA-256 prefixes for URLs, hosts, addresses), psl.txt.gz,
shorteners.txt.gz, confusables.txt.gz, brands.txt.gz, list.json (the manifest: every asset's SHA-256
and size, the source outcomes, the Ed25519 signature over the manifest when LIST_SIGNING_KEY is set),
and list.sig (the same signature).

Env: PHISHTANK_APP_KEY, PHISHTANK_UA (default phishtank/link-safety-list), ABUSECH_AUTH_KEY, LIST_SIGNING_KEY (base64, 32 bytes).
"""
from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAGIC = b"LSL2"
URL_PREFIX = 8      # exact-address entries; about 1e5 of them, collision odds about 1e-14 per lookup
HOST_PREFIX = 6     # domain entries; about 5e5 of them, collision odds about 2e-9 per lookup
ADDRESS_PREFIX = 8
TIMEOUT = 90
UA = "link-safety-list/2.0 (+https://github.com/verdettoqr/link-safety-list)"
BRANDS_TOP = 10_000

BLOCKLISTS = {
    "phishtank": "http://data.phishtank.com/data/{key}online-valid.json.gz",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "threatfox": "https://threatfox.abuse.ch/export/csv/urls/recent/",
    "certpl": "https://hole.cert.pl/domains/v2/domains.txt",
    "scamsniffer": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
}
SCAMSNIFFER_ADDRESSES = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
REFERENCE = {
    "psl": "https://publicsuffix.org/list/public_suffix_list.dat",
    "shorteners": "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list",
    "confusables": "https://www.unicode.org/Public/security/latest/confusables.txt",
    "brands": "https://downloads.majestic.com/majestic_million.csv",
}


def env(name: str, default: str = "") -> str:
    """An unset secret reaches a GitHub Actions step as an empty string, not as a missing variable:
    treat empty as absent, or the PhishTank request goes out with an empty User-Agent and gets HTTP 403."""
    return os.environ.get(name, "").strip() or default


# ---------------------------------------------------------------- normalization, mirrored by the app

def normalize(url: str) -> str | None:
    """Scheme and host lowercased, explicit port kept, path '/' when empty, query kept, fragment dropped.
    None for anything that is not an http(s) address."""
    u = url.strip()
    if not u or " " in u:
        return None
    try:
        p = urlsplit(u)
    except ValueError:
        return None
    scheme = (p.scheme or "").lower()
    try:
        hostname, port = p.hostname, p.port
    except ValueError:
        return None
    if scheme not in ("http", "https") or not hostname:
        return None
    host = hostname.lower()
    port_text = f":{port}" if port else ""
    path = p.path or "/"
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{host}{port_text}{path}{query}"


def normalize_host(host: str) -> str | None:
    """A bare domain, lowercased, without a trailing dot, scheme, path, or port."""
    h = host.strip().lower().rstrip(".")
    if h.startswith("http://") or h.startswith("https://"):
        h = urlsplit(h).hostname or ""
    h = h.split("/")[0].split(":")[0]
    if not h or " " in h or "." not in h:
        return None
    return h


def normalize_address(addr: str) -> str | None:
    """A wallet address as the phone will hash it: trimmed; EVM addresses lowercased (they are case-insensitive hex)."""
    a = addr.strip()
    if not a or " " in a:
        return None
    if a.startswith("0x") and len(a) == 42:
        a = a.lower()
    return a


def prefix(text: str, width: int) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()[:width]


# ---------------------------------------------------------------- fetching and parsing

def auth_headers(name: str) -> dict:
    """abuse.ch requires an Auth-Key since 2025-06-30; URLhaus and ThreatFox get it when the secret is set."""
    key = env("ABUSECH_AUTH_KEY")
    return {"Auth-Key": key} if key and name in ("urlhaus", "threatfox") else {}


def fetch(url: str, ua: str = UA, headers: dict | None = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "gzip", **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read()
        if r.headers.get("Content-Encoding") == "gzip" or url.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError):
                pass
        return data


def read_lines(data: bytes) -> list[str]:
    return [s for s in (line.strip() for line in data.decode("utf-8", errors="replace").splitlines()) if s and not s.startswith("#")]


def read_phishtank(data: bytes) -> list[str]:
    return [r["url"] for r in json.loads(data.decode("utf-8")) if r.get("verified") == "yes" and r.get("online") == "yes" and r.get("url")]


def read_threatfox(data: bytes) -> list[str]:
    out = []
    for row in csv.reader(io.StringIO(data.decode("utf-8", errors="replace")), skipinitialspace=True):
        if len(row) >= 4 and not row[0].startswith("#") and row[3].strip() == "url":
            out.append(row[2].strip().strip('"'))
    return out


def read_json_list(data: bytes) -> list[str]:
    return [str(r) for r in json.loads(data.decode("utf-8")) if isinstance(r, str)]


def collect(skip: set[str]) -> tuple[set[bytes], set[bytes], set[bytes], dict]:
    urls: set[bytes] = set()
    hosts: set[bytes] = set()
    addresses: set[bytes] = set()
    report: dict = {}
    key = env("PHISHTANK_APP_KEY")

    def run(name: str, url: str, ua: str, parse, add) -> None:
        t0 = time.time()
        try:
            items = parse(fetch(url, ua, auth_headers(name)))
            added = sum(1 for item in items if add(item))
            report[name] = {"fetched": True, "count": added, "seconds": int(round(time.time() - t0))}
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError) as e:
            report[name] = {"fetched": False, "count": 0, "error": f"{type(e).__name__}: {str(e)[:160]}"}

    def add_url(u: str) -> bool:
        n = normalize(u)
        if n:
            urls.add(prefix(n, URL_PREFIX))
        return bool(n)

    def add_host(h: str) -> bool:
        n = normalize_host(h)
        if n:
            hosts.add(prefix(n, HOST_PREFIX))
        return bool(n)

    def add_address(a: str) -> bool:
        n = normalize_address(a)
        if n:
            addresses.add(prefix(n, ADDRESS_PREFIX))
        return bool(n)

    for name, url in BLOCKLISTS.items():
        if name in skip:
            report[name] = {"fetched": False, "count": 0, "error": "skipped"}
            continue
        if name == "phishtank":
            run(name, url.format(key=f"{key}/" if key else ""), env("PHISHTANK_UA", "phishtank/link-safety-list"), read_phishtank, add_url)
        elif name == "threatfox":
            run(name, url, UA, read_threatfox, add_url)
        elif name == "certpl":
            run(name, url, UA, read_lines, add_host)
        elif name == "scamsniffer":
            run(name, url, UA, read_json_list, add_host)
            run("scamsniffer_addresses", SCAMSNIFFER_ADDRESSES, UA, read_json_list, add_address)
        else:
            run(name, url, UA, read_lines, add_url)
    return urls, hosts, addresses, report


# ---------------------------------------------------------------- reference assets

def build_psl(data: bytes) -> str:
    """The rules only: comments and blank lines dropped; the private section kept (github.io and kin depend on it)."""
    rules = [l for l in (line.strip() for line in data.decode("utf-8").splitlines()) if l and not l.startswith("//")]
    return "\n".join(rules) + "\n"


def build_shorteners(data: bytes) -> str:
    return "\n".join(sorted({h for h in (normalize_host(l) for l in read_lines(data)) if h})) + "\n"


def build_confusables(data: bytes) -> str:
    """source-codepoint<TAB>target, kept when the target is ASCII letters, digits, or hyphen (the characters a
    domain lookalike can imitate); the phone maps each character of a lowercased host through this table."""
    out = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 2:
            continue
        try:
            src = chr(int(parts[0], 16))
            target = "".join(chr(int(cp, 16)) for cp in parts[1].split())
        except ValueError:
            continue
        if target and src != target and all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c == "-" for c in target):
            out.append(f"{ord(src):04X}\t{target.lower()}")
    return "\n".join(out) + "\n"


def build_brands(data: bytes) -> str:
    """The top domains: Majestic Million CSV (CC BY 3.0; a header row, the domain in the column named Domain),
    or a Tranco-style zip of rank,domain rows. The first BRANDS_TOP registrable hosts, in rank order."""
    if data[:2] == b"PK":
        zf = zipfile.ZipFile(io.BytesIO(data))
        rows = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace").splitlines()
        col = 1
    else:
        rows = data.decode("utf-8", errors="replace").splitlines()
        header = [h.strip().lower() for h in rows[0].split(",")] if rows else []
        if "domain" not in header:
            raise ValueError("brands: no Domain column")
        col = header.index("domain")
        rows = rows[1:]
    domains: list[str] = []
    for row in rows:
        parts = row.split(",")
        if len(parts) > col:
            h = normalize_host(parts[col])
            if h:
                domains.append(h)
        if len(domains) >= BRANDS_TOP:
            break
    return "\n".join(domains) + "\n"


RELEASE = "https://github.com/verdettoqr/link-safety-list/releases/download/current"
PSL_MAX_AGE = 24 * 3600


def previous_psl(now: int) -> tuple[bytes, int] | None:
    """The PSL asset of the current release with its fetch time, when that fetch is under a day old
    (publicsuffix.org asks for at most one download per day; this workflow runs four times a day)."""
    try:
        manifest = json.loads(fetch(f"{RELEASE}/list.json").decode("utf-8"))
        fetched_at = int(manifest.get("psl_fetched_at", 0))
        if fetched_at <= 0 or now - fetched_at >= PSL_MAX_AGE:
            return None
        data = gzip.decompress(fetch(f"{RELEASE}/psl.txt.gz"))
        expected = manifest["assets"]["psl.txt.gz"]["sha256"]
        if hashlib.sha256(gzip.compress(data, mtime=0)).hexdigest() != expected:
            return None
        return data, fetched_at
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError, OSError, TimeoutError):
        return None


def build_reference(report: dict) -> dict[str, bytes]:
    builders = {"psl": build_psl, "shorteners": build_shorteners, "confusables": build_confusables, "brands": build_brands}
    out: dict[str, bytes] = {}
    now = int(time.time())
    for name, url in REFERENCE.items():
        t0 = time.time()
        if name == "psl":
            kept = previous_psl(now)
            if kept is not None:
                out[name] = kept[0]
                report[name] = {"fetched": True, "count": kept[0].count(b"\n"), "seconds": 0, "reused_from": kept[1]}
                report["psl_fetched_at"] = kept[1]
                continue
            report["psl_fetched_at"] = now
        try:
            text = builders[name](fetch(url))
            out[name] = text.encode("utf-8")
            report[name] = {"fetched": True, "count": text.count("\n"), "seconds": int(round(time.time() - t0))}
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError, OSError, zipfile.BadZipFile, KeyError) as e:
            report[name] = {"fetched": False, "count": 0, "error": f"{type(e).__name__}: {str(e)[:160]}"}
    return out


# ---------------------------------------------------------------- output

def write_bin(path: str, urls: list[bytes], hosts: list[bytes], addresses: list[bytes], generated_at: int) -> bytes:
    body = io.BytesIO()
    body.write(MAGIC)
    body.write(struct.pack("<IQ", 2, generated_at))
    for width, entries in ((URL_PREFIX, urls), (HOST_PREFIX, hosts), (ADDRESS_PREFIX, addresses)):
        body.write(struct.pack("<IB3x", len(entries), width))
    for entries in (urls, hosts, addresses):
        for p in entries:
            body.write(p)
    data = body.getvalue()
    with open(path, "wb") as f:
        f.write(data)
    return data


def canonical(manifest: dict) -> bytes:
    """The bytes that are signed: the manifest without its signature fields, keys sorted, no spaces."""
    m = {k: v for k, v in manifest.items() if k not in ("signature", "public_key")}
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(data: bytes) -> tuple[str | None, str | None]:
    raw = env("LIST_SIGNING_KEY")
    if not raw:
        return None, None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private.sign(data)).decode("ascii"), public.hex()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="dist")
    ap.add_argument("--skip", action="append", default=[], choices=sorted(BLOCKLISTS))
    ap.add_argument("--min-entries", type=int, default=1000, help="refuse to publish with fewer URL entries than this")
    args = ap.parse_args()

    urls, hosts, addresses, report = collect(set(args.skip))
    if not any(r["fetched"] for n, r in report.items() if n in BLOCKLISTS):
        print("no blocklist source could be fetched; nothing published", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 2
    if len(urls) < args.min_entries:
        print(f"only {len(urls)} URL entries, below --min-entries {args.min_entries}; nothing published", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 3
    reference = build_reference(report)
    if "psl" not in reference:
        print("the Public Suffix List could not be built; nothing published", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 4

    os.makedirs(args.out, exist_ok=True)
    generated_at = int(time.time())
    data = write_bin(os.path.join(args.out, "list.bin"), sorted(urls), sorted(hosts), sorted(addresses), generated_at)
    assets = {"list.bin": {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "url_count": len(urls), "host_count": len(hosts), "address_count": len(addresses)}}
    for name, text in reference.items():
        fname = f"{name}.txt.gz"
        gz = gzip.compress(text, mtime=0)
        with open(os.path.join(args.out, fname), "wb") as f:
            f.write(gz)
        assets[fname] = {"sha256": hashlib.sha256(gz).hexdigest(), "bytes": len(gz), "lines": text.count(b"\n")}

    manifest = {
        "format": MAGIC.decode("ascii"),
        "version": generated_at,
        "generated_at": datetime.fromtimestamp(generated_at, timezone.utc).isoformat(),
        "prefix_bytes": {"url": URL_PREFIX, "host": HOST_PREFIX, "address": ADDRESS_PREFIX},
        "assets": assets,
        "sources": {k: v for k, v in report.items() if k != "psl_fetched_at"},
        "psl_fetched_at": int(report.get("psl_fetched_at", 0)),
        "normalization": {
            "url": "scheme and host lowercased, explicit port kept, path '/' when empty, query kept, fragment dropped",
            "host": "lowercased, no trailing dot; the phone checks the host and each parent domain down to the registrable domain",
            "address": "trimmed; 0x EVM addresses lowercased",
        },
    }
    signature, public_key = sign(canonical(manifest))
    manifest["signature"] = signature
    manifest["public_key"] = public_key
    with open(os.path.join(args.out, "list.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(args.out, "list.sig"), "w", encoding="ascii") as f:
        f.write((signature or "") + "\n")
    print(json.dumps({k: v for k, v in manifest.items() if k not in ("sources", "normalization")}, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
