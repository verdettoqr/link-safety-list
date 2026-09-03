#!/usr/bin/env python3
"""Compile the open phishing and malware URL feeds into one small list a phone can check offline.

Sources (each can be switched off with --skip):
  phishtank  PhishTank's verified, online phishes (JSON). An application key raises the download limit.
  openphish  OpenPhish community feed (one URL per line).
  urlhaus    abuse.ch URLhaus, online malware URLs (one URL per line, CC0).

Every URL is normalized exactly as the app normalizes a scanned link, hashed with SHA-256, and the first
8 bytes kept. The output is a sorted, de-duplicated array of those prefixes (list.bin), a manifest
(list.json) with counts, the bin's SHA-256 and the source outcomes, and an Ed25519 signature (list.sig)
when a signing key is present. The phone binary-searches the array: no false positives from a filter,
and nothing readable about which addresses are listed.

Usage:  python build_list.py --out dist [--skip phishtank] [--min-entries 1000]
Env:    PHISHTANK_APP_KEY   optional; PhishTank's higher download limit
        PHISHTANK_UA        User-Agent for PhishTank (they ask for a descriptive one), default phishtank/link-safety-list
        LIST_SIGNING_KEY    optional; base64 of the 32-byte Ed25519 private key
"""
from __future__ import annotations

import argparse
import base64
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
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAGIC = b"LSL1"
PREFIX_BYTES = 8
TIMEOUT = 60
UA = "link-safety-list/1.0 (+https://github.com/verdettoqr/link-safety-list)"

SOURCES = {
    "phishtank": {"url": "http://data.phishtank.com/data/{key}online-valid.json.gz", "terms": "https://www.phishtank.com/developer_info.php"},
    "openphish": {"url": "https://openphish.com/feed.txt", "terms": "https://openphish.com/terms.html"},
    "urlhaus": {"url": "https://urlhaus.abuse.ch/downloads/text_online/", "terms": "https://urlhaus.abuse.ch/api/#tos (CC0)"},
}


def normalize(url: str) -> str | None:
    """The app's rule, mirrored: scheme and host lowercased, explicit port kept, path '/' when empty,
    query kept, fragment dropped. Returns None for anything that is not an http(s) address."""
    u = url.strip()
    if not u or " " in u:
        return None
    try:
        p = urlsplit(u)
    except ValueError:
        return None
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower()
    port = f":{p.port}" if p.port and p.port not in (80 if scheme == "http" else 443,) else ""
    # Android's Uri keeps an explicit default port; mirror that: keep any explicit port as written.
    if p.port:
        port = f":{p.port}"
    path = p.path or "/"
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def prefix(normalized: str) -> bytes:
    return hashlib.sha256(normalized.encode("utf-8")).digest()[:PREFIX_BYTES]


def fetch(url: str, ua: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = r.read()
        if r.headers.get("Content-Encoding") == "gzip" or url.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError):
                pass
        return data


def read_phishtank(data: bytes) -> list[str]:
    rows = json.loads(data.decode("utf-8"))
    return [r["url"] for r in rows if r.get("verified") == "yes" and r.get("online") == "yes" and r.get("url")]


def read_lines(data: bytes) -> list[str]:
    out = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def env(name: str, default: str = "") -> str:
    """An unset secret reaches a GitHub Actions step as an empty string, not as a missing variable:
    treat empty as absent, or the PhishTank request goes out with an empty User-Agent and gets HTTP 403."""
    return os.environ.get(name, "").strip() or default


def collect(skip: set[str]) -> tuple[set[bytes], dict]:
    prefixes: set[bytes] = set()
    report: dict = {}
    key = env("PHISHTANK_APP_KEY")
    for name, src in SOURCES.items():
        if name in skip:
            report[name] = {"fetched": False, "count": 0, "error": "skipped"}
            continue
        url = src["url"].format(key=f"{key}/" if key else "") if name == "phishtank" else src["url"]
        ua = env("PHISHTANK_UA", "phishtank/link-safety-list") if name == "phishtank" else UA
        t0 = time.time()
        try:
            data = fetch(url, ua)
            urls = read_phishtank(data) if name == "phishtank" else read_lines(data)
            added = 0
            for u in urls:
                n = normalize(u)
                if n:
                    prefixes.add(prefix(n))
                    added += 1
            report[name] = {"fetched": True, "count": added, "seconds": round(time.time() - t0, 1)}
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, json.JSONDecodeError, TimeoutError, OSError) as e:
            report[name] = {"fetched": False, "count": 0, "error": f"{type(e).__name__}: {str(e)[:160]}"}
    return prefixes, report


def write_bin(path: str, url_prefixes: list[bytes], host_prefixes: list[bytes], generated_at: int) -> bytes:
    body = io.BytesIO()
    body.write(MAGIC)
    body.write(struct.pack("<IQII", 1, generated_at, len(url_prefixes), len(host_prefixes)))
    for p in url_prefixes:
        body.write(p)
    for p in host_prefixes:
        body.write(p)
    data = body.getvalue()
    with open(path, "wb") as f:
        f.write(data)
    return data


def sign(data: bytes) -> tuple[str | None, str | None]:
    raw = env("LIST_SIGNING_KEY")
    if not raw:
        return None, None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private.sign(data)).decode("ascii"), public.hex()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="dist")
    ap.add_argument("--skip", action="append", default=[], choices=sorted(SOURCES))
    ap.add_argument("--min-entries", type=int, default=1000, help="refuse to publish a list smaller than this")
    args = ap.parse_args()

    prefixes, report = collect(set(args.skip))
    fetched = [n for n, r in report.items() if r["fetched"]]
    if not fetched:
        print("no source could be fetched; nothing published", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 2
    if len(prefixes) < args.min_entries:
        print(f"only {len(prefixes)} entries, below --min-entries {args.min_entries}; nothing published", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 3

    os.makedirs(args.out, exist_ok=True)
    generated_at = int(time.time())
    url_prefixes = sorted(prefixes)
    data = write_bin(os.path.join(args.out, "list.bin"), url_prefixes, [], generated_at)
    signature, public_key = sign(data)
    manifest = {
        "format": MAGIC.decode("ascii"),
        "version": generated_at,
        "generated_at": datetime.fromtimestamp(generated_at, timezone.utc).isoformat(),
        "url_count": len(url_prefixes),
        "host_count": 0,
        "prefix_bytes": PREFIX_BYTES,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature": signature,
        "public_key": public_key,
        "sources": report,
        "normalization": "scheme and host lowercased, explicit port kept, path '/' when empty, query kept, fragment dropped",
    }
    with open(os.path.join(args.out, "list.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(args.out, "list.sig"), "w", encoding="ascii") as f:
        f.write((signature or "") + "\n")
    print(json.dumps({k: v for k, v in manifest.items() if k != "sources"}, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
