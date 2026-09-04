#!/usr/bin/env python3
"""Compile open safety data into a small bundle a phone can check offline.

Blocklist sources, each switchable with --skip:
  phishtank    PhishTank's verified, online phishes (full URLs). An application key raises the download limit.
  certpl       CERT Polska's warning list of dangerous domains (hosts; an entry covers its subdomains).
  phishdestroy PhishDestroy destroylist, phishing and scam domains (MIT).
  phishindex   PhishIndex own malicious domains (MIT).
  polkadot     polkadot-js phishing deny list (hosts) and scam addresses (Apache-2.0).
  ofac         OFAC SDN list, sanctioned digital-currency addresses (US government work, public domain).

Reference data, always built:
  psl          Mozilla's Public Suffix List (MPL 2.0), so the phone computes registrable domains correctly.
  shorteners   URL shortener hosts (PeterDaveHello/url-shorteners).
  confusables  Unicode confusables, kept to the mappings whose target is ASCII, for lookalike detection.
  brands       The top 10,000 domains from the Majestic Million (CC BY 3.0), for "popular site" notes and lookalike targets.

Output (in --out): list.bin (LSL2: sorted SHA-256 prefixes for URLs, hosts, addresses), psl.txt.gz,
shorteners.txt.gz, confusables.txt.gz, brands.txt.gz, list.json (the manifest: every asset's SHA-256
and size, the source outcomes, the Ed25519 signature over the manifest when LIST_SIGNING_KEY is set),
and list.sig (the same signature).

Env: PHISHTANK_APP_KEY, PHISHTANK_UA (default phishtank/link-safety-list), LIST_SIGNING_KEY (base64, 32 bytes).
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
import re
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
RETRY_ATTEMPTS = 3          # downloads per source before it counts as failed
RETRY_DELAY = 30.0          # seconds before the second attempt; the third waits twice as long
RETRY_STATUS = {404, 408, 425, 429, 500, 502, 503, 504}   # answers worth a retry; 403 is not one
UA = "link-safety-list/2.0 (+https://github.com/verdettoqr/link-safety-list)"
BRANDS_TOP = 10_000

BLOCKLISTS = {
    "phishtank": "http://data.phishtank.com/data/{key}online-valid.json.gz",
    "certpl": "https://hole.cert.pl/domains/v2/domains.txt",
    "phishdestroy": "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt",
    "phishindex": "https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/Malicious%20Domains/txt/phishindex_domains.txt",
    "polkadot": "https://polkadot.js.org/phishing/all.json",
    "ofac": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML",
}
POLKADOT_ADDRESSES = "https://polkadot.js.org/phishing/address.json"
REFERENCE = {
    "psl": "https://publicsuffix.org/list/public_suffix_list.dat",
    "shorteners": "https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/master/list",
    "confusables": "https://www.unicode.org/Public/security/latest/confusables.txt",
    "brands": "https://downloads.majestic.com/majestic_million.csv",
    "aviation": "https://query.wikidata.org/sparql?format=json&query=" + (
        "SELECT%20%3Fcode%20%3Fkind%20%3Fname%20%3Flinks%20WHERE%20%7B%20%7B%20%3Fitem%20wdt%3AP238%20%3Fcode%20.%20BIND(%22A%22%20AS%20%3Fkind)%20"
        "%3Fitem%20rdfs%3Alabel%20%3Fname%20.%20FILTER(LANG(%3Fname)%20%3D%20%22en%22)%20%7D%20UNION%20%7B%20%3Fitem%20wdt%3AP229%20%3Fcode%20.%20"
        "BIND(%22L%22%20AS%20%3Fkind)%20%3Fitem%20rdfs%3Alabel%20%3Fname%20.%20FILTER(LANG(%3Fname)%20%3D%20%22en%22)%20%7D%20"
        "OPTIONAL%20%7B%20%3Fitem%20wikibase%3Asitelinks%20%3Flinks%20%7D%20%7D"
    ),
    # the builder fetches the per-country files under this directory itself
    "postal": "https://download.geonames.org/export/zip/",
    "aic": "https://drive.aifa.gov.it/farmaci/confezioni_fornitura.csv",
}

# GeoNames country files kept for the postal symbologies the reader decodes: POSTNET and Intelligent Mail (US),
# RM4SCC and Mailmark (GB), KIX (NL), Japan Post (JP), CEPNET (BR), Deutsche Post Leitcode (DE), Korea Post (KR)
POSTAL_COUNTRIES = ("US", "GB", "NL", "JP", "BR", "DE", "KR")


def env(name: str, default: str = "") -> str:
    """An unset secret reaches a GitHub Actions step as an empty string, not as a missing variable:
    treat empty as absent, or the PhishTank request goes out with an empty User-Agent and gets HTTP 403."""
    return os.environ.get(name, "").strip() or default


# ---------------------------------------------------------------- normalization, mirrored by the app

_HEX = "0123456789ABCDEF"
_UNSAFE = set('"<>\\^`{|}#')


def _is_unreserved(b: int) -> bool:
    return (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (45, 46, 95, 126)


def _percent_decode_all(s: str) -> str:
    """Every %XX decoded once (the host rule); malformed escapes kept as written."""
    if "%" not in s:
        return s
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%" and i + 2 < len(s) + 0 and i + 2 <= len(s) - 1 and s[i + 1] in "0123456789abcdefABCDEF" and s[i + 2] in "0123456789abcdefABCDEF":
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        else:
            out.extend(c.encode("utf-8"))
            i += 1
    return out.decode("utf-8", errors="replace")


def _normalize_percent(s: str) -> str:
    """Unreserved escapes decoded, other escapes uppercased, disallowed characters encoded as UTF-8 escapes."""
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%":
            if i + 2 <= len(s) - 1 and s[i + 1] in "0123456789abcdefABCDEF" and s[i + 2] in "0123456789abcdefABCDEF":
                b = int(s[i + 1:i + 3], 16)
                out.append(chr(b) if _is_unreserved(b) else "%" + _HEX[b >> 4] + _HEX[b & 15])
                i += 3
            else:
                out.append("%25")
                i += 1
            continue
        cp = ord(c)
        if cp <= 0x20 or cp >= 0x7F or c in _UNSAFE:
            for b in c.encode("utf-8"):
                out.append("%" + _HEX[b >> 4] + _HEX[b & 15])
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _canonical_path(p: str) -> str:
    """'.' and '..' resolved, duplicate slashes collapsed, a trailing slash kept."""
    trailing = p.endswith("/") or p.endswith("/.") or p.endswith("/..")
    out: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    joined = "/" + "/".join(out)
    return joined + "/" if trailing and out else joined


def ipv4_canonical(h: str) -> str | None:
    """Dotted-decimal for any numeric IPv4 form (0x7f000001, 0177.0.0.1, 2130706433, 127.1); None when not numeric."""
    parts = h.split(".")
    if not parts or len(parts) > 4:
        return None
    values: list[int] = []
    for part in parts:
        if not part:
            return None
        if part[:2] in ("0x", "0X"):
            d = part[2:]
            if not d or len(d) > 8 or any(ch not in "0123456789abcdefABCDEF" for ch in d):
                return None
            values.append(int(d, 16))
        elif len(part) > 1 and part[0] == "0" and all(ch in "01234567" for ch in part):
            if len(part) > 12:
                return None
            values.append(int(part, 8))
        elif part.isdigit() and all(ch in "0123456789" for ch in part):
            if len(part) > 10:
                return None
            values.append(int(part))
        else:
            return None
    remaining = 4 - (len(values) - 1)
    if any(v > 255 for v in values[:-1]):
        return None
    if values[-1] >= (1 << (8 * remaining)):
        return None
    total = 0
    for v in values[:-1]:
        total = (total << 8) | v
    total = (total << (8 * remaining)) | values[-1]
    return ".".join(str((total >> sh) & 0xFF) for sh in (24, 16, 8, 0))


def normalize(url: str) -> str | None:
    """Canonicalization v4, the same rule as the app's UrlCanon: tabs and line breaks dropped; scheme and host
    lowercased; user info and fragment dropped; the default port dropped; host escapes decoded, dots collapsed and
    trimmed, a non-ASCII host converted to its IDNA ASCII form; a numeric IPv4 host written dotted-decimal; dot segments resolved and duplicate slashes collapsed;
    unreserved escapes decoded, other escapes uppercased; controls, spaces, non-ASCII, and unsafe characters
    percent-encoded; the query kept in order under the same escaping. None for anything that is not http(s)."""
    t = "".join(ch for ch in url.strip(" \t\n\r") if ch not in "\t\n\r")
    scheme_end = t.find("://")
    if scheme_end <= 0:
        return None
    scheme_raw = t[:scheme_end]
    if not scheme_raw.isalpha() or not scheme_raw.isascii():
        return None
    scheme = scheme_raw.lower()
    if scheme not in ("http", "https"):
        return None
    rest = t[scheme_end + 3:]
    hash_at = rest.find("#")
    if hash_at >= 0:
        rest = rest[:hash_at]
    auth_end = len(rest)
    for i, ch in enumerate(rest):
        if ch in "/?":
            auth_end = i
            break
    authority, tail = rest[:auth_end], rest[auth_end:]
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1:]
    port_text = None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host = authority[:close + 1]
        after = authority[close + 1:]
        if after.startswith(":"):
            port_text = after[1:]
        elif after:
            return None
    else:
        colon = authority.rfind(":")
        if colon >= 0:
            host, port_text = authority[:colon], authority[colon + 1:]
        else:
            host = authority
    if not host:
        return None
    port = None
    if port_text:
        if not port_text.isdigit() or not port_text.isascii() or len(port_text) > 5:
            return None
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    if host.startswith("["):
        h = host.lower()
    else:
        h = host
        for _ in range(3):
            h = _percent_decode_all(h)
        h = h.lower().strip(".")
        while ".." in h:
            h = h.replace("..", ".")
        if not h:
            return None
        if not h.isascii():
            # v4: an internationalized host is hashed in its IDNA ASCII (punycode) form, the spelling the feeds
            # store, so a QR code carrying the Unicode spelling still matches a listed phish
            try:
                h = h.encode("idna").decode("ascii")
            except UnicodeError:
                pass
        ip = ipv4_canonical(h)
        if ip is not None:
            h = ip
    path, query = tail, None
    q = path.find("?")
    if q >= 0:
        query, path = path[q + 1:], path[:q]
    if not path:
        path = "/"
    path = _canonical_path(_normalize_percent(path))
    if query is not None:
        query = _normalize_percent(query)
    port_part = f":{port}" if port else ""
    query_part = f"?{query}" if query is not None else ""
    return f"{scheme}://{h}{port_part}{path}{query_part}"


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

def fetch(url: str, ua: str = UA, headers: dict | None = None) -> bytes:
    """One download, tried up to RETRY_ATTEMPTS times.

    A source that answers 404, 408, 425, 429, or a 5xx, or does not answer at all, is tried again
    after RETRY_DELAY seconds and once more after twice that: PhishTank's hourly dump answered 404
    for a moment on 2026-09-04, it is the only URL-class source, and the build refused to publish
    (issue #4). A 403 is a credential or User-Agent problem and is raised at once."""
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "gzip", **(headers or {})})
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or url.endswith(".gz"):
                    try:
                        data = gzip.decompress(data)
                    except (OSError, EOFError):
                        pass
                return data
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS or attempt == RETRY_ATTEMPTS:
                raise
            reason = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt == RETRY_ATTEMPTS:
                raise
            reason = type(e).__name__
        delay = RETRY_DELAY * attempt
        print(f"{url}: {reason}; retrying in {int(delay)} s (attempt {attempt} of {RETRY_ATTEMPTS})", file=sys.stderr)
        time.sleep(delay)
    raise RuntimeError("unreachable")


def read_lines(data: bytes) -> list[str]:
    return [s for s in (line.strip() for line in data.decode("utf-8", errors="replace").splitlines()) if s and not s.startswith("#")]


def read_phishtank(data: bytes) -> list[str]:
    return [r["url"] for r in json.loads(data.decode("utf-8")) if r.get("verified") == "yes" and r.get("online") == "yes" and r.get("url")]


def read_polkadot_domains(data: bytes) -> list[str]:
    """polkadot-js/phishing all.json: {"allow": [...], "deny": [...]}; the deny list are the scam hosts."""
    doc = json.loads(data.decode("utf-8"))
    return [str(h) for h in doc.get("deny", [])]


def read_polkadot_addresses(data: bytes) -> list[str]:
    """polkadot-js/phishing address.json: {"site": ["address", ...], ...}; every address is a scam recipient."""
    doc = json.loads(data.decode("utf-8"))
    return [str(a) for addrs in doc.values() if isinstance(addrs, list) for a in addrs]


def read_ofac_addresses(data: bytes) -> list[str]:
    """OFAC's legacy SDN.XML (a US government work, public domain): every <id> whose <idType> starts with
    'Digital Currency Address - ' carries one sanctioned wallet address in <idNumber>. Streamed, namespace-agnostic,
    so the 30 MB file never sits in memory as a tree. The Sanctions List Service answers only requests that carry
    a User-Agent and redirects to a signed, short-lived download link, which urllib follows."""
    import xml.etree.ElementTree as ET
    out: list[str] = []
    for _event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
        tag = el.tag.rsplit("}", 1)[-1]
        if tag != "id":
            continue
        id_type = ""
        number = ""
        for child in el:
            ctag = child.tag.rsplit("}", 1)[-1]
            if ctag == "idType":
                id_type = (child.text or "").strip()
            elif ctag == "idNumber":
                number = (child.text or "").strip()
        if id_type.startswith("Digital Currency Address - ") and number:
            out.append(number)
        el.clear()
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
            items = parse(fetch(url, ua))
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
        elif name == "certpl":
            run(name, url, UA, read_lines, add_host)
        elif name in ("phishdestroy", "phishindex"):
            run(name, url, UA, read_lines, add_host)
        elif name == "polkadot":
            run(name, url, UA, read_polkadot_domains, add_host)
            run("polkadot_addresses", POLKADOT_ADDRESSES, UA, read_polkadot_addresses, add_address)
        elif name == "ofac":
            run("ofac_addresses", url, UA, read_ofac_addresses, add_address)
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


def build_aviation(data: bytes) -> str:
    """Wikidata (CC0): IATA airport codes (P238) and airline codes (P229) with English labels, one per line as
    kind<TAB>code<TAB>name, A for airports and L for airlines; the phone shows names on boarding passes."""
    doc = json.loads(data.decode("utf-8"))
    best: dict[tuple[str, str], tuple[int, str]] = {}
    for b in doc.get("results", {}).get("bindings", []):
        kind = b.get("kind", {}).get("value", "")
        code = b.get("code", {}).get("value", "").strip().upper()
        name = b.get("name", {}).get("value", "").strip()
        if kind not in ("A", "L") or not name:
            continue
        if kind == "A" and not (len(code) == 3 and code.isalpha()):
            continue
        if kind == "L" and not (len(code) == 2 and code.isalnum()):
            continue
        try:
            links = int(b.get("links", {}).get("value", "0"))
        except ValueError:
            links = 0
        # a code shared by several items (AC: Air Canada and its charter arm) goes to the best-known one,
        # measured by Wikipedia sitelinks, then the shorter name
        key = (links, -len(name))
        if (kind, code) not in best or key > best[(kind, code)][0]:
            best[(kind, code)] = (key, name)
    rows = {k: v[1] for k, v in best.items()}
    if len(rows) < 1000:
        raise ValueError(f"aviation: only {len(rows)} rows, the query service answered short")
    return "\n".join(f"{k}\t{c}\t{n}" for (k, c), n in sorted(rows.items())) + "\n"


def parse_postal_txt(country: str, text: str) -> dict[tuple[str, str], str]:
    """One GeoNames postal-code file: country, postal code, place name, admin1 name, admin1 code, admin2 name,
    admin2 code, admin3 name, admin3 code, latitude, longitude, accuracy. The first row per code wins."""
    rows: dict[tuple[str, str], str] = {}
    for line in text.split("\n"):
        f = line.split("\t")
        if len(f) < 11 or f[0] != country:
            continue
        # digits and letters only: GeoNames writes Japanese and Brazilian codes with a hyphen, the barcodes carry none
        code = re.sub("[^A-Z0-9]", "", f[1].strip().upper())
        place = f[2].strip()
        if not code or not place:
            continue
        admin1 = f[3].strip()
        try:
            lat = f"{float(f[9]):.3f}"
            lng = f"{float(f[10]):.3f}"
        except ValueError:
            lat = lng = ""
        rows.setdefault((country, code), "\t".join((place, admin1, lat, lng)))
    return rows


def build_postal(index: bytes) -> str:
    """GeoNames postal codes (CC BY 4.0), the country files named in POSTAL_COUNTRIES, one line per code as
    country<TAB>code<TAB>place<TAB>region<TAB>lat<TAB>lng; the phone names the place behind a postal barcode."""
    rows: dict[tuple[str, str], str] = {}
    base = REFERENCE["postal"]
    for cc in POSTAL_COUNTRIES:
        data = fetch(base + cc + ".zip")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            name = cc + ".txt"
            if name not in z.namelist():
                raise ValueError(f"postal: {cc}.zip carries no {name}")
            rows.update(parse_postal_txt(cc, z.read(name).decode("utf-8")))
    if len(rows) < 50000:
        raise ValueError(f"postal: only {len(rows)} rows, a country file answered short")
    return "\n".join(f"{cc}\t{code}\t{rest}" for (cc, code), rest in sorted(rows.items())) + "\n"


def build_aic(data: bytes) -> str:
    """The AIFA list of authorised medicine packs (CC BY 4.0): AIC code, name, pack, holder, and a status letter
    (A authorised, S suspended, R revoked), one line per pack; the phone names an Italian pharmacode's medicine."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("cp1252", errors="replace")
    reader = csv.DictReader(io.StringIO(text), delimiter=";")
    status_letter = {"autorizzata": "A", "sospesa": "S", "revocata": "R"}
    rows: dict[str, str] = {}
    for r in reader:
        aic = (r.get("CODICE_AIC") or "").strip()
        if len(aic) != 9 or not aic.isdigit():
            continue
        name = (r.get("DENOMINAZIONE") or "").strip()
        pack = (r.get("DESCRIZIONE") or "").strip()
        holder = (r.get("RAGIONE_SOCIALE") or "").strip()
        status = status_letter.get((r.get("STATO_AMMINISTRATIVO") or "").strip().lower(), "?")
        if not name:
            continue
        rows.setdefault(aic, "\t".join(x.replace("\t", " ") for x in (name, pack, holder, status)))
    if len(rows) < 20000:
        raise ValueError(f"aic: only {len(rows)} rows, the list answered short")
    return "\n".join(f"{aic}\t{rest}" for aic, rest in sorted(rows.items())) + "\n"


def build_reference(report: dict) -> dict[str, bytes]:
    builders = {"psl": build_psl, "shorteners": build_shorteners, "confusables": build_confusables, "brands": build_brands, "aviation": build_aviation, "postal": build_postal, "aic": build_aic}
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
            "url": "v4: tabs and line breaks dropped; scheme and host lowercased; user info and fragment dropped; default port dropped; host escapes decoded, dots collapsed and trimmed, a non-ASCII host converted to its IDNA ASCII form; numeric IPv4 hosts dotted-decimal; dot segments resolved, duplicate slashes collapsed; unreserved escapes decoded, others uppercased; controls, spaces, non-ASCII, and unsafe characters percent-encoded; query kept in order",
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
