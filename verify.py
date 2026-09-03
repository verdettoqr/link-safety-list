#!/usr/bin/env python3
"""Check a published bundle and look things up in it, the way the app does.

  python verify.py dist                                  # every asset's hash, the signature
  python verify.py dist https://example.com/ evil.example 0xabc...   # URL, host (with parent walk), address lookups
"""
from __future__ import annotations

import base64
import bisect
import gzip
import hashlib
import json
import os
import struct
import sys

from build_list import ADDRESS_PREFIX, HOST_PREFIX, MAGIC, URL_PREFIX, canonical, normalize, normalize_address, normalize_host, prefix


def load_bin(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != MAGIC:
        raise SystemExit("not an LSL2 file")
    version, generated_at = struct.unpack_from("<IQ", data, 4)
    off = 16
    sections = []
    for _ in range(3):
        count, width = struct.unpack_from("<IB3x", data, off)
        sections.append((count, width))
        off += 8
    arrays = []
    for count, width in sections:
        arrays.append([data[off + i * width: off + (i + 1) * width] for i in range(count)])
        off += count * width
    return {"version": version, "generated_at": generated_at, "sections": sections}, arrays, data


def listed(arr: list[bytes], p: bytes) -> bool:
    i = bisect.bisect_left(arr, p)
    return i < len(arr) and arr[i] == p


def psl_registrable(host: str, rules: set[str], wildcards: set[str], exceptions: set[str]) -> str:
    """Registrable domain per the Public Suffix List algorithm (enough of it for lookups)."""
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        parent = ".".join(labels[i + 1:])
        if candidate in exceptions:
            return candidate
        if parent in wildcards:
            return ".".join(labels[i - 1:]) if i >= 1 else host
        if candidate in rules:
            return ".".join(labels[i - 1:]) if i >= 1 else host
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    out = sys.argv[1]
    with open(os.path.join(out, "list.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    ok = True
    for name, meta in manifest["assets"].items():
        with open(os.path.join(out, name), "rb") as f:
            blob = f.read()
        good = hashlib.sha256(blob).hexdigest() == meta["sha256"] and len(blob) == meta["bytes"]
        ok &= good
        print(f"{name}: {len(blob)} bytes, sha256 {'ok' if good else 'MISMATCH'}")
    if manifest.get("signature") and manifest.get("public_key"):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key"])).verify(base64.b64decode(manifest["signature"]), canonical(manifest))
            print("signature: valid")
        except InvalidSignature:
            print("signature: INVALID")
            ok = False
    else:
        print("signature: none (unsigned build)")

    header, (urls, hosts, addresses), _ = load_bin(os.path.join(out, "list.bin"))
    print(f"list.bin: {header}")
    if len(sys.argv) > 2:
        rules, wildcards, exceptions = set(), set(), set()
        with gzip.open(os.path.join(out, "psl.txt.gz"), "rt", encoding="utf-8") as f:
            for line in f:
                r = line.strip()
                if r.startswith("*."):
                    wildcards.add(r[2:])
                elif r.startswith("!"):
                    exceptions.add(r[1:])
                elif r:
                    rules.add(r)
        for raw in sys.argv[2:]:
            if raw.startswith("0x") or (len(raw) > 25 and "." not in raw and "/" not in raw):
                a = normalize_address(raw)
                print(f"{raw}: address {'LISTED' if a and listed(addresses, prefix(a, ADDRESS_PREFIX)) else 'not listed'}")
                continue
            n = normalize(raw) if "://" in raw else None
            host = normalize_host(raw if "://" not in raw else raw.split("://", 1)[1])
            if n:
                print(f"{raw} -> {n}: url {'LISTED' if listed(urls, prefix(n, URL_PREFIX)) else 'not listed'}")
            if host:
                reg = psl_registrable(host, rules, wildcards, exceptions)
                labels = host.split(".")
                hit = None
                for i in range(len(labels)):
                    cand = ".".join(labels[i:])
                    if listed(hosts, prefix(cand, HOST_PREFIX)):
                        hit = cand
                        break
                    if cand == reg:
                        break
                print(f"{host}: registrable {reg}; host {'LISTED via ' + hit if hit else 'not listed'}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
