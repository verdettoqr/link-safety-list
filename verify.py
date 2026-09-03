#!/usr/bin/env python3
"""Check a published list and look addresses up in it, the way the app does.

  python verify.py dist/list.bin dist/list.json                       # integrity and signature
  python verify.py dist/list.bin dist/list.json https://example.com/  # is this address listed?
"""
from __future__ import annotations

import base64
import bisect
import hashlib
import json
import struct
import sys

from build_list import MAGIC, PREFIX_BYTES, normalize, prefix


def load(path: str) -> tuple[dict, list[bytes], bytes]:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != MAGIC:
        raise SystemExit("not a list file")
    version, generated_at, url_count, host_count = struct.unpack_from("<IQII", data, 4)
    off = 4 + struct.calcsize("<IQII")
    urls = [data[off + i * PREFIX_BYTES: off + (i + 1) * PREFIX_BYTES] for i in range(url_count)]
    return {"version": version, "generated_at": generated_at, "url_count": url_count, "host_count": host_count}, urls, data


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    header, urls, data = load(sys.argv[1])
    with open(sys.argv[2], encoding="utf-8") as f:
        manifest = json.load(f)
    ok = hashlib.sha256(data).hexdigest() == manifest["sha256"] and len(urls) == manifest["url_count"]
    print(f"header {header}")
    print(f"sha256 matches manifest: {ok}")
    if manifest.get("signature") and manifest.get("public_key"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest["public_key"])).verify(base64.b64decode(manifest["signature"]), data)
            print("signature: valid")
        except InvalidSignature:
            print("signature: INVALID")
            ok = False
    else:
        print("signature: none (unsigned build)")
    for raw in sys.argv[3:]:
        n = normalize(raw)
        if n is None:
            print(f"{raw}: not an http(s) address")
            continue
        p = prefix(n)
        i = bisect.bisect_left(urls, p)
        listed = i < len(urls) and urls[i] == p
        print(f"{raw} -> {n}: {'LISTED' if listed else 'not listed'}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
