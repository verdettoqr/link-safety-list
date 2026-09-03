# List format, version 1 (`LSL1`)

One binary file, little-endian, checked by binary search on the phone.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `LSL1` |
| 4 | 4 | Format version, `1` |
| 8 | 8 | Generated-at, Unix seconds |
| 16 | 4 | URL prefix count, `n` |
| 20 | 4 | Host prefix count, `m` (always `0` in version 1; reserved) |
| 24 | 8·n | URL prefixes, sorted ascending, unique |
| 24 + 8·n | 8·m | Host prefixes, sorted ascending, unique |

A prefix is the first 8 bytes of SHA-256 over the normalized address.

## Normalization (must match the app)

Scheme and host lowercased; an explicit port kept as written; the path
`/` when empty; the query kept; the fragment dropped. Only `http` and
`https` addresses are listed. Example: `HTTPS://Example.COM/a?b=1#c`
becomes `https://example.com/a?b=1`.

## Lookup on the phone

1. Normalize the scanned address the same way.
2. SHA-256 it and take the first 8 bytes.
3. Binary-search the URL prefix array. A hit means the exact
   normalized address was in a source feed at build time.

With 8-byte prefixes and about 10<sup>5</sup> entries the chance that
an unrelated address collides with a listed one is about 10<sup>-14</sup>
per lookup: no filter, no false positives in practice, and the file
holds nothing readable about which addresses are listed.

## Manifest (`list.json`)

`format`, `version` (same as generated-at), `generated_at` (ISO 8601),
`url_count`, `host_count`, `prefix_bytes`, `bytes`, `sha256` of the
binary, `signature` (base64 Ed25519 over the binary, or null), `public_key`
(hex, or null), `sources` (per source: fetched, count, seconds or error),
and the normalization rule in words.

## Signature (`list.sig`)

The base64 Ed25519 signature over the whole binary, the same value as
`signature` in the manifest. The phone verifies it with the public key
compiled into the app before it replaces the list it already has.
