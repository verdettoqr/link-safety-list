# Bundle format, version 2

One release, tagged `current`, replaced on every build. It holds:

| Asset | What | Size, typical |
|---|---|---|
| `list.bin` | Sorted SHA-256 prefixes for listed URLs, hosts, and wallet addresses (`LSL2`) | 3 to 4 MB |
| `psl.txt.gz` | The Public Suffix List rules, one per line (MPL 2.0) | 70 KB |
| `shorteners.txt.gz` | URL shortener hosts, one per line | 6 KB |
| `confusables.txt.gz` | Unicode confusables whose target is ASCII, `HEX<TAB>target` per line | 30 KB |
| `brands.txt.gz` | The top 10,000 domains, one per line, most popular first | 60 KB |
| `list.json` | The manifest: every asset's SHA-256 and size, source outcomes, the signature | 2 KB |
| `list.sig` | The same signature on its own | 90 B |

## `list.bin` (`LSL2`), little-endian

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `LSL2` |
| 4 | 4 | Format version, `2` |
| 8 | 8 | Generated-at, Unix seconds |
| 16 | 8 | URL section: count `u32`, prefix width `u8` (8), 3 bytes padding |
| 24 | 8 | Host section: count `u32`, prefix width `u8` (6), 3 bytes padding |
| 32 | 8 | Address section: count `u32`, prefix width `u8` (8), 3 bytes padding |
| 40 | width·count each | URL prefixes, then host prefixes, then address prefixes; each section sorted ascending, unique |

A prefix is the first `width` bytes of SHA-256 over the normalized text.
With about 10<sup>5</sup> URLs at 8 bytes and 5·10<sup>5</sup> hosts at 6
bytes, the chance that an unrelated lookup collides with a listed entry
is about 10<sup>-14</sup> and 2·10<sup>-9</sup> respectively: no filter,
no false positives in practice, and nothing readable inside.

## Normalization (the app mirrors each rule)

URL, version 4 (2026-09-04; the app's `UrlCanon` and `normalize()` here are
one rule, held together by identical test vectors):

1. Tabs and line breaks dropped; surrounding spaces trimmed.
2. Scheme and host lowercased; only `http` and `https` are listed.
3. User info (`user:pass@`) and the fragment dropped.
4. The default port (80 for http, 443 for https) dropped; other ports kept.
5. Host: percent-escapes decoded, dots collapsed and trimmed; a non-ASCII
   host converted to its IDNA ASCII (punycode) form, the spelling the feeds
   store (v4, 2026-09-04); a numeric IPv4 host in any form (hex, octal,
   decimal, short) written dotted-decimal.
6. Path: `/` when empty; `.` and `..` resolved; duplicate slashes collapsed;
   a trailing slash kept.
7. Percent-escapes: unreserved ones (letters, digits, `-` `.` `_` `~`)
   decoded, others uppercased; controls, spaces, non-ASCII, and `"<>\^\`{|}#`
   percent-encoded as UTF-8; a bare `%` becomes `%25`.
8. The query kept in order under rule 7.

Host: lowercased, no trailing dot; the phone checks the host and each parent
domain down to the registrable domain.

Address: trimmed; 0x EVM addresses lowercased.

## Lookup on the phone

1. URL: normalize, hash, binary-search the URL section.
2. Host: for the scanned host and each parent down to the registrable
   domain, hash and binary-search the host section.
3. Address: for a payment or wallet code, normalize, hash, binary-search
   the address section.
4. Shorteners: the host, or a parent, equals a line of `shorteners.txt`.
5. Lookalikes: map each character of the lowercased Unicode host through
   `confusables.txt` to its ASCII skeleton; if the skeleton's registrable
   domain is in `brands.txt` and the literal host is not, the name imitates
   a known site. A brand within edit distance one of the registrable
   domain is a weaker signal, shown as a note only.
6. Popular site: the registrable domain is in `brands.txt`.

## Manifest and signature (`list.json`, `list.sig`)

`format`, `version` (equals generated-at), `generated_at` (ISO 8601),
`prefix_bytes`, `assets` (per file: `sha256`, `bytes`, and counts),
`sources` (per source: fetched, count, seconds or error; `own` also lists its expired entries and `allow` how many listings it suppressed), `normalization`,
then `signature` and `public_key`. The signature is Ed25519 over the
canonical manifest: the manifest without `signature` and `public_key`,
JSON with keys sorted and no whitespace. The phone verifies the manifest
first, then each asset against its SHA-256, and only then replaces the
bundle it has.

## aviation.txt.gz

One line per IATA code: `kind<TAB>code<TAB>name`, kind `A` for an airport and `L` for an airline, from Wikidata (CC0). Optional for the phone: a missing file only leaves boarding passes with their codes.

## postal.txt.gz

One line per postal code: `country<TAB>code<TAB>place<TAB>region<TAB>lat<TAB>lng`, from the GeoNames postal code files for the countries whose postal barcodes the reader decodes (CC BY 4.0). Optional for the phone.

## aic.txt.gz

One line per Italian medicine pack: `aic<TAB>name<TAB>pack<TAB>holder<TAB>status`, status A authorised, S suspended, R revoked, from the AIFA list of authorised medicines (CC BY 4.0). Optional for the phone.
