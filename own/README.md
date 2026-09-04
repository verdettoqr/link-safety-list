# Our own entries

Links, hosts, and wallet or payment addresses that a person at Verdetto verified
from reports sent through the app and through verdettoqr.com/report. They are
the seventh source of the bundle, hashed exactly like the public feeds.

## The rule

Nothing enters these files without a person's review and an evidence line.
Reports, report counts, and heuristics raise a case's priority; only a person
lists. A false listing is the worst outcome, so when in doubt an entry is a
full URL, not a host, and a host is listed only when the whole domain exists for
the scam.

## Format

One entry per line, then a comment that starts with the date and the case id,
followed by the evidence in one line:

```
https://example-login.test/verify/   # 2026-09-04 case-12 credential form imitating a bank; domain registered 2026-09-01; urlscan abc123
scam-domain.test                      # 2026-09-04 case-13 whole domain a fake shop; registered 2026-08-30; screenshot sha256 9f...
0xabc...                              # 2026-09-04 case-14 scam wallet; three reports; explorer shows drain pattern
```

- `urls.txt`: full URLs, normalized by the builder (canonicalization v4).
- `hosts.txt`: hosts; an entry covers its subdomains.
- `addresses.txt`: wallet and payment addresses.
- `allow.txt`: entries suppressed after a review, whatever source listed them:
  an exact URL, or a host with everything under it. This is how a public feed's
  false positive stops warning on phones the same day.

A line without a date or a case id fails the tests, not the build. Blank lines
and lines that start with `#` are ignored.

## Expiry

An entry in `urls.txt`, `hosts.txt`, or `addresses.txt` expires 90 days after
its date unless the date is renewed after a fresh look; an `allow.txt` entry
expires after 180 days. The build drops expired entries and lists them in its
report so they can be re-verified. Fresh scam domains die young, and a stale
host entry is where false positives come from.

## Getting an entry removed

Report it at https://verdettoqr.com/report ("My site or link is listed by
mistake") or write to support@verdettoqr.com. The page is fetched again; if it
is clean, the entry moves to `allow.txt` the same day. A domain found abusive
again within 30 days of a removal is listed again for at least 30 days.

## License

The data in this folder is released under CC0 1.0 Universal: use it for
anything, no attribution required, no warranty. Attribution to Verdetto is
appreciated. The code that builds the bundle is under the repository's MIT
license.
