# onion-status-check

Honest liveness checks for `.onion` (and clearnet) URLs over Tor.

**Status:** v0.1 — a working measurement tool; the JSON layout may still change.

One plain HTTP GET per target through the local Tor SOCKS proxy; records the
HTTP status code and the page `<title>`. No JavaScript, no images, no forms, no
login, no crawling. At the end of each run it measures a few known-good control
targets, so a batch of negatives can be told apart from a broken circuit.

## Why another link checker

The naive version of this tool — *"anything that isn't a clean 200 is dead"* —
produces false **OFFLINE** verdicts in three separate ways, and each of them
looks identical in a summary count:

| Cause | What actually happened | Naive verdict | This tool |
|---|---|---|---|
| **TLS** | a `.onion` address already *is* the public key, so CA-signed certificates there are the exception; verification "fails" | OFFLINE | `ONLINE (TLS not verified)` — chain checking is off for `.onion` by policy; the label says what the tool did, not that the certificate is bad. On clearnet the chain **is** verified, and the request is retried unverified only when the handshake fails — so a clearnet `TLS not verified` means "live server, certificate did not validate" |
| **HTTP ≥ 400** | a WAF, a login wall or a rate limiter answered 403/429 — a living server saying "not you" | OFFLINE | `ONLINE (HTTP 403 - access barrier)` |
| **Challenge page** | a captcha / anti-DDoS / waiting-room page served with **200** — often an HTML fragment with no `<title>` at all | "online, no title" or "needs JS" | `ONLINE (challenge page)` — a living server gating access; JavaScript would not help |
| **HTTP/2-only** | the server answered in HTTP/2 only; `requests` speaks HTTP/1.1 and sees binary frames (`BadStatusLine`) | OFFLINE | `ONLINE [HTTP/2, measured via curl]` |

The rule is simple: **any response means ONLINE.** Only a target that sends
nothing at all is OFFLINE, and then `error_class` says why:

| `error_class` | Meaning |
|---|---|
| `hidden_service_unreachable` | Tor could not fetch the descriptor / reach the service (SOCKS 0x04) — the usual "it's down" |
| `host_unreachable_via_exit` | clearnet host not resolvable/reachable from the exit (SOCKS 0x04) |
| `invalid_onion_address` | Tor refused to even try (SOCKS 0x01): malformed name, bad checksum, invalid key, retired v2 address |
| `socks_general_failure` | the same SOCKS 0x01 on a clearnet target |
| `proxy_unreachable` | the TCP connection to the SOCKS proxy itself failed — Tor is not running, or not where `--proxy` points; nothing was measured |
| `connection_refused_by_destination` | SOCKS 0x05 |
| `circuit_failed` | SOCKS 0x06 / TTL expired |
| `timeout` | no answer within `--timeout` |
| `tls_failed_even_unverified` | TLS handshake failed with verification already off |
| `connection_refused_or_reset` | connection error not matching any SOCKS code |
| `request_error` | anything else from `requests` |

## Circuit controls

A batch of negative results is far more often the instrument or the circuit
than the population. Every run ends by measuring three known-good targets
(Tor Project's check endpoint, DuckDuckGo's onion, Ahmia's onion). If they fail
too, the report says so in capitals and you should not record anything as dead
from that run.

## What it deliberately does not do

- **No JavaScript rendering.** Rendering unknown dark-web pages is a different
  risk category and has historically been used for deanonymization. When a page
  only fills its `<title>` via JS (the title matches a placeholder such as
  *Loading…*, *Please wait*, *Just a moment*, *Redirecting*, *Verifying humanity*,
  *Checking your browser*), the tool takes a second, purely static pass
  over the HTML it already has (`og:title`, `twitter:title`, API endpoint hints,
  embedded-state markers) and otherwise flags the entry as
  `needs_js_rendering`, listed separately in the report.
- **No retries through curl on ordinary failures.** The `curl --http2` second
  opinion fires only when the failure has the HTTP/2 signature. If Tor cannot
  reach a service, curl would use the same daemon and fail the same way,
  doubling the cost of every dead target for nothing.
- **No concurrency.** One request at a time, with a random 2–5 s pause. This is
  a measurement tool, not a scanner.

## Requirements

- A local Tor daemon with SOCKS5 on `127.0.0.1:9050` (Debian/Arch: `tor`
  package; `systemctl enable --now tor`)
- Python 3.10+
- `pip install -r requirements.txt` (`requests[socks]`, `beautifulsoup4`)
- `curl` on `PATH` (only used for the HTTP/2 second opinion)

## Usage

```bash
python3 onion_status_check.py examples/targets.txt
python3 onion_status_check.py targets.txt --out-dir results --timeout 25
```

`targets.txt` has one target per line, either `Name | URL` or just `URL`;
lines starting with `#` are ignored.

Options: `--proxy` (default `socks5h://127.0.0.1:9050` — keep the `h` so Tor
resolves `.onion` names), `--timeout` (default 25 s), `--delay MIN MAX`,
`--no-controls` (not recommended), `--no-html`.

## Output

```
results/<targets-stem>-<YYYYmmdd-HHMM>.json            raw results, one object per target
results/<targets-stem>-<YYYYmmdd-HHMM>-controls.json   the control targets
results/<targets-stem>-<YYYYmmdd-HHMM>.html            human-readable report
```

Existing files are never overwritten; on a collision within the same minute a
numeric suffix is added (`-2`, `-3`, …). File names use local time; the
`checked_at` field inside the records is UTC.

Every record carries `name`, `uri`, `checked_at`, `status` (`ONLINE`/`OFFLINE`),
`status_detail` and `http_code`.

ONLINE records add `content_type` (as sent by the server, empty if none),
`title`, `title_source` (`html_title`; `meta_tag` when the
`<title>` was a placeholder and `og:title`/`twitter:title` was used instead;
`html_title_placeholder` when nothing better was found; `not_html` when the
answer was not an HTML document at all — JSON, plain text — so no title was
expected and the entry is *not* flagged for JavaScript; `challenge_page` when
the body is a captcha / anti-DDoS / queue page — the server's `Content-Type`
decides what counts as HTML, and the body is only sniffed when there is no
header), `tls_unverified`,
`final_url` and `needs_js_rendering`. When the title looked like a placeholder
they also carry `static_hints`: `meta_title`, `meta_description`, `api_hints`,
`spa_state_markers` and `script_srcs` — reported, never fetched.

OFFLINE records have `http_code` and `title` set to `null`, plus `error_class`
(table above) and a truncated `error` string.

## Exit status

| Code | Meaning |
|---|---|
| `0` | run completed; every control target answered (or `--no-controls`) |
| `3` | run completed, but at least one control target failed — **circuit suspect**, do not record anything as dead from this run |
| `2` | usage error (bad arguments) |

Anything else is a crash. Scripts and cron jobs should treat any non-zero as
"do not trust this run".

## Tests

Offline unit tests (no Tor, no network) pin the behaviour that makes this tool
different from a naive checker — status semantics, error classification with the
real error strings PySocks produces, the HTTP/2 second-opinion branch,
placeholder handling, output naming and report escaping:

```bash
python3 -m unittest discover -s tests -v
```

For a live check, run the example list (public services only):

```bash
python3 onion_status_check.py examples/targets.txt
```

Expected: every target `ONLINE` (the HTTPS onions with the `TLS not verified`
caveat), `Controls: 3/3 online`, exit status `0`.

## A note on the User-Agent

The tool sends Tor Browser's default User-Agent — currently the one of Tor
Browser 15 (Firefox ESR 140). Every Tor Browser install sends that exact string
by design; using it makes these requests indistinguishable from ordinary Tor
Browser traffic rather than singling them out. It has to track Tor Browser's
ESR line: when a new major ships, update `TOR_BROWSER_UA` or the requests start
standing out as the previous generation.

## License

MIT — see `LICENSE`.
