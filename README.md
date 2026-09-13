# onion-status-check

Honest liveness checks for `.onion` (and clearnet) URLs over Tor.

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
| **TLS** | a `.onion` address already *is* the public key, so CA-signed certificates there are the exception; verification "fails" | OFFLINE | `ONLINE (TLS not verified)` — chain checking is off for `.onion` by policy; the label says what the tool did, not that the certificate is bad |
| **HTTP ≥ 400** | a WAF, a login wall or a rate limiter answered 403/429 — a living server saying "not you" | OFFLINE | `ONLINE (HTTP 403 - access barrier)` |
| **HTTP/2-only** | the server answered in HTTP/2 only; `requests` speaks HTTP/1.1 and sees binary frames (`BadStatusLine`) | OFFLINE | `ONLINE [HTTP/2, measured via curl]` |

The rule is simple: **any response means ONLINE.** Only a target that sends
nothing at all is OFFLINE, and then `error_class` says why:

| `error_class` | Meaning |
|---|---|
| `hidden_service_unreachable` | Tor could not fetch the descriptor / reach the service (SOCKS 0x04) — the usual "it's down" |
| `host_unreachable_via_exit` | clearnet host not resolvable/reachable from the exit (SOCKS 0x04) |
| `invalid_onion_address` | Tor refused to even try (SOCKS 0x01): malformed name, bad checksum, invalid key, retired v2 address |
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
  only fills its `<title>` via JS, the tool takes a second, purely static pass
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

Existing files are never overwritten; a numeric suffix is added on collision.

Each JSON record carries `status` (`ONLINE`/`OFFLINE`), `status_detail`,
`http_code`, `title`, `title_source`, `tls_unverified`, `final_url`,
`needs_js_rendering`, and for OFFLINE targets `error_class` and a truncated
`error` string.

## A note on the User-Agent

The tool sends Tor Browser's default User-Agent. Every Tor Browser install
sends that exact string by design; using it makes these requests
indistinguishable from ordinary Tor Browser traffic rather than singling them
out.

## License

MIT — see `LICENSE`.
