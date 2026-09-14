# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) — while the major is `0`, a minor
bump may change the JSON layout and says so under **Changed**.

## [Unreleased]

## [0.2.0] — 2026-09-13

### Added
- `pyproject.toml`: installable with `pip install .` or `pipx install`, which
  puts an `onion-status-check` command on the `PATH`; `--version`. Running
  the file directly keeps working.
- CI: the offline unit tests run on every push and pull request, on Python
  3.10, 3.12 and 3.14; a second job installs the package and runs the command.
- **Index cross-check.** `--indices FILE` names sources, one per line
  `Name | URL-or-path`: remote pages (dark.fail, tor.taxi, Ahmia's onion list,
  any page that lists addresses) are fetched once per run through the proxy;
  local paths — a file or a whole tree, a markdown catalog, your own notes —
  are read from disk. `--catalog PATH …` is a shortcut for local sources;
  `--indices-only` cross-checks without measuring anything. Every record gains
  an `indices` object: `verdict` (`listed` / `name-match` / `unlisted`),
  `listed_in`, `name_matches` (source, name, host, where, line) and
  `sources_failed`. Name matching is normalized (plurals folded, kind and
  generic words dropped, first segment only) and deliberately has no substring
  containment — that rule removed 4 false positives measured on 1,038 real
  addresses against a 1,300-entry catalog while keeping 41 genuine second
  addresses.
- `challenge_page`: a captcha, anti-DDoS or waiting-room page served with a
  2xx is reported as `ONLINE (challenge page)` with
  `title_source=challenge_page` — detected on the body, or on a title that
  names the wall (e.g. *"… Access Queue"*) — instead of being flagged as
  needing JavaScript.
- `content_type` on every ONLINE record, as sent by the server (also via the
  curl branch). The server's `Content-Type` now decides what counts as HTML;
  the body is sniffed only when no header was sent.
- `title_source=not_html` for JSON or plain-text answers, instead of
  `needs_js_rendering`.
- `error_class=proxy_unreachable`: a failed TCP connection to the SOCKS proxy
  itself, as opposed to a refusal by the destination.
- Exit status `3` when a circuit control fails or an index source fails to
  load — "run completed, but do not trust its negatives" — so a cron job
  cannot record a dead batch by mistake. `0` with `--no-controls`.
- `tests/test_unit.py`: 43 offline tests (no Tor needed) pinning error
  classification against the real strings PySocks produces, the HTTP/2
  branch, placeholder and challenge handling, output naming, report escaping,
  exit codes, index matching and its known false positives.
- The HTML report has a stylesheet: status badges, `listed by` chips, circuit
  verdict. Same content as before.
- `docs/`: animated demo of a real run (`demo.gif`, `demo.svg`, regenerated
  by `make_demo.py` from a transcript), report screenshot, two Mermaid
  diagrams in the README (per-target decision; index cross-check flow).

### Changed
- User-Agent tracks Tor Browser 15 (Firefox ESR 140); it was Tor Browser 14
  (ESR 128), which singled the requests out as the previous generation — the
  opposite of what the constant is for.
- README rewritten to be read top to bottom: the two questions and a real
  transcript first, then how to read a result, why naive checkers lie,
  indices, what the tool never does, and a reference section. Module
  docstring cut to what a reader of the source needs.

### Fixed
- Error classification order. PySocks wraps every SOCKS reply in the same
  `NewConnectionError` text, and the `proxy_unreachable` check was inserted
  before the `0x01`/`0x05`/`0x06` checks — so an invalid onion address (`0x01`)
  and a refusal by the destination (`0x05`) were reported as a dead proxy.
  Introduced and fixed within this release cycle; the tests now use the real
  error strings so it cannot come back unnoticed.
- An HTML fragment without `<html>`/`<title>` (a captcha form) was labeled
  `not_html`.

## [0.1.0] — 2026-09-13

Initial release.

- One plain HTTP GET per target through the local Tor SOCKS proxy; status code
  and page `<title>`, nothing else — no JavaScript, images, forms, login or
  crawling; one request at a time with a random 2–5 s pause.
- **Any response means ONLINE; only silence is OFFLINE.** The nuance goes into
  `status_detail`: TLS not verified, access barrier (401/402/403/407/429/451),
  missing resource (404), server error (5xx); OFFLINE records carry
  `error_class` and a truncated error string.
- The three ways a naive checker lies, each handled: TLS chain verification
  off for `.onion` from the first attempt (a `.onion` address already *is* the
  key), and on clearnet retried unverified only after a handshake failure;
  HTTP ≥ 400 is a living server; HTTP/2-only servers (binary frames surface as
  `BadStatusLine`) get a `curl --http2` second opinion through the same proxy,
  and only on that signature.
- Circuit controls: known-up targets measured at the end of every run, so a
  batch of negatives can be told from a broken circuit.
- Placeholder titles (*Loading…*, *Just a moment…*) trigger a second, purely
  static look at the HTML already fetched — `og:title`, `twitter:title`, API
  endpoint hints, SPA state markers — and otherwise `needs_js_rendering`.
- JSON (one object per target) and HTML report; results are never
  overwritten — file names carry a local-time stamp and get a `-2` suffix on
  collision; `checked_at` is UTC.
- Options: `--out-dir`, `--proxy`, `--timeout`, `--delay`, `--no-controls`,
  `--no-html`.

[Unreleased]: https://github.com/xbara0x/onion-status-check/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/xbara0x/onion-status-check/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/xbara0x/onion-status-check/releases/tag/v0.1.0
