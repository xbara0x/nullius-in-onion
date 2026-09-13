#!/usr/bin/env python3
"""
onion-status-check — honest liveness checks for .onion (and clearnet) URLs over Tor.

What it does
------------
For each target it performs ONE plain HTTP GET through the local Tor SOCKS proxy
and records the HTTP status code and the page <title>. That is all. It does not
execute JavaScript, load images, submit forms, log in, or follow any link other
than the target's own redirects. Deciding whether a title matches what you
expected is analysis work for a human, not for this script.

Status semantics
----------------
ANY HTTP response means ONLINE. A server answering 403 is alive; a hidden
service with a self-signed certificate is alive. Only a target that sends no
response at all is OFFLINE. The nuance goes into "status_detail":

    ONLINE                                  response < 400, TLS chain OK (or plain HTTP)
    ONLINE (TLS not verified)               responded over TLS with chain verification off
    ONLINE (HTTP 4xx - access barrier)      401/402/403/407/429/451: login wall, WAF, rate limit
    ONLINE (challenge page)                 2xx, but the body is a captcha / anti-DDoS / queue page
    ONLINE (HTTP 404 - missing resource)    server alive, path dead
    ONLINE (HTTP 5xx - server error)        application broken, host up
    OFFLINE                                 no response (see "error_class")

This distinction exists because the naive version of this tool — "anything that
isn't a clean 200 is dead" — produced false OFFLINE verdicts in three separate
ways, each of which looks identical in a summary count:

  1. TLS.    A .onion address already IS the public key, so CA-signed
             certificates on hidden services are the exception rather than the
             rule. Verifying the chain there is close to meaningless, and
             treating a handshake failure as "down" is simply wrong. Chain
             verification is therefore disabled for .onion from the first
             attempt, and the result is labeled "TLS not verified" — a
             statement about what the tool did, not a claim that the
             certificate is bad (some onions do carry CA-signed certificates).
             On clearnet verification stays on, and is retried without it ONLY
             when the handshake fails — to tell "bad certificate" apart from
             "server gone". None of this loosens anything: still no JS, no
             login, no credentials.
  2. HTTP >= 400.  A 403 from a WAF or a login wall is a living server saying
             "not you". Counting it as dead hides exactly the targets that are
             most interesting.
  3. HTTP/2. `requests` speaks HTTP/1.1 only. A server that answers only in
             HTTP/2 sends binary frames that surface as BadStatusLine, which
             the naive version reported as OFFLINE. When the failure has that
             signature — and only then — the script asks `curl --http2` for a
             second opinion through the same proxy. It does not retry via curl
             on ordinary failures: if Tor cannot reach the service, curl uses
             the same daemon and fails the same way, doubling the cost of every
             dead target for nothing.

Circuit controls
----------------
At the end of every run the script measures a few control targets that are
known to be up. A batch of negative results is far more often the instrument or
the circuit than the population; a control failure means "do not record anything
as dead from this run". Do not skip this step — false negatives caught this way
are the reason it exists.

Placeholder titles
------------------
Some pages only populate <title> via JavaScript ("Loading...", "Just a
moment..."). The script deliberately does NOT render JS: rendering unknown
dark-web pages is a different risk category and has historically been used for
deanonymization. Instead, when the title looks like a placeholder, it takes a
second, purely static pass over the HTML already downloaded: it checks
<meta property="og:title"> / twitter:title (often server-rendered even on SPAs)
as an alternative title, and looks for API endpoint hints (fetch/axios/XHR
calls, "/api/", "/graphql") and embedded-state markers (__NEXT_DATA__, __NUXT__,
__INITIAL_STATE__) — reported as hints only, never fetched. If nothing resolves,
the entry is flagged "needs_js_rendering" and listed separately in the report,
instead of disappearing among the resolved ones.

Requirements
------------
  - A local Tor daemon (SOCKS5 on 127.0.0.1:9050 by default)
  - Python 3.10+, `pip install requests[socks] beautifulsoup4`
  - `curl` on PATH (only used for the HTTP/2 second opinion)

Usage
-----
  python3 onion_status_check.py targets.txt
  python3 onion_status_check.py targets.txt --out-dir results --timeout 25

  targets.txt: one target per line, either "Name | URL" or just "URL".
  Lines starting with "#" are ignored.

Output
------
  <out-dir>/<targets-stem>-<YYYYmmdd-HHMM>.json           raw results
  <out-dir>/<targets-stem>-<YYYYmmdd-HHMM>-controls.json  control targets
  <out-dir>/<targets-stem>-<YYYYmmdd-HHMM>.html           human-readable report
  Existing files are never overwritten; a numeric suffix is added instead.

Exit status
-----------
  0  run completed and every control target answered (or --no-controls)
  3  run completed but a control target failed: circuit suspect, do not
     record anything as dead from this run
  2  usage error (argparse)
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

# Chain verification is disabled on purpose for .onion (see module docstring);
# the urllib3 warning would only clutter the output and teach people to ignore
# warnings, which is worse.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_TIMEOUT = 25
DEFAULT_DELAY = (2.0, 5.0)  # seconds between requests; do not look like an aggressive crawler

# Tor Browser's User-Agent. Every Tor Browser install sends this exact string by
# design, so using it does not single this request out from the rest of the
# traffic leaving the network — it is the opposite of fingerprinting.
# Tor Browser's default UA. It tracks Firefox ESR: Tor Browser 15.x = ESR 140.
# Update when a new Tor Browser major ships, or the requests stand out as the
# previous generation — the opposite of what this constant is for.
TOR_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0"

# Control targets: known-good services measured at the end of each run to
# validate the Tor circuit. If these fail together with everything else, the
# problem is the path, not the targets.
CONTROL_TARGETS = [
    ("[control] Tor Project check", "https://check.torproject.org/api/ip"),
    ("[control] DuckDuckGo (onion)",
     "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"),
    ("[control] Ahmia (onion)",
     "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"),
]

# Access barrier: a living server saying "not for you".
ACCESS_BARRIER_CODES = {401, 402, 403, 407, 429, 451}

PLACEHOLDER_TITLE_RE = re.compile(
    r"^\s*(loading|please wait|just a moment|redirecting|verify(ing)? humanity|checking your browser)\b",
    re.IGNORECASE,
)

# API / embedded-state hints: reported only, never fetched.
API_HINT_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.(?:get|post|put|delete)\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\.open\(\s*['"](?:GET|POST)['"]\s*,\s*['"]([^'"]+)['"]"""),
    re.compile(r"""["'](/api/[^"'<>\s]+)["']"""),
    re.compile(r"""["'](/graphql[^"'<>\s]*)["']"""),
]
SPA_STATE_MARKERS = ["__NEXT_DATA__", "__NUXT__", "__INITIAL_STATE__", "application/json"]
MAX_HINTS = 10

CURL_MARKER = "__CURL_META__"


class Config:
    """Run-time settings, filled from the command line."""

    def __init__(self, proxy: str, timeout: int, delay: tuple[float, float]):
        self.proxy = proxy
        self.timeout = timeout
        self.delay = delay


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #

def read_targets(path: Path) -> list[tuple[str, str]]:
    """One target per line: "Name | URL" or just "URL". '#' starts a comment."""
    entries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            name, uri = (p.strip() for p in line.split("|", 1))
        else:
            name = uri = line
        if not uri.startswith(("http://", "https://")):
            print(f"skipping (not http/https): {line}", file=sys.stderr)
            continue
        entries.append((name, uri))
    return entries


def is_onion(uri: str) -> bool:
    host = urlparse(uri).hostname or ""
    return host.endswith(".onion")


# --------------------------------------------------------------------------- #
# Static hints for placeholder titles
# --------------------------------------------------------------------------- #

def looks_like_placeholder(title: str) -> bool:
    if not title or len(title.strip()) < 2:
        return True
    return bool(PLACEHOLDER_TITLE_RE.match(title.strip()))


CHALLENGE_RE = re.compile(
    r"captcha|anti-?ddos|ddos-?guard|prove (that )?you are (a )?human|are you (a )?human|"
    r"verify you are (a )?human|access queue|waiting room",
    re.IGNORECASE,
)


def looks_like_challenge(body: str) -> bool:
    """Captcha / anti-DDoS / waiting-room page served with a 2xx. A living
    server that will not show content yet — an access barrier, not a title
    problem and not something JavaScript would fix."""
    return bool(CHALLENGE_RE.search(body[:4096]))


def is_html_response(resp: "Fetched") -> bool:
    """Trust the server's Content-Type when it sent one; sniff the body only
    when it did not. An HTML fragment (a bare <form>, say) has no <html> or
    <title> to sniff for, yet is HTML."""
    if resp.content_type:
        return "html" in resp.content_type.lower()
    return looks_like_html(resp.text)


def looks_like_html(body: str) -> bool:
    """Cheap sniff of the first bytes: a JSON or plain-text answer has no <title>
    to begin with, and must not be flagged as "title only via JavaScript"."""
    head = body[:2048].lower()
    return any(tag in head for tag in ("<!doctype", "<html", "<head", "<body", "<title"))


def extract_static_hints(html_text: str, soup: BeautifulSoup) -> dict:
    def meta_content(*, prop: str | None = None, name: str | None = None) -> str:
        attrs = {"property": prop} if prop else {"name": name}
        tag = soup.find("meta", attrs=attrs)
        content = tag.get("content") if tag else None
        return content.strip() if content else ""

    meta_title = (
        meta_content(prop="og:title")
        or meta_content(name="twitter:title")
        or meta_content(name="title")
    )
    meta_description = meta_content(prop="og:description") or meta_content(name="description")

    api_hints: list[str] = []
    for pattern in API_HINT_PATTERNS:
        for match in pattern.findall(html_text):
            candidate = match if isinstance(match, str) else match[0]
            if candidate and candidate not in api_hints:
                api_hints.append(candidate)
    api_hints = api_hints[:MAX_HINTS]

    spa_markers = [m for m in SPA_STATE_MARKERS if m in html_text]

    script_srcs: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src not in script_srcs:
            script_srcs.append(src)
    script_srcs = script_srcs[:MAX_HINTS]

    return {
        "meta_title": meta_title,
        "meta_description": meta_description,
        "api_hints": api_hints,
        "spa_state_markers": spa_markers,
        "script_srcs": script_srcs,
    }


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #

class Fetched:
    """Normalized response — whether it came from requests or from curl."""

    def __init__(self, status_code: int, text: str, url: str, via: str = "requests",
                 content_type: str = ""):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.via = via
        self.content_type = content_type


def classify_error(exc: Exception, uri: str = "") -> str:
    """Name the reason there was no response. Only for genuine OFFLINE."""
    text = str(exc)
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if "0x04" in text or "Host unreachable" in text:
        # SOCKS: Tor could not reach the destination. For .onion that means the
        # hidden-service descriptor; for clearnet, the exit could not resolve or
        # reach the host.
        return "hidden_service_unreachable" if is_onion(uri) else "host_unreachable_via_exit"
    if "0x06" in text or "TTL expired" in text:
        return "circuit_failed"
    if "0x05" in text:
        # SOCKS 0x05 only. A bare "[Errno 111] Connection refused" with no SOCKS
        # code is the proxy itself refusing — handled below as proxy_unreachable.
        return "connection_refused_by_destination"
    if "0x01" in text or "General SOCKS server failure" in text:
        # Tor answers "general failure" for an address it will not even try:
        # malformed .onion, wrong length, bad checksum, or a retired v2 name.
        return "invalid_onion_address" if is_onion(uri) else "socks_general_failure"
    if ("Failed to establish a new connection" in text or "NewConnectionError" in text) \
            and "0x" not in text:
        # The TCP connection to the SOCKS proxy itself failed: Tor is not
        # running or not listening where --proxy points. Nothing was measured.
        # PySocks wraps every SOCKS reply in the same NewConnectionError text,
        # so this must come AFTER the 0xNN checks — otherwise "invalid onion"
        # and "connection refused by destination" would be misread as a dead
        # proxy.
        return "proxy_unreachable"
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls_failed_even_unverified"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_refused_or_reset"
    return "request_error"


def describe_response(resp: Fetched, tls_unverified: bool) -> str:
    """Human label for what the response means. It responded => it is ONLINE."""
    code = resp.status_code
    suffix = " [HTTP/2, measured via curl]" if resp.via == "curl-http2" else ""
    if code in ACCESS_BARRIER_CODES:
        return f"ONLINE (HTTP {code} - access barrier){suffix}"
    if tls_unverified:
        return f"ONLINE (TLS not verified){suffix}"
    if code in (404, 410):
        return f"ONLINE (HTTP {code} - missing resource){suffix}"
    if code >= 500:
        return f"ONLINE (HTTP {code} - server error){suffix}"
    if code >= 400:
        return f"ONLINE (HTTP {code}){suffix}"
    return f"ONLINE{suffix}" if suffix else "ONLINE"


def fetch_via_curl(uri: str, cfg: Config) -> Fetched | None:
    """Second opinion for what `requests` cannot speak (HTTP/2-only servers).

    Same policy as everywhere else: plain GET, no JS, no login.
    """
    cmd = [
        "curl", "-s", "-k", "-L", "--http2",
        "--socks5-hostname", cfg.proxy.split("//", 1)[1],
        "--max-time", str(cfg.timeout),
        "-A", TOR_BROWSER_UA,
        "-w", f"\n{CURL_MARKER}%{{http_code}}|%{{content_type}}|%{{url_effective}}",
        uri,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=cfg.timeout + 15)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = proc.stdout.decode("utf-8", errors="replace")
    if CURL_MARKER not in out:
        return None
    body, meta = out.rsplit(CURL_MARKER, 1)
    code_txt, _, rest = meta.partition("|")
    content_type, _, final_url = rest.partition("|")
    try:
        code = int(code_txt.strip())
    except ValueError:
        return None
    if code == 0:  # curl got no response either
        return None
    return Fetched(code, body, final_url.strip() or uri, via="curl-http2",
                   content_type=content_type.strip())


def fetch(uri: str, session: requests.Session, cfg: Config) -> tuple[Fetched, bool]:
    """GET with the right TLS policy for the target. Returns (response, tls_unverified).

    For .onion the chain is not verified from the first attempt: the address is
    already the public key. On clearnet verification applies, and is retried
    without it only when the handshake fails — to distinguish "bad certificate"
    from "server down".
    """
    try:
        if is_onion(uri):
            r = session.get(uri, timeout=cfg.timeout, allow_redirects=True, verify=False)
            # "TLS not verified" only makes sense if TLS exists: a plain-http
            # .onion has no certificate at all, and labeling it would be
            # inventing a fact about the target.
            return (Fetched(r.status_code, r.text, r.url, content_type=r.headers.get("Content-Type", "")),
                    r.url.startswith("https://"))
        try:
            r = session.get(uri, timeout=cfg.timeout, allow_redirects=True)
            return Fetched(r.status_code, r.text, r.url, content_type=r.headers.get("Content-Type", "")), False
        except requests.exceptions.SSLError:
            r = session.get(uri, timeout=cfg.timeout, allow_redirects=True, verify=False)
            return Fetched(r.status_code, r.text, r.url, content_type=r.headers.get("Content-Type", "")), True
    except (requests.exceptions.ConnectionError, requests.exceptions.SSLError) as e:
        # Second opinion via curl ONLY when the failure looks like HTTP/2 — i.e.
        # the server DID respond, in a protocol requests does not speak.
        # On any other failure curl would use the same Tor daemon and fail the
        # same way, spending another full timeout without changing the result.
        text = str(e)
        looks_like_http2 = ("BadStatusLine" in text or "\\x00\\x00" in text
                            or "Invalid method encountered" in text)
        if not looks_like_http2:
            raise
        alt = fetch_via_curl(uri, cfg)
        if alt is None:
            raise
        # A .onion over TLS was fetched with verification off by policy; on
        # clearnet nothing can be claimed about the chain from a `curl -k`.
        return alt, is_onion(uri) and alt.url.startswith("https://")


def check_one(name: str, uri: str, session: requests.Session, cfg: Config) -> dict:
    result = {
        "name": name,
        "uri": uri,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        resp, tls_unverified = fetch(uri, session, cfg)
        result["http_code"] = resp.status_code
        result["status"] = "ONLINE"  # it responded: it is alive, whatever the code
        result["status_detail"] = describe_response(resp, tls_unverified)
        result["tls_unverified"] = tls_unverified
        result["final_url"] = resp.url
        soup = BeautifulSoup(resp.text, "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""
        result["title"] = title
        result["title_source"] = "html_title"
        result["needs_js_rendering"] = False

        result["content_type"] = resp.content_type
        if not title and not is_html_response(resp):
            result["title_source"] = "not_html"  # JSON / plain text: no title expected
        elif looks_like_challenge(resp.text) and (not title or looks_like_placeholder(title)):
            # Captcha / anti-DDoS wall with a 2xx: the server is up and is
            # gating access. Label it as such instead of blaming JavaScript.
            result["title_source"] = "challenge_page"
            if resp.status_code < 400:
                result["status_detail"] = "ONLINE (challenge page)" + (
                    " [HTTP/2, measured via curl]" if resp.via == "curl-http2" else "")
        elif looks_like_placeholder(title):
            hints = extract_static_hints(resp.text, soup)
            result["static_hints"] = hints
            fallback_title = hints["meta_title"]
            if fallback_title and not looks_like_placeholder(fallback_title):
                result["title"] = fallback_title
                result["title_source"] = "meta_tag"
            else:
                result["title_source"] = "html_title_placeholder"
                result["needs_js_rendering"] = True
    except requests.exceptions.RequestException as e:
        result["status"] = "OFFLINE"
        result["status_detail"] = "OFFLINE"
        result["http_code"] = None
        result["title"] = None
        result["error_class"] = classify_error(e, uri)
        result["error"] = str(e)[:200]
    return result


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def write_html_report(results: list[dict], out_path: Path,
                      controls: list[dict] | None = None) -> None:
    online = [r for r in results if r["status"] == "ONLINE"]
    offline = [r for r in results if r["status"] != "ONLINE"]
    needs_js = [r for r in online if r.get("needs_js_rendering")]
    # "With caveat": responded, but not a clean 2xx with a valid chain. The naive
    # version of this tool reported this whole group as OFFLINE.
    caveat = [r for r in online
              if not r.get("needs_js_rendering") and r.get("status_detail", "ONLINE") != "ONLINE"]
    resolved = [r for r in online
                if not r.get("needs_js_rendering") and r.get("status_detail", "ONLINE") == "ONLINE"]

    lines = ["<!doctype html><html><head><meta charset='utf-8'>"
             "<title>onion-status-check report</title></head><body>"]

    lines.append(f"<h1>Online, title resolved ({len(resolved)})</h1><ol>")
    for r in resolved:
        title = r.get("title") or "(no title)"
        note = " [via meta tag, not &lt;title&gt;]" if r.get("title_source") == "meta_tag" else ""
        lines.append(f"<li><a href='{_esc(r['uri'])}' target='_blank'>{_esc(title)}</a>{note}"
                     f" — target: {_esc(r['name'])}</li>")
    lines.append("</ol>")

    lines.append(f"<h1>Online, but title only via JavaScript ({len(needs_js)})</h1><ol>")
    for r in needs_js:
        hints = r.get("static_hints", {})
        parts = []
        if hints.get("api_hints"):
            parts.append("API: " + ", ".join(hints["api_hints"]))
        if hints.get("spa_state_markers"):
            parts.append("embedded state: " + ", ".join(hints["spa_state_markers"]))
        hint_txt = " | ".join(parts) if parts else "no static hints found"
        lines.append(f"<li>{_esc(r['name'])} — {_esc(r['uri'])} — raw title: "
                     f"\"{_esc(str(r.get('title')))}\" — {_esc(hint_txt)}</li>")
    lines.append("</ol>")

    lines.append(f"<h1>Online, with caveat ({len(caveat)})</h1>")
    lines.append("<p>These responded. They are <b>not</b> offline.</p><ol>")
    for r in caveat:
        title = r.get("title") or "(no title)"
        lines.append(f"<li><b>{_esc(r.get('status_detail', ''))}</b> — {_esc(r['name'])} — "
                     f"{_esc(r['uri'])} — title: \"{_esc(title)}\"</li>")
    lines.append("</ol>")

    lines.append(f"<h1>Offline ({len(offline)})</h1><p>No response at all.</p><ol>")
    for r in offline:
        detail = r.get("error_class") or r.get("error") or "no detail"
        lines.append(f"<li>{_esc(r['name'])} — {_esc(r['uri'])} — {_esc(detail)}</li>")
    lines.append("</ol>")

    if controls:
        ok = sum(1 for c in controls if c["status"] == "ONLINE")
        verdict = ("Tor circuit validated" if ok == len(controls)
                   else "<b>CIRCUIT SUSPECT — do not record anything as dead from this run</b>")
        lines.append(f"<h1>Circuit controls ({ok}/{len(controls)}) — {verdict}</h1><ul>")
        for c in controls:
            lines.append(f"<li>{_esc(c['name'])} — {_esc(c.get('status_detail', c['status']))}</li>")
        lines.append("</ul>")

    lines.append("</body></html>")
    out_path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def unique_base(out_dir: Path, stem: str) -> str:
    """Date + time + list name. Never overwrite: add a numeric suffix on collision."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    base = f"{stem}-{stamp}"
    n = 1
    while (out_dir / f"{base}.json").exists():
        n += 1
        base = f"{stem}-{stamp}-{n}"
    return base


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="onion_status_check.py",
        description="Honest liveness checks for .onion (and clearnet) URLs over Tor: "
                    "one plain GET per target, HTTP code + <title>, circuit controls at the end.",
    )
    p.add_argument("targets", type=Path,
                   help='text file, one target per line: "Name | URL" or just "URL"')
    p.add_argument("--out-dir", type=Path, default=Path("results"),
                   help="where to write the JSON/HTML results (default: ./results)")
    p.add_argument("--proxy", default=DEFAULT_PROXY,
                   help=f"SOCKS proxy URL (default: {DEFAULT_PROXY}; use socks5h so Tor resolves .onion)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                   help=f"seconds per request (default: {DEFAULT_TIMEOUT})")
    p.add_argument("--delay", type=float, nargs=2, metavar=("MIN", "MAX"), default=DEFAULT_DELAY,
                   help=f"random pause between requests, in seconds (default: {DEFAULT_DELAY[0]} {DEFAULT_DELAY[1]})")
    p.add_argument("--no-controls", action="store_true",
                   help="skip the circuit control targets (not recommended)")
    p.add_argument("--no-html", action="store_true", help="write JSON only")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = Config(proxy=args.proxy, timeout=args.timeout, delay=tuple(args.delay))

    if not args.targets.is_file():
        print(f"targets file not found: {args.targets}", file=sys.stderr)
        return 2
    targets = read_targets(args.targets)
    if not targets:
        print(f"no targets found in {args.targets}", file=sys.stderr)
        return 2

    print(f"Checking {len(targets)} URLs via {cfg.proxy} (timeout {cfg.timeout}s)...", file=sys.stderr)

    session = requests.Session()
    session.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    session.headers["User-Agent"] = TOR_BROWSER_UA

    results = []
    for i, (name, uri) in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {name} ({uri})", file=sys.stderr)
        results.append(check_one(name, uri, session, cfg))
        if i < len(targets):
            time.sleep(random.uniform(*cfg.delay))

    controls: list[dict] = []
    if not args.no_controls:
        print("\nMeasuring control targets (circuit validation)...", file=sys.stderr)
        for name, uri in CONTROL_TARGETS:
            controls.append(check_one(name, uri, session, cfg))
            time.sleep(random.uniform(*cfg.delay))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    base = unique_base(args.out_dir, args.targets.stem)

    json_path = args.out_dir / f"{base}.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if controls:
        controls_path = args.out_dir / f"{base}-controls.json"
        controls_path.write_text(json.dumps(controls, ensure_ascii=False, indent=2), encoding="utf-8")
    if not args.no_html:
        html_path = args.out_dir / f"{base}.html"
        write_html_report(results, html_path, controls or None)

    online = [r for r in results if r["status"] == "ONLINE"]
    caveat = [r for r in online if r.get("status_detail", "ONLINE") != "ONLINE"]
    offline = [r for r in results if r["status"] != "ONLINE"]
    exit_code = 0

    print(f"\nDone: {len(online)} online ({len(caveat)} with caveat), {len(offline)} offline.",
          file=sys.stderr)
    for r in caveat:
        print(f"  caveat: {r['name']} — {r.get('status_detail')}", file=sys.stderr)
    if controls:
        ok = sum(1 for c in controls if c["status"] == "ONLINE")
        print(f"Controls: {ok}/{len(controls)} online.", file=sys.stderr)
        if ok < len(controls):
            print("  WARNING: circuit suspect — do NOT record any target as dead "
                  "based on this run.", file=sys.stderr)
            exit_code = 3  # non-zero so cron/CI cannot record a dead batch by mistake
    print(f"JSON: {json_path}", file=sys.stderr)
    if controls:
        print(f"Controls: {controls_path}", file=sys.stderr)
    if not args.no_html:
        print(f"HTML: {html_path}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
