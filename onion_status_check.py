#!/usr/bin/env python3
"""
onion-status-check — is it up, and who already lists it?

For each target: ONE plain HTTP GET through the local Tor SOCKS proxy, then
the status code and the page <title>. No JavaScript, no images, no forms, no
login, no crawling. Optionally, every target is also looked up in a set of
index sources (curated lists, crawler lists, local catalogs) to say who
already lists that address or that name.

The full explanation — why a naive checker lies, what every label and error
class means, how index matching works, exit codes — lives in README.md. What
follows is the part a reader of the source needs.

Status semantics
    ANY HTTP response means ONLINE; only silence is OFFLINE. The nuance goes
    into "status_detail" (TLS not verified, access barrier, challenge page,
    missing resource, server error, HTTP/2 via curl) and, for OFFLINE, into
    "error_class" (see classify_error).

Three false-OFFLINE traps this file exists to avoid
    1. TLS: a .onion address already IS the public key, so chain verification
       is off for .onion by policy and the label says so. Clearnet is verified,
       and retried unverified only when the handshake fails.
    2. HTTP >= 400: a 403 from a WAF or a login wall is a living server.
    3. HTTP/2-only servers: `requests` speaks HTTP/1.1; when the failure has the
       HTTP/2 signature — and only then — `curl --http2` gives a second opinion.

Circuit controls
    Every run ends by measuring known-good targets. If they fail, nothing from
    the run may be recorded as dead (exit 3). Index sources that fail to load
    have the same effect on "unlisted".

Usage
    python3 onion_status_check.py targets.txt [--indices sources.txt] [--catalog PATH]
                                              [--indices-only] [--out-dir DIR] ...
    targets.txt: one per line, "Name | URL" or just "URL"; '#' comments.
    sources.txt: one per line, "Name | URL-or-path"; '#' comments.

Exit status
    0  run completed and every control answered (or --no-controls)
    3  run completed but a control or an index source failed — do not trust
       negatives from this run
    2  usage error
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

__version__ = "0.2.0"  # also read by pyproject.toml; keep CHANGELOG.md in step

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
# Index cross-check (optional): who already lists this target?
# --------------------------------------------------------------------------- #

MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
ONION_RE = re.compile(r"\b([a-z2-7]{56}\.onion)\b")
# Words that name the *kind* of thing, not the thing — dropped before comparing
# names so that "XSS (Deep)" and "XSS forum" still meet.
NAME_NOISE_RE = re.compile(
    r"\b(market(place)?|forum(s)?|shop(s)?|store|onion|mirror(s)?|link(s)?|official|"
    r"deep|dark|surface|clearnet|tor|v2|v3|site|the|project|blog|team|group|club|"
    r"service(s)?|network|online|new|old|home|page|index|directory|leaked)\b|\(.*?\)",
    re.IGNORECASE,
)


# Keys that are a generic word on their own once the noise is gone. "Onion
# Search" and "Deep Search" both collapse to "search" — that is not a match.
GENERIC_KEYS = {"search", "searchengine", "engine", "hidden", "wiki", "hiddenwiki", "news", "mail",
                "chat", "index", "directory", "home", "answers", "questions", "leaks", "leak",
                "dump", "dumps", "data", "database", "databases", "underground", "anonymous",
                "community", "hub", "club", "team", "group", "project", "service", "services",
                "escrow", "vendor", "vendors", "verified", "trusted", "best", "free", "secure",
                # topic words of this domain: they describe a category, not a site
                "darknet", "darkweb", "deepweb", "carding", "cards", "exploit", "exploits",
                "phishing", "ransomware", "hacking", "hacked", "hacker", "hackers", "bitcoin",
                "crypto", "monero", "center", "centre", "guns", "drugs", "weed", "list", "lists",
                "login", "entering", "welcome", "premium", "private", "global",
                # nationalities and languages name a region, not a site
                "russian", "german", "french", "turkish", "polish", "italian", "spanish", "chinese",
                "brazilian", "english", "american", "european", "arabic", "japanese", "korean"}


def _words(text: str) -> list[str]:
    """Lowercase alphanumeric words, with a light plural fold so that
    'LEAK FORUMS' and 'Leak Forum' meet: a trailing 's' after a consonant is
    dropped from words of five or more letters ('forums', 'leaks' — but not
    'nexus', 'anubis', 'osiris', 'abacus', 'kairos')."""
    out = []
    for w in re.findall(r"[a-z0-9]+", text.lower()):
        if len(w) >= 5 and w.endswith("s") and w[-2] not in "aeious":
            w = w[:-1]
        out.append(w)
    return out


def normalize_name(name: str) -> str:
    """Lowercase, drop kind-words and punctuation: 'XSSF (Dark)' -> 'xssf'."""
    return "".join(_words(NAME_NOISE_RE.sub(" ", name)))


def name_keys(name: str) -> list[str]:
    """Both the noise-stripped key and the plain compact key, minus generic
    words: 'Find Tor' -> ['find', 'findtor'] so it still meets 'FindTor'."""
    keys = []
    for k in (normalize_name(name), "".join(_words(name))):
        if len(k) >= 4 and k not in GENERIC_KEYS and k not in keys:
            keys.append(k)
    return keys


def name_words(name: str) -> frozenset[str]:
    """The meaningful words of a name: noise and generic words removed, 4+
    letters each. 'Cracking Island' -> {'cracking', 'island'}."""
    return frozenset(w for w in _words(NAME_NOISE_RE.sub(" ", name))
                     if len(w) >= 4 and w not in GENERIC_KEYS)


def first_segment(name: str) -> str:
    """'Nexus Market - Escrow Marketplace' -> 'Nexus Market'. A page title or
    a long label usually starts with the site's own name."""
    return re.split(r"\s[-|–—:]\s|\s\|\s|\s{2,}", name.strip())[0]


def names_match(a_keys: list[str], a_words: frozenset[str], b_keys: list[str], b_words: frozenset[str]) -> bool:
    """Same name after normalization, or one name's meaningful words are all
    whole words of the other (with at least one word of 5+ letters, so a
    single short word never carries a match). Substring containment is
    deliberately NOT used: 'trustmarket' contains 'stmarket', and a long
    title contains all sorts of listed words."""
    if set(a_keys) & set(b_keys):
        return True
    if not a_words or not b_words:
        return False
    small, big = (a_words, b_words) if len(a_words) <= len(b_words) else (b_words, a_words)
    if not small <= big:
        return False
    # One shared word carries a match only if it is long enough to be a name
    # ("lockbit", "atomsilo", "hacktown"), never a short common word.
    return len(small) >= 2 or any(len(w) >= 7 for w in small)


def host_of(uri: str) -> str:
    """Hostname of a URL, lowercased, without a leading "www.". Never raises:
    a hand-edited catalog contains malformed URLs, and one of them must not
    abort the whole load — it just yields no host."""
    try:
        host = (urlparse(uri if "://" in uri else "http://" + uri).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


HTML_LINK_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


class Source:
    """One index of onion addresses: a local file/tree or a remote page.

    Anything that lists addresses works as a source — a curated index such as
    dark.fail or tor.taxi, Ahmia's public onion list, a blog post, a saved
    forum thread, a markdown catalog like deepdarkCTI, your own bookmarks.
    The loader understands markdown links, HTML anchors and bare v3 addresses
    (labeled by the text on the same line), and never decides anything: it
    only remembers who lists what.
    """

    def __init__(self, name: str, origin: str):
        self.name = name
        self.origin = origin
        self.hosts: dict[str, list[dict]] = {}
        self.named: list[tuple[list[str], frozenset[str], dict]] = []
        self.files = 0
        self.error: str | None = None

    @property
    def names(self) -> int:
        return len(self.named)

    @property
    def is_remote(self) -> bool:
        return self.origin.startswith(("http://", "https://"))

    # -- loading -----------------------------------------------------------
    def load_local(self) -> None:
        root = Path(self.origin).expanduser()
        if not root.exists():
            self.error = "path not found"
            return
        files = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in (".md", ".txt", ".html", ".htm", ".csv")
            and ".git" not in p.parts)
        for f in files:
            self.files += 1
            rel = str(f.relative_to(root)) if root.is_dir() else f.name
            self._ingest(f.read_text(encoding="utf-8", errors="replace"), rel)

    def load_remote(self, session: requests.Session, cfg: "Config") -> None:
        try:
            resp, _ = fetch(self.origin, session, cfg)
        except requests.exceptions.RequestException as e:
            self.error = classify_error(e, self.origin)
            return
        if resp.status_code >= 400:
            self.error = f"HTTP {resp.status_code}"
            return
        self.files = 1
        self._ingest(resp.text, host_of(self.origin))
        if not self.hosts:
            # A 200 with no addresses in it is a source that changed shape (or
            # a challenge page) — not "nobody is listed". Say so, loudly.
            self.error = "loaded but no addresses found — page format changed?"

    def _ingest(self, text: str, where: str) -> None:
        # HTML anchors first (remote pages), then markdown links, then bare
        # addresses labeled by the visible text of their line. Block-level
        # tags count as line breaks, so a one-line HTML page still yields one
        # label per entry.
        if "<" in text:
            text = re.sub(r"(?i)</?(p|br|li|div|h[1-6]|tr|td|th|section|article)\b[^>]*>", "\n", text)
        for lineno, line in enumerate(text.splitlines(), 1):
            seen_hosts: set[str] = set()
            for url, inner in HTML_LINK_RE.findall(line):
                name = TAG_RE.sub("", inner).strip()
                self._add(name, host_of(url), where, lineno, seen_hosts)
            for name, url in MD_LINK_RE.findall(line):
                self._add(name.strip(), host_of(url), where, lineno, seen_hosts)
            label = TAG_RE.sub(" ", ONION_RE.sub(" ", line))
            label = re.sub(r"https?://\S*|\s+", " ", label).strip(" |:-–—")[:80]
            for onion in ONION_RE.findall(line):
                self._add(label, onion, where, lineno, seen_hosts)

    def _add(self, name: str, host: str, where: str, lineno: int, seen: set[str]) -> None:
        if not host or host in seen:
            return
        seen.add(host)
        entry = {"source": self.name, "name": name, "host": host, "where": where, "line": lineno}
        self.hosts.setdefault(host, []).append(entry)
        keys, words = name_keys(name), name_words(name)
        if keys or words:
            self.named.append((keys, words, entry))

    # -- lookup ------------------------------------------------------------
    def lookup(self, host: str, candidates: list[tuple[list[str], frozenset[str]]]) -> tuple[list[dict], list[dict]]:
        listed = self.hosts.get(host, [])[:5]
        name_matches: list[dict] = []
        if not listed:
            for t_keys, t_words in candidates:
                for c_keys, c_words, e in self.named:
                    if e not in name_matches and names_match(t_keys, t_words, c_keys, c_words):
                        name_matches.append(e)
        return listed, name_matches[:5]


def read_sources(path: Path) -> list[Source]:
    """One source per line: "Name | URL-or-path" (or just the URL/path).
    Lines starting with "#" are ignored."""
    sources = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            name, origin = (p.strip() for p in line.split("|", 1))
        else:
            name = origin = line
        sources.append(Source(name, origin))
    return sources


class Indices:
    """All sources of a run, loaded once, queried per target."""

    def __init__(self, sources: list[Source]):
        self.sources = sources

    def load(self, session: requests.Session | None, cfg: "Config | None") -> None:
        for src in self.sources:
            if src.is_remote:
                if session is None or cfg is None:
                    src.error = "no session"
                else:
                    src.load_remote(session, cfg)
            else:
                src.load_local()

    def lookup(self, uri: str, label: str = "", title: str = "") -> dict:
        host = host_of(uri)
        candidates: list[tuple[list[str], frozenset[str]]] = []
        for text in (label if label and host_of(label) != host else "", title):
            if text:  # a label that is just the URL says nothing
                seg = first_segment(text)
                candidates.append((name_keys(seg), name_words(seg)))
        listed_in: list[dict] = []
        name_matches: list[dict] = []
        failed = [s.name for s in self.sources if s.error]
        for src in self.sources:
            if src.error:
                continue
            l, n = src.lookup(host, candidates)
            listed_in += l
            name_matches += n
        verdict = "listed" if listed_in else ("name-match" if name_matches else "unlisted")
        return {"verdict": verdict, "listed_in": listed_in, "name_matches": name_matches,
                "sources_failed": failed}


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
        elif looks_like_challenge(title) or (
                looks_like_challenge(resp.text) and (not title or looks_like_placeholder(title))):
            # Either the title itself says so ("... Access Queue"), or the body
            # does and there is no real title to contradict it.
            # Captcha / anti-DDoS / queue wall with a 2xx: the server is up and
            # is gating access. Label it as such instead of blaming JavaScript.
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

    css = ("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:960px;"
           "margin:2rem auto;padding:0 1rem;color:#1f2328;line-height:1.5}"
           "h1{font-size:1.15rem;border-bottom:1px solid #d0d7de;padding-bottom:.3rem;margin-top:2rem}"
           "ol,ul{padding-left:1.4rem}li{margin:.35rem 0;word-break:break-all}"
           "a{color:#0969da}code,.lbl{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}"
           ".lbl{background:#fff8c5;border-radius:4px;padding:0 .3em}"
           ".ok{color:#1a7f37}.warn{color:#9a6700}.bad{color:#cf222e}.dim{color:#656d76}"
           ".src{background:#ddf4ff;border-radius:4px;padding:0 .3em}")
    lines = ["<!doctype html><html><head><meta charset='utf-8'>"
             "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>onion-status-check report</title><style>{css}</style></head><body>",
             f"<p class='dim'>onion-status-check — {len(results)} target(s)</p>"]

    def cat_note(r: dict) -> str:
        ix = r.get("indices")
        if not ix:
            return ""
        if ix["verdict"] == "listed":
            who = " ".join(f"<span class='src'>{_esc(m)}</span>" for m in sorted({m["source"] for m in ix["listed_in"]}))
            return f" — <b>listed by</b> {who}"
        if ix["verdict"] == "name-match":
            names = ", ".join(f"<span class='src'>{_esc(m['source'])}</span> {_esc(m['name'])}" for m in ix["name_matches"][:3])
            return f" — <b>name-match</b> {names}"
        return " — <span class='dim'>unlisted</span>"

    lines.append(f"<h1>Online, title resolved ({len(resolved)})</h1><ol>")
    for r in resolved:
        title = r.get("title") or "(no title)"
        note = " [via meta tag, not &lt;title&gt;]" if r.get("title_source") == "meta_tag" else ""
        lines.append(f"<li><a href='{_esc(r['uri'])}' target='_blank'>{_esc(title)}</a>{note}"
                     f" — target: {_esc(r['name'])}{cat_note(r)}</li>")
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
        lines.append(f"<li><span class='lbl warn'>{_esc(r.get('status_detail', ''))}</span> {_esc(r['name'])} — "
                     f"{_esc(r['uri'])} — title: \"{_esc(title)}\"{cat_note(r)}</li>")
    lines.append("</ol>")

    lines.append(f"<h1>Offline ({len(offline)})</h1><p>No response at all.</p><ol>")
    for r in offline:
        detail = r.get("error_class") or r.get("error") or "no detail"
        lines.append(f"<li><span class='lbl bad'>{_esc(detail)}</span> {_esc(r['name'])} — {_esc(r['uri'])}</li>")
    lines.append("</ol>")

    if controls:
        ok = sum(1 for c in controls if c["status"] == "ONLINE")
        verdict = ("<span class='ok'>Tor circuit validated</span>" if ok == len(controls)
                   else "<b class='bad'>CIRCUIT SUSPECT — do not record anything as dead from this run</b>")
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
        description="Is it up, and who already lists it? One plain GET per .onion/clearnet target "
                    "through Tor (status code + <title>, circuit controls at the end), plus an optional "
                    "cross-check against any index sources you name. Details: README.md",
        epilog='targets file: one per line, "Name | URL" or just "URL". '
               'sources file (--indices): one per line, "Name | URL-or-path". '
               'Lines starting with # are ignored.',
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    p.add_argument("--indices", type=Path, metavar="FILE",
                   help='sources list, one per line "Name | URL-or-path" — see the Index cross-check section')
    p.add_argument("--catalog", type=Path, nargs="+", metavar="PATH",
                   help="add a local file or directory tree as an index source (shortcut for a path line in --indices)")
    p.add_argument("--indices-only", action="store_true",
                   help="cross-check only; measure no target (remote indices are still fetched once)")
    return p.parse_args(argv)


def print_indices_summary(indices: "Indices", results: list[dict]) -> None:
    for src in indices.sources:
        if src.error:
            print(f"  source {src.name}: FAILED ({src.error}) — 'unlisted' is unreliable this run",
                  file=sys.stderr)
    counts = {"listed": 0, "name-match": 0, "unlisted": 0}
    for r in results:
        counts[r["indices"]["verdict"]] += 1
    print(f"Indices: {counts['listed']} listed, {counts['name-match']} name-match, "
          f"{counts['unlisted']} unlisted.", file=sys.stderr)
    for r in results:
        ix = r["indices"]
        if ix["verdict"] == "listed":
            who = ", ".join(sorted({m["source"] for m in ix["listed_in"]}))
            print(f"  listed: {r['name']} -> {who}", file=sys.stderr)
        elif ix["verdict"] == "name-match":
            hits = "; ".join(f"{m['source']}: {m['name']} <{m['host'][:24]}…>" for m in ix["name_matches"][:3])
            print(f"  name-match: {r['name']} -> {hits}", file=sys.stderr)


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

    sources: list[Source] = []
    if args.indices:
        if not args.indices.is_file():
            print(f"indices file not found: {args.indices}", file=sys.stderr)
            return 2
        sources += read_sources(args.indices)
    for path in args.catalog or []:
        sources.append(Source(str(path), str(path)))
    if args.indices_only and not sources:
        print("--indices-only needs --indices and/or --catalog", file=sys.stderr)
        return 2
    indices: Indices | None = Indices(sources) if sources else None

    session = requests.Session()
    session.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    session.headers["User-Agent"] = TOR_BROWSER_UA

    if indices is not None:
        remote = sum(1 for s in sources if s.is_remote)
        print(f"Loading {len(sources)} index source(s) ({remote} remote, via {cfg.proxy})...", file=sys.stderr)
        indices.load(session, cfg)
        for src in sources:
            print(f"  {src.name}: " + (f"FAILED ({src.error})" if src.error else
                  f"{len(src.hosts)} hosts, {src.names} named entries, {src.files} file(s)"), file=sys.stderr)

    if args.indices_only:
        assert indices is not None
        results = [{"name": name, "uri": uri, "indices": indices.lookup(uri, label=name)}
                   for name, uri in targets]
        args.out_dir.mkdir(parents=True, exist_ok=True)
        base = unique_base(args.out_dir, args.targets.stem + "-indices")
        json_path = args.out_dir / f"{base}.json"
        json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print_indices_summary(indices, results)
        print(f"JSON: {json_path}", file=sys.stderr)
        return 3 if any(s.error for s in sources) else 0

    print(f"Checking {len(targets)} URLs via {cfg.proxy} (timeout {cfg.timeout}s)...", file=sys.stderr)

    results = []
    for i, (name, uri) in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {name} ({uri})", file=sys.stderr)
        r = check_one(name, uri, session, cfg)
        if indices is not None:
            r["indices"] = indices.lookup(uri, label=name, title=r.get("title") or "")
        results.append(r)
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
    if indices is not None:
        print_indices_summary(indices, results)
        if any(src.error for src in indices.sources):
            exit_code = 3
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
