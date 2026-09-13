"""Offline unit tests — no Tor, no network. Run with:  python3 -m unittest -v

They pin the behaviour that makes this tool different from a naive checker:
status semantics, error classification (with the real error strings PySocks
produces), the HTTP/2 second-opinion branch, placeholder handling, output
naming, and HTML escaping in the report.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("osc", ROOT / "onion_status_check.py")
osc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(osc)

CE = requests.exceptions.ConnectionError

# Real error texts as produced by requests + PySocks through a Tor SOCKS proxy.
SOCKS_0x04 = ("SOCKSHTTPConnectionPool(host='x.onion', port=80): Max retries exceeded with url: / "
              "(Caused by NewConnectionError(\"SOCKSConnection(host='x.onion'): "
              "Failed to establish a new connection: 0x04: Host unreachable\"))")
SOCKS_0x01 = SOCKS_0x04.replace("0x04: Host unreachable", "0x01: General SOCKS server failure")
SOCKS_0x05 = SOCKS_0x04.replace("0x04: Host unreachable", "0x05: Connection refused")
SOCKS_0x06 = SOCKS_0x04.replace("0x04: Host unreachable", "0x06: TTL expired")
PROXY_DOWN = ("SOCKSHTTPConnectionPool(host='x.onion', port=80): Max retries exceeded with url: / "
              "(Caused by NewConnectionError('<urllib3.contrib.socks.SOCKSConnection object>: "
              "Failed to establish a new connection: [Errno 111] Connection refused'))")
HTTP2_SIG = "('Connection aborted.', BadStatusLine('\\x00\\x00\\x12\\x04\\x00\\x00\\x00\\x00\\x00'))"


class ErrorClassification(unittest.TestCase):
    def test_socks_codes_on_onion(self):
        self.assertEqual(osc.classify_error(CE(SOCKS_0x04), "http://x.onion/"), "hidden_service_unreachable")
        self.assertEqual(osc.classify_error(CE(SOCKS_0x01), "http://x.onion/"), "invalid_onion_address")
        self.assertEqual(osc.classify_error(CE(SOCKS_0x05), "http://x.onion/"), "connection_refused_by_destination")
        self.assertEqual(osc.classify_error(CE(SOCKS_0x06), "http://x.onion/"), "circuit_failed")

    def test_socks_codes_on_clearnet(self):
        self.assertEqual(osc.classify_error(CE(SOCKS_0x04), "https://example.com/"), "host_unreachable_via_exit")
        self.assertEqual(osc.classify_error(CE(SOCKS_0x01), "https://example.com/"), "socks_general_failure")

    def test_proxy_down_is_not_a_destination_verdict(self):
        # No SOCKS reply code at all: the proxy itself refused the TCP connection.
        self.assertEqual(osc.classify_error(CE(PROXY_DOWN), "http://x.onion/"), "proxy_unreachable")

    def test_proxy_check_does_not_shadow_socks_codes(self):
        # Regression: PySocks wraps every SOCKS reply in the same NewConnectionError
        # text, so the proxy check must not fire when a 0xNN code is present.
        for text in (SOCKS_0x01, SOCKS_0x05, SOCKS_0x06):
            self.assertNotEqual(osc.classify_error(CE(text), "http://x.onion/"), "proxy_unreachable", text)

    def test_other_exceptions(self):
        self.assertEqual(osc.classify_error(requests.exceptions.ConnectTimeout("t")), "timeout")
        self.assertEqual(osc.classify_error(requests.exceptions.ReadTimeout("t")), "timeout")
        self.assertEqual(osc.classify_error(requests.exceptions.SSLError("s")), "tls_failed_even_unverified")
        self.assertEqual(osc.classify_error(CE("reset by peer")), "connection_refused_or_reset")
        self.assertEqual(osc.classify_error(requests.exceptions.RequestException("x")), "request_error")


class StatusLabels(unittest.TestCase):
    def test_any_response_is_online(self):
        F = osc.Fetched
        self.assertEqual(osc.describe_response(F(200, "", "http://x.onion/"), False), "ONLINE")
        self.assertEqual(osc.describe_response(F(200, "", "https://x.onion/"), True), "ONLINE (TLS not verified)")
        for code in sorted(osc.ACCESS_BARRIER_CODES):
            self.assertEqual(osc.describe_response(F(code, "", "http://x/"), False),
                             f"ONLINE (HTTP {code} - access barrier)")
        self.assertEqual(osc.describe_response(F(404, "", "http://x/"), False), "ONLINE (HTTP 404 - missing resource)")
        self.assertEqual(osc.describe_response(F(410, "", "http://x/"), False), "ONLINE (HTTP 410 - missing resource)")
        self.assertEqual(osc.describe_response(F(502, "", "http://x/"), False), "ONLINE (HTTP 502 - server error)")
        self.assertEqual(osc.describe_response(F(418, "", "http://x/"), False), "ONLINE (HTTP 418)")

    def test_http2_suffix(self):
        r = osc.Fetched(200, "", "https://x.onion/", via="curl-http2")
        self.assertEqual(osc.describe_response(r, True), "ONLINE (TLS not verified) [HTTP/2, measured via curl]")
        self.assertEqual(osc.describe_response(osc.Fetched(200, "", "http://x.onion/", via="curl-http2"), False),
                         "ONLINE [HTTP/2, measured via curl]")


class Http2Branch(unittest.TestCase):
    """fetch() must ask curl only when the failure has the HTTP/2 signature."""

    def setUp(self):
        self.cfg = osc.Config(osc.DEFAULT_PROXY, 5, (0, 0))
        self.calls: list[str] = []
        self._orig = osc.fetch_via_curl
        osc.fetch_via_curl = lambda uri, cfg: (self.calls.append(uri) or
                                              osc.Fetched(200, "<title>h2</title>", uri, via="curl-http2"))

    def tearDown(self):
        osc.fetch_via_curl = self._orig

    def test_http2_signature_triggers_curl(self):
        class S:
            def get(self, *a, **k): raise CE(HTTP2_SIG)
        resp, tls = osc.fetch("https://x.onion/", S(), self.cfg)
        self.assertEqual(self.calls, ["https://x.onion/"])
        self.assertEqual(resp.via, "curl-http2")
        self.assertTrue(tls)  # https .onion fetched with verification off

    def test_plain_http_onion_over_http2_is_not_tls(self):
        class S:
            def get(self, *a, **k): raise CE(HTTP2_SIG)
        _, tls = osc.fetch("http://x.onion/", S(), self.cfg)
        self.assertFalse(tls)

    def test_ordinary_failure_does_not_call_curl(self):
        class S:
            def get(self, *a, **k): raise CE(SOCKS_0x04)
        with self.assertRaises(CE):
            osc.fetch("http://x.onion/", S(), self.cfg)
        self.assertEqual(self.calls, [])


class Titles(unittest.TestCase):
    def test_placeholder_detection(self):
        for t in ("Loading...", "Just a moment...", "Please wait", "Checking your browser", "", " "):
            self.assertTrue(osc.looks_like_placeholder(t), t)
        for t in ("Runion — Главная", "Deep Answers", "404 Not Found"):
            self.assertFalse(osc.looks_like_placeholder(t), t)

    def test_is_html_response(self):
        self.assertTrue(osc.is_html_response(osc.Fetched(200, "<form>", "u", content_type="text/html")))
        self.assertFalse(osc.is_html_response(osc.Fetched(200, "{}", "u", content_type="application/json")))
        # no header: fall back to sniffing
        self.assertTrue(osc.is_html_response(osc.Fetched(200, "<html>", "u")))
        self.assertFalse(osc.is_html_response(osc.Fetched(200, "{}", "u")))

    def test_challenge_detection(self):
        for t in ("<legend>Anti-DDoS</legend> Captcha:", "DDoS-Guard", "Prove you are human", "Access Queue"):
            self.assertTrue(osc.looks_like_challenge(t), t)
        self.assertFalse(osc.looks_like_challenge("<html><title>Forum</title>"))

    def test_html_sniff(self):
        self.assertTrue(osc.looks_like_html("<!DOCTYPE html><html>"))
        self.assertTrue(osc.looks_like_html("  <html lang=en>"))
        self.assertFalse(osc.looks_like_html('{"IsTor":true,"IP":"1.2.3.4"}'))
        self.assertFalse(osc.looks_like_html("plain text answer"))

    def test_static_hints(self):
        html = ('<html><head><title>Loading...</title><meta property="og:title" content="Real Title">'
                '<meta name="description" content="desc"><script src="/app.js"></script></head>'
                '<body><script>fetch("/api/v1/items"); window.__NEXT_DATA__={}</script></body></html>')
        h = osc.extract_static_hints(html, BeautifulSoup(html, "html.parser"))
        self.assertEqual(h["meta_title"], "Real Title")
        self.assertEqual(h["meta_description"], "desc")
        self.assertIn("/api/v1/items", h["api_hints"])
        self.assertIn("__NEXT_DATA__", h["spa_state_markers"])
        self.assertIn("/app.js", h["script_srcs"])


class CheckOneOffline(unittest.TestCase):
    """check_one() end to end with a fake session — the record shape."""

    def setUp(self):
        self.cfg = osc.Config(osc.DEFAULT_PROXY, 5, (0, 0))

    def _session(self, status=200, text="", url="http://x.onion/", exc=None):
        class R:
            status_code = status
            headers: dict = {}
        R.text, R.url = text, url

        class S:
            def get(self, *a, **k):
                if exc: raise exc
                return R()
        return S()

    def test_online_html(self):
        r = osc.check_one("n", "http://x.onion/", self._session(text="<html><title>Hi</title></html>"), self.cfg)
        self.assertEqual((r["status"], r["http_code"], r["title"], r["title_source"], r["needs_js_rendering"]),
                         ("ONLINE", 200, "Hi", "html_title", False))

    def test_content_type_beats_sniff(self):
        # An HTML fragment with no <html>/<title>: the server said text/html, so it IS html.
        frag = '<form class="voting-form" action="" method="POST"><fieldset><legend>Anti-DDoS</legend>' \
               '<label>Captcha: <b>5 + 1 = </b></label><input type="number" name="a"></fieldset></form>'
        class R:
            status_code, text, url = 200, frag, "http://x.onion/"
            headers = {"Content-Type": "text/html; charset=UTF-8"}
        class S:
            def get(self, *a, **k): return R()
        r = osc.check_one("n", "http://x.onion/", S(), self.cfg)
        self.assertEqual(r["content_type"], "text/html; charset=UTF-8")
        self.assertEqual(r["title_source"], "challenge_page")
        self.assertEqual(r["status_detail"], "ONLINE (challenge page)")
        self.assertFalse(r["needs_js_rendering"])

    def test_challenge_with_placeholder_title(self):
        html = "<html><head><title>Just a moment...</title></head><body>Checking your browser (DDoS-Guard)</body></html>"
        r = osc.check_one("n", "http://x.onion/", self._session(text=html), self.cfg)
        self.assertEqual(r["title_source"], "challenge_page")
        self.assertFalse(r["needs_js_rendering"])

    def test_challenge_in_real_title(self):
        # A real, non-placeholder title that itself names the wall (seen on markets).
        html = "<html><head><title>Some Market Access Queue</title></head><body>please wait</body></html>"
        r = osc.check_one("n", "http://x.onion/", self._session(text=html), self.cfg)
        self.assertEqual((r["title"], r["title_source"], r["status_detail"]),
                         ("Some Market Access Queue", "challenge_page", "ONLINE (challenge page)"))

    def test_real_title_is_not_a_challenge(self):
        # The word "captcha" in a normal page body must not override a real title.
        html = "<html><head><title>Forum Home</title></head><body>Register (captcha required)</body></html>"
        r = osc.check_one("n", "http://x.onion/", self._session(text=html), self.cfg)
        self.assertEqual((r["title"], r["title_source"], r["status_detail"]), ("Forum Home", "html_title", "ONLINE"))

    def test_online_not_html(self):
        r = osc.check_one("n", "https://x/", self._session(text='{"IsTor":true}', url="https://x/"), self.cfg)
        self.assertEqual(r["title_source"], "not_html")
        self.assertFalse(r["needs_js_rendering"])

    def test_online_placeholder_with_meta(self):
        html = '<html><head><title>Loading...</title><meta property="og:title" content="Real"></head></html>'
        r = osc.check_one("n", "http://x.onion/", self._session(text=html), self.cfg)
        self.assertEqual((r["title"], r["title_source"], r["needs_js_rendering"]), ("Real", "meta_tag", False))

    def test_online_placeholder_without_meta(self):
        r = osc.check_one("n", "http://x.onion/", self._session(text="<html><title>Loading...</title></html>"), self.cfg)
        self.assertEqual(r["title_source"], "html_title_placeholder")
        self.assertTrue(r["needs_js_rendering"])
        self.assertIn("static_hints", r)

    def test_offline_record(self):
        r = osc.check_one("n", "http://x.onion/", self._session(exc=CE(SOCKS_0x04)), self.cfg)
        self.assertEqual((r["status"], r["status_detail"], r["http_code"], r["title"], r["error_class"]),
                         ("OFFLINE", "OFFLINE", None, None, "hidden_service_unreachable"))
        self.assertLessEqual(len(r["error"]), 200)


class TargetsAndOutput(unittest.TestCase):
    def test_read_targets(self):
        d = Path(tempfile.mkdtemp())
        f = d / "t.txt"
        f.write_text("# comment\n\nA | http://a.onion/\nhttps://b.example/\nfile:///etc/passwd\nC | ftp://c\n")
        self.assertEqual(osc.read_targets(f),
                         [("A", "http://a.onion/"), ("https://b.example/", "https://b.example/")])

    def test_unique_base_never_overwrites(self):
        d = Path(tempfile.mkdtemp())
        b1 = osc.unique_base(d, "t")
        (d / f"{b1}.json").write_text("")
        b2 = osc.unique_base(d, "t")
        self.assertEqual(b2, b1 + "-2")
        (d / f"{b2}.json").write_text("")
        self.assertEqual(osc.unique_base(d, "t"), b1 + "-3")

    def test_report_escapes_html(self):
        d = Path(tempfile.mkdtemp())
        out = d / "r.html"
        osc.write_html_report([{"name": "<script>alert(1)</script>", "uri": "http://x.onion/\"><img>",
                                "status": "ONLINE", "status_detail": "ONLINE", "title": "<b>t</b>",
                                "title_source": "html_title", "needs_js_rendering": False}], out, None)
        html = out.read_text()
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('<img>', html)

    def test_main_exit_codes_for_input_errors(self):
        self.assertEqual(osc.main(["/definitely/not/here.txt"]), 2)
        d = Path(tempfile.mkdtemp())
        f = d / "empty.txt"
        f.write_text("# nothing\n")
        self.assertEqual(osc.main([str(f)]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
