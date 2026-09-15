"""Offline unit tests — no Tor, no network. Run with:  python3 -m unittest -v

They pin the behaviour that makes this tool different from a naive checker:
status semantics, error classification (with the real error strings PySocks
produces), the HTTP/2 second-opinion branch, placeholder handling, output
naming, and HTML escaping in the report.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("osc", ROOT / "nullius.py")
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
        r = osc.check_one("n", "http://x.onion/", self._session(text="<html><title>Ahmia —\n   Search Tor\n</title></html>"), self.cfg)
        self.assertEqual(r["title"], "Ahmia — Search Tor")  # whitespace collapsed, as a browser renders it

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


class IndexCrossCheck(unittest.TestCase):
    """--indices / --catalog: who lists this host, by exact host or by name."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "forum.md").write_text(
            "| Name | Status |\n| --- | --- |\n"
            "| [XSSF (Dark)](http://xssfnet2env65wnrlixkn4io3gzukirz7w767gdilk64iq6dg33jwsad.onion/) | ONLINE |\n"
            "| [DARK FAIL](https://dark.fail) | ONLINE |\n"
            "| [RUNION](http://runionv3do7jdylpx7ufc6qkmygehsiuichjcstpj4hb2ycqrnmp67ad.onion) | ONLINE |\n"
            "bare address on a line: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion\n")
        (self.d / "sub").mkdir()
        (self.d / "sub" / "markets.md").write_text("|[Digital Den](http://ddenjrrcjmltjgidxbtqrqbnyhunhlo4dhb6oiy63n4sk6ekzg5aodqd.onion)| ONLINE | |\n")
        (self.d / ".git").mkdir()
        (self.d / ".git" / "ignored.md").write_text("[SHOULD NOT LOAD](http://ignoredignoredignoredignoredignoredignoredignoredignoredxx.onion)\n")
        self.local = osc.Source("local", str(self.d))
        self.local.load_local()

    def _indices(self, *sources):
        ix = osc.Indices(list(sources))
        return ix

    def test_local_loads_links_and_bare_addresses_recursively_skipping_git(self):
        self.assertEqual(self.local.files, 2)
        self.assertIn("dark.fail", self.local.hosts)
        self.assertIn("ddenjrrcjmltjgidxbtqrqbnyhunhlo4dhb6oiy63n4sk6ekzg5aodqd.onion", self.local.hosts)
        self.assertIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion", self.local.hosts)
        self.assertNotIn("ignoredignoredignoredignoredignoredignoredignoredignoredxx.onion", self.local.hosts)
        self.assertEqual(self.local.hosts["runionv3do7jdylpx7ufc6qkmygehsiuichjcstpj4hb2ycqrnmp67ad.onion"][0]["line"], 5)

    def test_malformed_url_does_not_abort(self):
        (self.d / "bad.md").write_text("[BAD](http://[garbage/) and [OK](http://okhost.example/)\n")
        src = osc.Source("l", str(self.d)); src.load_local()
        self.assertIn("okhost.example", src.hosts)
        self.assertEqual(osc.host_of("http://[garbage/"), "")

    def test_missing_local_path_is_a_failed_source(self):
        src = osc.Source("nope", str(self.d / "nope")); src.load_local()
        self.assertEqual(src.error, "path not found")

    def test_remote_html_source_via_fake_session(self):
        html = ('<html><body><h3>Dread</h3><a href="http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion">'
                'dreadyto…</a><p>VormWeb <code>volkancfgpi4c7ghph6id2t7vcntenuly66qjt6oedwtjmyj4tkk5oqd.onion</code></p></body></html>')
        class R:
            status_code, text, url = 200, html, "https://index.example/"
            headers = {"Content-Type": "text/html"}
        class S:
            def get(self, *a, **k): return R()
        src = osc.Source("idx", "https://index.example/")
        src.load_remote(S(), osc.Config(osc.DEFAULT_PROXY, 5, (0, 0)))
        self.assertIsNone(src.error)
        self.assertIn("dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion", src.hosts)
        bare = src.hosts["volkancfgpi4c7ghph6id2t7vcntenuly66qjt6oedwtjmyj4tkk5oqd.onion"][0]
        self.assertEqual(bare["name"], "VormWeb")  # labeled by the visible text of its line

    def test_remote_200_without_addresses_is_a_failed_source(self):
        class R:
            status_code, text, url = 200, "<html><body>We redesigned! <a href='/about'>About</a></body></html>", "https://index.example/"
            headers = {"Content-Type": "text/html"}
        class S:
            def get(self, *a, **k): return R()
        src = osc.Source("idx", "https://index.example/")
        src.load_remote(S(), osc.Config(osc.DEFAULT_PROXY, 5, (0, 0)))
        self.assertIn("no addresses found", src.error or "")

    def test_remote_failure_marks_source_and_verdict_unreliable(self):
        class S:
            def get(self, *a, **k): raise CE(SOCKS_0x04)
        src = osc.Source("down", "http://downdowndowndowndowndowndowndowndowndowndowndowndowndown.onion/")
        src.load_remote(S(), osc.Config(osc.DEFAULT_PROXY, 5, (0, 0)))
        self.assertEqual(src.error, "hidden_service_unreachable")
        ix = self._indices(src, self.local)
        r = ix.lookup("http://example.org/", label="Nobody")
        self.assertEqual(r["verdict"], "unlisted")
        self.assertEqual(r["sources_failed"], ["down"])

    def test_listed_by_exact_host(self):
        ix = self._indices(self.local)
        r = ix.lookup("http://runionv3do7jdylpx7ufc6qkmygehsiuichjcstpj4hb2ycqrnmp67ad.onion/some/path")
        self.assertEqual(r["verdict"], "listed")
        self.assertEqual(r["listed_in"][0]["source"], "local")
        self.assertEqual(ix.lookup("https://www.dark.fail/")["verdict"], "listed")  # www. stripped

    def test_name_match_from_label_and_from_title(self):
        ix = self._indices(self.local)
        r = ix.lookup("http://xssfnet2env25nv16wnqn3vik4igq3igq3igq767igdik6jsad.onion", label="XSSF (Deep)")
        self.assertEqual((r["verdict"], r["name_matches"][0]["name"]), ("name-match", "XSSF (Dark)"))
        r = ix.lookup("http://ddenupaqxuvvilo4yetjv3qbq7p45vqbrr7vd2fmorjglh5bk7uh73id.onion",
                      label="", title="Digital Den - best digital goods")
        self.assertEqual((r["verdict"], r["name_matches"][0]["where"]), ("name-match", "sub/markets.md"))

    def test_label_that_is_just_the_url_does_not_match(self):
        u = "http://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion/"
        self.assertEqual(self._indices(self.local).lookup(u, label=u)["verdict"], "unlisted")

    def test_shared_common_word_is_not_a_match(self):
        (self.d / "m.md").write_text("[Russian Market (Deep)](https://russianmarket.gs)\n"
                                     "[HIDDEN LINKS](http://wclekwrf2aclunlmuikf2bopusjfv66jlhwtgbiycy5nw524r6ngioid.onion)\n"
                                     "[Deep Search](http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion)\n"
                                     "[FindTor](http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/)\n")
        src = osc.Source("l", str(self.d)); src.load_local(); ix = self._indices(src)
        self.assertEqual(ix.lookup("http://commudazrdyhbullltfdy222krfjhoqzizks5ejmocpft3ijtxq5khqd.onion", label="Russian Community")["verdict"], "unlisted")
        self.assertEqual(ix.lookup("http://hiddenwep33eg4w225lcdwcez4iefacwpiia6cwg7pfmcz4hvijzbgid.onion", label="Hidden Wiki")["verdict"], "unlisted")
        self.assertEqual(ix.lookup("http://luciferpvnfmqku7agzmcdoskor536za5574qtyx2vhrnuozv5fla6ad.onion", label="Onion Search")["verdict"], "unlisted")
        r = ix.lookup("http://findtorrstubj7z4ax7wuhfx5dhy4iekiew6ljjk7bl2h7q2j7oulxyd.onion", label="Find Tor")
        self.assertEqual((r["verdict"], r["name_matches"][0]["name"]), ("name-match", "FindTor"))

    def test_normalize_name(self):
        self.assertEqual(osc.normalize_name("XSSF (Dark)"), "xssf")
        self.assertEqual(osc.normalize_name("Nexus Market"), "nexus")
        self.assertEqual(osc.normalize_name("LEAK FORUMS"), "leak")
        self.assertEqual(osc.name_keys("LEAK FORUMS"), osc.name_keys("Leak Forum"))  # plural folded, "leak" alone is generic
        self.assertTrue(osc.names_match(osc.name_keys("LEAK FORUMS"), osc.name_words("LEAK FORUMS"),
                                        osc.name_keys("Leak Forum"), osc.name_words("Leak Forum")))
        self.assertFalse(osc.names_match(osc.name_keys("Bitcoin Miner"), osc.name_words("Bitcoin Miner"),
                                         osc.name_keys("Bitcoin Market"), osc.name_words("Bitcoin Market")))
        self.assertEqual(osc.name_keys("Find Tor"), ["find", "findtor"])
        self.assertEqual(osc.name_keys("Onion Search"), ["onionsearch"])  # "search" alone is generic; the compact form is a name

    def test_read_sources(self):
        f = self.d / "sources.txt"
        f.write_text("# c\ndark.fail | https://dark.fail/\n/some/local/path\n")
        srcs = osc.read_sources(f)
        self.assertEqual([(s.name, s.origin, s.is_remote) for s in srcs],
                         [("dark.fail", "https://dark.fail/", True), ("/some/local/path", "/some/local/path", False)])

    def test_indices_only_main_with_catalog_shortcut(self):
        t = self.d / "targets.txt"
        t.write_text("XSSF (Deep) | http://xssfnet2env25nv16wnqn3vik4igq3igq3igq767igdik6jsad.onion\n"
                     "https://dark.fail/\nNobody | http://example.org/\n")
        out = self.d / "out"
        self.assertEqual(osc.main([str(t), "--catalog", str(self.d), "--indices-only", "--out-dir", str(out)]), 0)
        f = next(out.glob("targets-indices-*.json"))
        verdicts = [r["indices"]["verdict"] for r in json.loads(f.read_text())]
        self.assertEqual(verdicts, ["name-match", "listed", "unlisted"])

    def test_indices_only_exit_3_when_a_source_failed(self):
        t = self.d / "t3.txt"; t.write_text("http://example.org/\n")
        out = self.d / "out3"
        self.assertEqual(osc.main([str(t), "--catalog", str(self.d / "nope"), "--indices-only", "--out-dir", str(out)]), 3)

    def test_indices_only_requires_a_source(self):
        t = self.d / "t2.txt"; t.write_text("http://example.org/\n")
        self.assertEqual(osc.main([str(t), "--indices-only"]), 2)
        self.assertEqual(osc.main([str(t), "--indices", str(self.d / "missing.txt")]), 2)


class DiffBetweenRuns(unittest.TestCase):
    @staticmethod
    def rec(name, uri, status="ONLINE", **kw):
        r = {"name": name, "uri": uri, "checked_at": "2026-09-13T20:00:00+00:00", "status": status,
             "status_detail": "ONLINE" if status == "ONLINE" else "OFFLINE",
             "http_code": 200 if status == "ONLINE" else None,
             "title": "T" if status == "ONLINE" else None, "title_source": "html_title"}
        if status == "OFFLINE":
            r["error_class"] = "timeout"
        r.update(kw)
        return r

    @staticmethod
    def mkrun(records, controls=None, file="x.json"):
        return {"file": file, "targets": len(records), "checked_at": records[0]["checked_at"] if records else None,
                "controls": controls, "records": records}

    def test_record_key_normalizes_identity(self):
        k = osc.record_key
        self.assertEqual(k("http://ABC.onion/"), k("http://abc.onion"))
        self.assertEqual(k("https://x.example/a/#frag"), k("https://x.example/a"))
        self.assertNotEqual(k("http://a.onion/x"), k("http://a.onion/y"))
        self.assertNotEqual(k("http://a.onion/?q=1"), k("http://a.onion/"))
        self.assertNotEqual(k("http://a.onion/"), k("https://a.onion/"))

    def test_transitions(self):
        old = self.mkrun([self.rec("A", "http://a.onion/"), self.rec("B", "http://b.onion/", "OFFLINE"),
                        self.rec("C", "http://c.onion/"), self.rec("D", "http://d.onion/", "OFFLINE"),
                        self.rec("E", "http://e.onion/"), self.rec("G", "http://g.onion/")])
        new = self.mkrun([self.rec("A", "http://A.onion", "OFFLINE", error_class="host_unreachable"),
                        self.rec("B", "http://b.onion/", status_detail="ONLINE (TLS not verified)"),
                        self.rec("C", "http://c.onion/", title="Seized", status_detail="ONLINE (HTTP 403 - access barrier)", http_code=403),
                        self.rec("D", "http://d.onion/", "OFFLINE", error_class="invalid_onion_address"),
                        self.rec("E", "http://e.onion/"), self.rec("F", "http://f.onion/")])
        d = osc.diff_runs(old, new)
        self.assertEqual(d["summary"], {"went_offline": 1, "came_back": 1, "changed": 2, "added": 1,
                                        "removed": 1, "unchanged": 1})
        self.assertEqual(d["differences"], 6)
        self.assertEqual(d["went_offline"][0]["new_error_class"], "host_unreachable")
        self.assertEqual(d["came_back"][0]["new_detail"], "ONLINE (TLS not verified)")
        c = {r["name"]: [(x["field"], x["old"], x["new"]) for x in r["changes"]] for r in d["changed"]}
        self.assertEqual(c["C"], [("detail", "ONLINE", "ONLINE (HTTP 403 - access barrier)"), ("http", 200, 403),
                                  ("title", "T", "Seized")])
        self.assertEqual(c["D"], [("error", "timeout", "invalid_onion_address")])
        self.assertEqual([r["name"] for r in d["added"]], ["F"])
        self.assertEqual([r["name"] for r in d["removed"]], ["G"])
        self.assertFalse(d["old_suspect"] or d["new_suspect"])
        self.assertEqual(osc.diff_exit_code(d), 1)

    def test_indices_verdict_change_is_a_change(self):
        ix_old = {"verdict": "unlisted", "listed_in": [], "name_matches": [], "sources_failed": []}
        ix_new = {"verdict": "listed", "listed_in": [{"source": "tor.taxi"}], "name_matches": [], "sources_failed": []}
        d = osc.diff_runs(self.mkrun([self.rec("A", "http://a.onion/", indices=ix_old)]),
                          self.mkrun([self.rec("A", "http://a.onion/", indices=ix_new)]))
        self.assertEqual(d["changed"][0]["changes"],
                         [{"field": "indices", "old": "unlisted", "new": "listed", "listed_in": ["tor.taxi"]}])
        self.assertIn('indices: "unlisted" -> "listed" (tor.taxi)', osc.render_diff(d))

    def test_identical_runs_exit_0_and_say_so(self):
        recs = [self.rec("A", "http://a.onion/", title="Ahmia —\n      Search"), self.rec("B", "http://b.onion/", "OFFLINE")]
        same = [self.rec("A", "http://a.onion/", title="Ahmia — Search"), self.rec("B", "http://b.onion/", "OFFLINE")]
        d = osc.diff_runs(self.mkrun(recs), self.mkrun(same))  # whitespace inside a title is not a change
        self.assertEqual(d["differences"], 0)
        self.assertEqual(osc.diff_exit_code(d), 0)
        self.assertIn("No differences: 2 targets", osc.render_diff(d))

    def test_failed_controls_make_the_diff_suspect(self):
        old = self.mkrun([self.rec("A", "http://a.onion/")], controls={"online": 3, "total": 3})
        new = self.mkrun([self.rec("A", "http://a.onion/", "OFFLINE")], controls={"online": 1, "total": 3})
        d = osc.diff_runs(old, new)
        self.assertTrue(d["new_suspect"]); self.assertFalse(d["old_suspect"])
        self.assertEqual(osc.diff_exit_code(d), 3)
        text = osc.render_diff(d)
        self.assertIn("controls 1/3 — SUSPECT", text)
        self.assertIn("WARNING: the new run's controls failed", text)
        # a run with no controls file is unverified, not suspect
        self.assertFalse(osc.run_is_suspect(self.mkrun([], controls=None)))

    def test_load_run_reads_controls_sidecar_and_rejects_other_files(self):
        d = Path(tempfile.mkdtemp())
        f = d / "t-20260913-1200.json"
        f.write_text(json.dumps([self.rec("A", "http://a.onion/")]))
        (d / "t-20260913-1200-controls.json").write_text(json.dumps([self.rec("c1", "http://c.onion/"),
                                                                     self.rec("c2", "http://d.onion/", "OFFLINE")]))
        run = osc.load_run(f)
        self.assertEqual(run["controls"], {"online": 1, "total": 2})
        self.assertEqual(run["checked_at"], "2026-09-13T20:00:00+00:00")
        ix = d / "t-indices-20260913-1200.json"
        ix.write_text(json.dumps([{"name": "A", "uri": "http://a.onion/", "indices": {"verdict": "listed"}}]))
        with self.assertRaises(ValueError):
            osc.load_run(ix)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(osc.main(["diff", str(ix), str(f)]), 2)
            self.assertEqual(osc.main(["diff", str(d / "missing.json"), str(f)]), 2)

    def test_previous_run_picks_the_latest_of_the_same_list_only(self):
        d = Path(tempfile.mkdtemp())
        for name in ("t-20260913-1200.json", "t-20260913-1200-2.json", "t-20260913-1159.json",
                     "t-20260913-1200-controls.json", "t-20260913-1200-diff.json",
                     "t-indices-20260913-1300.json", "t-extra-20260913-1400.json", "t-20260913-1500.json"):
            (d / name).write_text("[]")
        self.assertEqual(osc.previous_run(d, "t").name, "t-20260913-1500.json")
        self.assertEqual(osc.previous_run(d, "t", exclude=d / "t-20260913-1500.json").name, "t-20260913-1200-2.json")
        self.assertEqual(osc.previous_run(d, "t-extra").name, "t-extra-20260913-1400.json")
        self.assertIsNone(osc.previous_run(d, "nothing"))

    def test_diff_main_writes_json_and_never_overwrites(self):
        d = Path(tempfile.mkdtemp())
        a = d / "t-20260913-1200.json"; b = d / "t-20260913-1300.json"
        a.write_text(json.dumps([self.rec("A", "http://a.onion/")]))
        b.write_text(json.dumps([self.rec("A", "http://a.onion/", "OFFLINE")]))
        out = d / "diff.json"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(osc.main(["diff", str(a), str(b), "--json", str(out)]), 1)
            self.assertEqual(osc.main(["diff", str(a), str(b), "--json", str(out)]), 2)
        self.assertIn("Went OFFLINE (1)", buf.getvalue())
        self.assertEqual(json.loads(out.read_text())["summary"]["went_offline"], 1)

    def test_diff_previous_after_a_run(self):
        d = Path(tempfile.mkdtemp())
        t = d / "list.txt"; t.write_text("A | http://a.onion/\n")
        out = d / "out"
        calls = iter([self.rec("A", "http://a.onion/"), self.rec("A", "http://a.onion/", "OFFLINE")])
        original = osc.check_one
        osc.check_one = lambda name, uri, session, cfg: next(calls)
        try:
            args = [str(t), "--out-dir", str(out), "--no-controls", "--no-html", "--delay", "0", "0", "--diff-previous"]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(osc.main(args), 0)      # first run: nothing to compare with
                self.assertEqual(list(out.glob("*-diff.json")), [])
                (out / next(out.glob("list-*.json")).name).rename(out / "list-20260913-0001.json")  # make it older
                self.assertEqual(osc.main(args), 0)      # run exit code is the run's, not the diff's
            diff = json.loads(next(out.glob("list-*-diff.json")).read_text())
            self.assertEqual(diff["summary"]["went_offline"], 1)
            self.assertEqual(Path(diff["old"]["file"]).name, "list-20260913-0001.json")
        finally:
            osc.check_one = original


class Batch(unittest.TestCase):
    """Journal, checkpoints and the stop rule — offline, with check_one and
    measure_controls replaced by scripted answers."""

    ONION = "http://" + "a" * 56 + ".onion/"
    ONION2 = "http://" + "b" * 56 + ".onion/"
    ONION3 = "http://" + "c" * 56 + ".onion/"

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._check_one, self._controls = osc.check_one, osc.measure_controls

    def tearDown(self):
        osc.check_one, osc.measure_controls = self._check_one, self._controls

    @staticmethod
    def online(name, uri, title="T", **kw):
        r = {"name": name, "uri": uri, "checked_at": "2026-09-13T20:00:00+00:00", "status": "ONLINE",
             "status_detail": "ONLINE", "http_code": 200, "title": title, "title_source": "html_title",
             "needs_js_rendering": False, "content_type": "text/html"}
        r.update(kw)
        return r

    def script(self, answers: dict, controls_ok: list[bool]):
        """check_one answers by uri; measure_controls answers by call order."""
        calls = []
        def fake_check(name, uri, session, cfg):
            calls.append(uri)
            return dict(answers[uri])
        it = iter(controls_ok)
        def fake_controls(session, cfg, checkpoint):
            ok = next(it)
            return [{"name": "[control] x", "uri": "http://c.onion/", "status": "ONLINE" if ok else "OFFLINE",
                     "status_detail": "ONLINE" if ok else "OFFLINE", "checkpoint": checkpoint}]
        osc.check_one, osc.measure_controls = fake_check, fake_controls
        return calls

    def run_main(self, targets: str, *extra: str) -> int:
        t = self.d / "list.txt"; t.write_text(targets)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return osc.main([str(t), "--out-dir", str(self.d / "out"), "--no-html", "--delay", "0", "0", *extra])

    def snapshot(self) -> list[dict]:
        latest = max(f for f in (self.d / "out").glob("list-*.json") if "-controls" not in f.name)
        return json.loads(latest.read_text())

    # --- Journal -----------------------------------------------------------
    def test_journal_segments_and_failed_checkpoint(self):
        j = osc.Journal(self.d / "j.jsonl")
        j.append(self.online("A", self.ONION))
        j.checkpoint("start", [{"status": "ONLINE"}])
        j.append(self.online("B", self.ONION2))
        j.checkpoint("after 1", [{"status": "OFFLINE"}])       # B measured through a circuit that then failed
        j.append(self.online("C", self.ONION3))                # trailing segment: the run died here
        (self.d / "j.jsonl").open("a").write('{"name": "cut", "uri": "http://d.onion/", "sta')  # crash mid-line
        done = j.load()
        self.assertEqual(sorted(r["name"] for r in done.values()), ["A", "C"])
        self.assertIn(osc.record_key(self.ONION), done)

    def test_journal_resume_skips_measured_and_writes_snapshot_in_list_order(self):
        j = self.d / "j.jsonl"
        osc.Journal(j).append(self.online("B", self.ONION2, title="from journal"))
        calls = self.script({self.ONION: self.online("A", self.ONION), self.ONION3: self.online("C", self.ONION3)}, [True])
        rc = self.run_main(f"A | {self.ONION}\nB | {self.ONION2}\nC | {self.ONION3}\n", "--journal", str(j))
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [self.ONION, self.ONION3])                       # B skipped
        self.assertEqual([r["name"] for r in self.snapshot()], ["A", "B", "C"])  # list order, journal merged
        self.assertEqual(self.snapshot()[1]["title"], "from journal")
        lines = [json.loads(l) for l in j.read_text().splitlines()]
        self.assertEqual([l.get("checkpoint") for l in lines], [None, None, None, "end"])
        # relaunch: nothing to measure, snapshot still written from the journal
        calls.clear()
        self.assertEqual(self.run_main(f"A | {self.ONION}\nB | {self.ONION2}\nC | {self.ONION3}\n", "--journal", str(j)), 0)
        self.assertEqual(calls, [])
        self.assertEqual(len(self.snapshot()), 3)

    # --- checkpoints ---------------------------------------------------------
    def test_controls_every_stops_on_a_failed_checkpoint_and_discards_the_segment(self):
        answers = {self.ONION: self.online("A", self.ONION), self.ONION2: self.online("B", self.ONION2),
                   self.ONION3: self.online("C", self.ONION3)}
        calls = self.script(answers, [True, False])           # start ok, "after 2" fails
        j = self.d / "j.jsonl"
        rc = self.run_main(f"A | {self.ONION}\nB | {self.ONION2}\nC | {self.ONION3}\n",
                           "--journal", str(j), "--controls-every", "2")
        self.assertEqual(rc, 3)
        self.assertEqual(calls, [self.ONION, self.ONION2])    # C never measured
        self.assertEqual(self.snapshot(), [])                 # A and B discarded: measured before the failed checkpoint
        self.assertEqual(osc.Journal(j).load(), {})           # and the journal agrees on relaunch
        controls = json.loads(next((self.d / "out").glob("list-*-controls.json")).read_text())
        self.assertEqual([c["checkpoint"] for c in controls], ["start", "after 2"])

    def test_controls_every_failed_start_measures_nothing(self):
        calls = self.script({self.ONION: self.online("A", self.ONION)}, [False])
        self.assertEqual(self.run_main(f"A | {self.ONION}\n", "--controls-every", "5"), 3)
        self.assertEqual(calls, [])

    def test_controls_every_all_good(self):
        answers = {u: self.online(n, u) for n, u in (("A", self.ONION), ("B", self.ONION2), ("C", self.ONION3))}
        self.script(answers, [True, True, True])              # start, after 2, end
        self.assertEqual(self.run_main(f"A | {self.ONION}\nB | {self.ONION2}\nC | {self.ONION3}\n",
                                       "--controls-every", "2"), 0)
        self.assertEqual(len(self.snapshot()), 3)
        controls = json.loads(next((self.d / "out").glob("list-*-controls.json")).read_text())
        self.assertEqual([c["checkpoint"] for c in controls], ["start", "after 2", "end"])

    # --- stop rule -----------------------------------------------------------
    def test_stop_rule_reads_plain_lines_and_markdown_tables(self):
        ex = self.d / "ex.txt"
        ex.write_text("# comment\n"
                      f"{'a' * 56}.onion\t2026-09-13\tterm:x\twhere:title\n"
                      "| `bbbbbbbbbbbbbbbbbbbbbbbb` | 2026-09-13 | signal | where |\n"
                      "|---|---|---|---|\n"
                      "short\n"                      # too short for a prefix, no dot: ignored
                      "www.example.org\n")
        s = osc.StopRule(None, ex)
        self.assertTrue(s.is_excluded(self.ONION))
        self.assertTrue(s.is_excluded(self.ONION2))          # 24-char prefix from the table
        self.assertFalse(s.is_excluded(self.ONION3))
        self.assertTrue(s.is_excluded("https://example.org/x"))
        self.assertFalse(s.is_excluded("https://notexample.org/"))
        self.assertFalse(s.is_excluded("http://shortyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy.onion/"))

    def test_stop_rule_terms_match_and_exclude_writes_the_file(self):
        terms = self.d / "terms.txt"; terms.write_text("# mine\n\\bforbidden\\b\nred\\s?room\n")
        ex = self.d / "ex.txt"
        s = osc.StopRule(terms, ex)
        self.assertEqual(s.match("nothing here"), None)
        self.assertEqual(s.match(None, "A Forbidden Thing"), "forbidden")
        self.assertEqual(s.match("RedRoom live"), "redroom")
        self.assertEqual(s.match("unforbidden"), None)       # whole word only, as the term says
        s.exclude(self.ONION, "forbidden", "title")
        line = ex.read_text().strip()
        self.assertTrue(line.startswith("a" * 56 + ".onion\t"))
        self.assertIn("\tterm:forbidden\twhere:title", line)
        self.assertTrue(s.is_excluded(self.ONION))           # remembered in memory too

    def test_apply_stop_rule_scrubs_the_record(self):
        terms = self.d / "terms.txt"; terms.write_text("forbidden\n")
        s = osc.StopRule(terms, None)
        r = self.online("A", self.ONION, title="Loading...", static_hints={"meta_title": "", "meta_description": "forbidden stuff"})
        out = osc.apply_stop_rule(s, "A", self.ONION, r)
        self.assertEqual(out["status"], "EXCLUDED")
        self.assertEqual(out["status_detail"], "EXCLUDED (stop term in meta)")
        self.assertEqual((out["stop_term"], out["stop_where"]), ("forbidden", "meta"))
        self.assertNotIn("static_hints", out); self.assertIsNone(out["title"]); self.assertNotIn("http_code_x", out)
        self.assertEqual(set(out), {"name", "uri", "checked_at", "status", "status_detail", "http_code", "title",
                                    "stop_term", "stop_where"})
        clean = self.online("B", self.ONION2, title="Fine")
        self.assertIs(osc.apply_stop_rule(s, "B", self.ONION2, clean), clean)

    def test_stop_rule_in_a_run_label_title_and_exclusions_file(self):
        terms = self.d / "terms.txt"; terms.write_text("forbidden\n")
        ex = self.d / "ex.txt"; ex.write_text(f"{'c' * 56}.onion\t2026-09-01\tterm:old\twhere:title\n")
        calls = self.script({self.ONION: self.online("A", self.ONION, title="a forbidden title"),
                             self.ONION2: self.online("B", self.ONION2)}, [True])
        rc = self.run_main(f"A | {self.ONION}\nB forbidden label | {self.ONION2}\nC | {self.ONION3}\n",
                           "--stop-terms", str(terms), "--exclusions", str(ex), "--catalog", str(self.d))
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [self.ONION])                 # B: label matched, not fetched; C: on file, not fetched
        snap = {r["name"]: r for r in self.snapshot()}
        self.assertEqual(snap["A"]["status_detail"], "EXCLUDED (stop term in title)")
        self.assertEqual(snap["B forbidden label"]["status_detail"], "EXCLUDED (stop term in label, not fetched)")
        self.assertEqual(snap["C"]["status_detail"], "EXCLUDED (on the exclusions file, not fetched)")
        self.assertTrue(all("indices" not in r for r in snap.values()))   # nothing looked up for excluded targets
        hosts = [l.split("\t")[0] for l in ex.read_text().splitlines()]
        self.assertEqual(hosts, ["c" * 56 + ".onion", "a" * 56 + ".onion", "b" * 56 + ".onion"])

    def test_diff_treats_excluded_as_a_status_change_not_offline(self):
        old = {"file": "o", "targets": 1, "checked_at": None, "controls": None, "records": [self.online("A", self.ONION)]}
        new = dict(old, records=[osc.excluded_record("A", self.ONION, "EXCLUDED (stop term in title)", "x", "title")])
        d = osc.diff_runs(old, new)
        self.assertEqual(d["summary"]["went_offline"], 0)
        self.assertEqual(d["changed"][0]["changes"], [{"field": "status", "old": "ONLINE", "new": "EXCLUDED"}])

    def test_report_lists_excluded_and_checkpoints(self):
        out = self.d / "r.html"
        osc.write_html_report([osc.excluded_record("A", self.ONION, "EXCLUDED (stop term in title)", "x", "title")], out,
                              [{"name": "[control] x", "status": "ONLINE", "status_detail": "ONLINE", "checkpoint": "after 250"}])
        html = out.read_text()
        self.assertIn("Excluded by the stop rule (1)", html)
        self.assertIn("Offline (0)", html)
        self.assertIn("[after 250]", html)

    def test_batch_usage_errors(self):
        self.assertEqual(self.run_main(f"A | {self.ONION}\n", "--stop-terms", str(self.d / "nope.txt")), 2)
        self.assertEqual(self.run_main(f"A | {self.ONION}\n", "--controls-every", "-1"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
