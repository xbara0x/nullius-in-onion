# Security policy

`nullius` is a tool for looking at hostile infrastructure — it fetches pages
served by adversaries and runs your patterns against their content. Its whole
premise is *take nobody's word for it*, so a flaw in it is a flaw in something
people rely on to be careful. Please report one privately.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Instead, use one of:

- **GitHub private vulnerability reporting** — the repository's **Security** tab
  → **Report a vulnerability**. This opens a private advisory only the
  maintainer can see.
- **Email** — `xbara0x@pm.me`. Say "nullius security" in the subject.

Include what it affects, how to reproduce it, and the impact you see. You will
get an acknowledgement on a best-effort basis (this is a solo project). Fixes
are coordinated: the flaw is corrected, then disclosed, with credit to you if
you want it.

## Supported versions

| Version | Supported |
|---|---|
| 0.9.x | ✅ |
| < 0.9 | ❌ |

The major is `0`: a minor release may change the JSON layout, and the
[CHANGELOG](CHANGELOG.md) says when it does.

## In scope

Report anything that lets hostile content or a crafted input do more than it
should. In particular:

- **ReDoS** — a `--stop-terms` or `--categories` pattern (see "trusted code"
  below) with catastrophic backtracking, or any input that makes matching hang.
- **The page body leaking into an artifact** — any path where text from a
  fetched page ends up in a results file, the journal, the exclusions file or
  the HTML report. The tool promises to keep *nothing that describes the page*
  (see below); a counter-example is a bug.
- **A stop-rule bypass** — content that should be excluded being fetched,
  measured or recorded anyway.
- **Leaking your intent or network position** — anything that sends a target,
  a query, or an identifier somewhere it should not go.
- **Control-protocol injection** through `--descriptor` (the Tor control port).
- **Path traversal** or arbitrary writes from a target name or output path.

## Threat model and guarantees

What the tool promises, so you know what a violation looks like:

- **One plain GET per target, over the proxy you point it at.** It never runs
  JavaScript, never logs in, never crawls, never follows a target's links.
- **Read once, keep nothing that describes the page.** The full response body is
  never serialized. A stop term that fires records the **rule name**, never a
  span of the page. `meta description` is read for the stop check and then
  dropped, never written. If you find page text in an output file, that is a
  bug — and there is a canary test in the suite guarding exactly this.
- **`verify=False` is deliberate, not an oversight.** For a `.onion`, the
  address *is* the service's public key; the Tor circuit authenticates it.
  TLS on top adds a certificate that says nothing more, and self-signed certs
  are the norm there. Clearnet targets are fetched the same way for uniformity.
- **`--stop-terms` and `--categories` files are trusted code.** They are regular
  expressions you run, single-threaded, against up to ~200 KB of
  adversary-controlled text per page. Treat these files as code you wrote or
  audited — a poisoned vocabulary can hang a scan (see ReDoS above). The tool
  ships neither by default.
- **OPSEC boundary.** Onion targets never leave Tor. Clearnet targets are
  fetched **through the Tor exit node**, so the target's operator sees a Tor
  exit, not your address — but the tool anonymizes you no further than routing
  through the proxy you gave it. Choosing and running that proxy safely is
  yours.

## Out of scope

Denial of service against a target you point the tool at (that is your
responsibility and your legal exposure), findings that require a malicious
`--stop-terms`/`--categories`/targets file you wrote yourself (that is trusted
code), and anything about services the tool merely *measures* rather than
*is*.
