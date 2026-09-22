# Down, or gone? — the descriptor check

`OFFLINE` says a service did not answer. It does not say whether anyone is still
running it. (Part of the [Nullius in Onion](../../README.md) docs.)

At the Tor layer a live onion service **publishes a descriptor** to a handful of
directory relays (the HSDirs) every few hours; a client fetches it before it can
connect. So an OFFLINE onion is one of two things — a service that is still
**published but not responding** (overloaded, application down, rendezvous
failing), or one that is **not published** at all, which is what "gone" looks
like from the network. A plain GET cannot tell them apart; the control port can.

```bash
pip install stem
python3 nullius.py my-list.txt --descriptor --control-port 9151
```

With `--descriptor`, every OFFLINE `.onion` gets one more question: `HSFETCH`
through the Tor control port, and the answer from the HSDirs — `RECEIVED`, or
`FAILED` with a reason. The record gains `descriptor` (`published` /
`not_published` / `unknown`) and `descriptor_detail`; the report labels the
offline lines *published, not responding* or *not published*; the summary counts
them; `diff` reports a change from one to the other.

```
Descriptors of the offline: 2 published (down, not gone), 5 not published (gone at the Tor layer), 0 unknown.
```

**What it needs.** The `stem` package (optional; `pip install stem`), and a Tor
control port you can authenticate to. Tor Browser's own tor listens on `9151`
with cookie authentication readable by your user — the easiest path. The system
daemon needs `ControlPort 9051` and `CookieAuthentication 1` in `torrc`, and a
user that can read the cookie file. When any of that is missing, every affected
record says `unknown` with the reason, the terminal prints the reason once and
then "same reason as above", and the run goes on: it never aborts anything.
Records taken from a `--journal` keep whatever they had; only targets measured in
this run are asked.

**How it decides.** Tor asks several HSDirs one after another and emits one
`REQUESTED` and one `FAILED` per directory it tried, with no aggregate event — so
a single `NOT_FOUND` proves nothing. *Not published* is concluded only when there
has been a `FAILED`, no request is still in flight, and a quiet period has passed
with nothing new. `RECEIVED` from any directory, at any moment before the
deadline, is *published*. Other reasons (`QUERY_REJECTED`, `BAD_DESC`, …) are
`unknown`, named; so is a deadline reached with a lookup still in progress — the
detail says how many `NOT_FOUND` had arrived. The first lookup of a run may take
most of the timeout (default 60 s) while the control connection's tor builds its
first HSDir circuit.

**What it tells the network.** A descriptor fetch is what every Tor client does
before connecting; the failed GET already did one. The HSDirs learn that someone
asked for that (blinded) address — not who. Nothing is sent to the service itself.

See also: the `--descriptor`, `--control-port`, `--control-socket` and
`--descriptor-timeout` [options](../reference.md#options).
</content>
