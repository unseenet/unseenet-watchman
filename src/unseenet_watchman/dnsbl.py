"""URI blocklists (SURBL, Spamhaus DBL ...), asked through Tor.

A URI blocklist is a DNS zone: ``example.com.multi.surbl.org`` has an A record when
``example.com`` is listed, and the address (127.0.0.x) says why.

**Why not plain DNS through Tor.** Tor's own resolving (SOCKS RESOLVE) throws away
every answer that points at an internal address such as 127.0.0.x - a safety rule of
the Tor client (``ClientDNSRejectInternalAddresses``) that cannot be turned off on the
real network. Every blocklist answer is such an address, so that way every domain would
look clean. Instead the watchman asks a **DNS-over-HTTPS** resolver, through Tor: the
answer is then HTTP content, which Tor does not look into. The resolver learns which
domains are looked up - links in public posts - and a Tor exit's address, never ours.
The request is RFC 8484 wire format, which every DoH resolver speaks on port 443;
Google's ``/resolve`` JSON API is still understood for configs that name it.

**Refusals.** Lists refuse lookups from big public resolvers, in two ways: with an
error code (``refused`` in a zone's config), or silently, answering "does not exist".
The silent way would make every domain look clean, so each zone has a **test point**,
a domain the list always lists. It is looked up at start and every few hours; a zone
that does not list its own test point is paused and the log says so loudly.

What works through public DoH (tried October 2026): SURBL's ``multi.surbl.org``.
Spamhaus refuses public resolvers - its free **DQS** key gives zones of its own
(``<key>.dbl.dq.spamhaus.net``) that answer. URIBL refuses them too. Check each list's
terms of use; several are free only for small, non-commercial use.

**More than one resolver.** A lookup that fails (a bad exit, a circuit that could not
be built) is asked once more on a fresh circuit, then through the next resolver in the
list. Since lists refuse resolvers differently, the test point is looked up through
*each* resolver: a resolver that fails it is not used for that zone, and a zone is only
paused when no resolver passes - a fallback to a resolver a list refuses silently would
otherwise make every domain look clean.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

CACHE_SECONDS = 6 * 3600
PAUSE_SECONDS = 3600
SELFTEST_SECONDS = 6 * 3600
# Each answered SURBL's test point through Tor, over HTTP/1.1, in October 2026.
# Cloudflare answers SURBL with SERVFAIL; Quad9 and Mullvad want HTTP/2.
DEFAULT_DOHS = ["https://dns.google/dns-query",
                "https://wikimedia-dns.org/dns-query",
                "https://unfiltered.adguard-dns.com/dns-query",
                "https://doh.dns.sb/dns-query"]
DEFAULT_DOH = DEFAULT_DOHS[0]


def doh_list(value) -> list[str]:
    """``doh`` from the config: one URL, a list of them, or empty for the defaults."""
    if not value:
        return list(DEFAULT_DOHS)
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value if v]


def doh_host(doh: str) -> str:
    return urlsplit(doh).hostname or doh


@dataclass
class Zone:
    """One URI blocklist and how to read its answers.

    ``codes``: an answer address to a reason (exact match). ``bits``: the last octet as
    a bitmask, each bit to a reason (SURBL's and URIBL's multi zones). An answer that
    matches neither is ignored, so a list that adds a code is never read as more than
    it says. ``test``: a domain the list always lists (its test point)."""
    name: str
    codes: dict[str, str] = field(default_factory=dict)
    bits: dict[int, str] = field(default_factory=dict)
    refused: frozenset[str] = frozenset()
    test: str = ""
    enabled: bool = True

    def reasons(self, address: str) -> set[str]:
        if address in self.codes:
            return {self.codes[address]}
        if self.bits and address.startswith("127.0.0."):
            last = int(address.rsplit(".", 1)[1])
            return {r for b, r in self.bits.items() if last & b}
        return set()


SPAMHAUS_CODES = {"127.0.1.2": "spam", "127.0.1.4": "phishing", "127.0.1.5": "malware",
                  "127.0.1.6": "malware", "127.0.1.102": "spam", "127.0.1.103": "spam",
                  "127.0.1.104": "phishing", "127.0.1.105": "malware", "127.0.1.106": "malware"}
SPAMHAUS_REFUSED = frozenset({"127.255.255.252", "127.255.255.254", "127.255.255.255"})
SURBL = Zone("multi.surbl.org", bits={8: "phishing", 16: "malware", 64: "spam", 128: "malware"},
             refused=frozenset({"127.0.0.1"}), test="surbl-org-permanent-test-point.com")
URIBL = Zone("multi.uribl.com", bits={2: "spam"}, refused=frozenset({"127.0.0.1"}),
             test="test.uribl.com", enabled=False)


def spamhaus_dqs(key: str) -> Zone:
    """Spamhaus DBL through a DQS key, the zone that answers public resolvers."""
    return Zone(f"{key}.dbl.dq.spamhaus.net", codes=SPAMHAUS_CODES, refused=SPAMHAUS_REFUSED,
                test="dbltest.com")


def default_zones(dqs_key: str = "") -> list[Zone]:
    return [SURBL] + ([spamhaus_dqs(dqs_key)] if dqs_key else []) + [URIBL]


class ResolveError(OSError):
    """The resolver could not be asked or did not answer (Tor down, resolver failing)."""


def http_body(http: bytes) -> bytes:
    """The body of a 200 response (chunked or not); ResolveError for any other status."""
    head, _, body = http.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or status_line[1] != b"200":
        raise ResolveError("resolver answered " + b" ".join(status_line[1:]).decode(errors="replace"))
    if b"transfer-encoding: chunked" in head.lower():
        out = b""
        while body:
            size, _, rest = body.partition(b"\r\n")
            n = int(size.split(b";")[0] or b"0", 16)
            if n == 0:
                break
            out, body = out + rest[:n], rest[n + 2:]
        body = out
    return body


def dns_query(name: str) -> bytes:
    """A DNS message asking for ``name``'s A record (RFC 1035), ID 0 as RFC 8484 asks."""
    q = b"".join(bytes([len(label)]) + label for label in name.rstrip(".").encode("ascii").split(b"."))
    return (b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # ID 0, RD, 1 question
            + q + b"\x00\x00\x01\x00\x01")                         # root, type A, class IN


def _skip_name(msg: bytes, i: int) -> int:
    while True:
        if i >= len(msg):
            raise ResolveError("resolver sent a cut-off DNS message")
        n = msg[i]
        if n & 0xC0 == 0xC0:                     # a pointer ends the name
            return i + 2
        if n == 0:
            return i + 1
        i += 1 + n


def read_dns_message(msg: bytes) -> str | None:
    """The first A record in a DNS message; None for "does not exist" or no A record.
    ResolveError for SERVFAIL, REFUSED and anything malformed."""
    if len(msg) < 12:
        raise ResolveError("resolver sent a cut-off DNS message")
    rcode = msg[3] & 0x0F
    if rcode == 3:
        return None                                 # NXDOMAIN: not listed
    if rcode != 0:
        raise ResolveError(f"resolver status {rcode}")
    qd, an = int.from_bytes(msg[4:6], "big"), int.from_bytes(msg[6:8], "big")
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    for _ in range(an):
        i = _skip_name(msg, i)
        if i + 10 > len(msg):
            raise ResolveError("resolver sent a cut-off DNS message")
        rtype = int.from_bytes(msg[i:i + 2], "big")
        rdlen = int.from_bytes(msg[i + 8:i + 10], "big")
        rdata = msg[i + 10:i + 10 + rdlen]
        if rtype == 1 and len(rdata) == 4:
            return ".".join(str(b) for b in rdata)
        i += 10 + rdlen
    return None


def uses_json(doh: str) -> bool:
    """Google's ``/resolve`` speaks DNS JSON; everything else RFC 8484 wire format."""
    return urlsplit(doh).path.rstrip("/").endswith("/resolve")


def read_dns_json(http: bytes) -> str | None:
    """The first A record in an HTTP response with DNS JSON; None for "does not exist".
    ResolveError for anything else (an HTTP error, SERVFAIL ...)."""
    body = http_body(http)
    try:
        d = json.loads(body)
    except ValueError as exc:
        raise ResolveError("resolver did not answer in DNS JSON") from exc
    status = d.get("Status")
    if status == 3:
        return None                                 # NXDOMAIN: not listed
    if status != 0:
        raise ResolveError(f"resolver status {status}")
    for a in d.get("Answer", []):
        if a.get("type") == 1:
            return a.get("data")
    return None


async def _socks_connect(reader, writer, host: str, port: int, timeout: float,
                         isolate: str = "") -> None:
    """SOCKS5 CONNECT. ``isolate``: a username for Tor's IsolateSOCKSAuth (on by
    default), so a different one gets a different circuit."""
    if isolate:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\x05\x02":
            raise ResolveError("Tor's SOCKS port refused the greeting")
        u = isolate.encode()[:255]
        writer.write(b"\x01" + bytes([len(u)]) + u + b"\x01x")
        await writer.drain()
        if (await asyncio.wait_for(reader.readexactly(2), timeout))[1] != 0:
            raise ResolveError("Tor's SOCKS port refused the isolation username")
    else:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\x05\x00":
            raise ResolveError("Tor's SOCKS port refused the greeting")
    h = host.encode("ascii")
    writer.write(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
    await writer.drain()
    rep = await asyncio.wait_for(reader.readexactly(4), timeout)
    if rep[1] != 0:
        raise ResolveError(f"Tor could not reach {host} (SOCKS error {rep[1]})")
    if rep[3] == 1:
        await reader.readexactly(4 + 2)
    elif rep[3] == 4:
        await reader.readexactly(16 + 2)
    else:
        await reader.readexactly((await reader.readexactly(1))[0] + 2)


async def doh_resolve_retry(name: str, socks_host: str, socks_port: int, doh: str = DEFAULT_DOH,
                            timeout: float = 45.0) -> str | None:
    """``doh_resolve``, asked once more on a fresh circuit when it fails."""
    try:
        return await doh_resolve(name, socks_host, socks_port, doh, timeout)
    except ResolveError:
        return await doh_resolve(name, socks_host, socks_port, doh, timeout,
                                 isolate="watchman-" + secrets.token_hex(6))


async def doh_resolve(name: str, socks_host: str, socks_port: int, doh: str = DEFAULT_DOH,
                      timeout: float = 45.0, isolate: str = "") -> str | None:
    """Resolve ``name`` (A) with a DNS-over-HTTPS resolver reached through Tor."""
    url = urlsplit(doh)
    host, port = url.hostname or "", url.port or 443
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(socks_host, socks_port), timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise ResolveError(f"Tor at {socks_host}:{socks_port}: {exc}") from exc
    try:
        await _socks_connect(reader, writer, host, port, timeout, isolate)
        await asyncio.wait_for(writer.start_tls(ssl.create_default_context(), server_hostname=host), timeout)
        if uses_json(doh):
            path, accept = url.path + f"?name={quote(name)}&type=A", "application/dns-json"
        else:
            dns = base64.urlsafe_b64encode(dns_query(name)).rstrip(b"=").decode()
            path, accept = (url.path or "/dns-query") + f"?dns={dns}", "application/dns-message"
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: {accept}\r\n"
                     "Connection: close\r\n\r\n".encode())
        await writer.drain()
        http = await asyncio.wait_for(reader.read(-1), timeout)
        return read_dns_json(http) if uses_json(doh) else read_dns_message(http_body(http))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError, ConnectionError) as exc:
        raise ResolveError(f"no answer from {host}: {exc!r}") from exc
    finally:
        writer.close()


@dataclass
class Hit:
    """A domain listed in a zone, and why."""
    domain: str
    zone: str
    reasons: set[str]


class Lookups:
    """Lookups with a cache; zones paused when they refuse or fail their test point.

    ``resolve(qname)`` returns an address or None; tests pass their own. With
    ``resolvers``, it is ``resolve(qname, resolver)``: they are tried in order, and
    each zone uses only the resolvers that passed its test point."""

    def __init__(self, zones: list[Zone], resolve, log=print, resolvers: list[str] | None = None):
        self.zones = [z for z in zones if z.enabled]
        self.resolve = resolve
        self.log = log
        self.resolvers: list[str | None] = list(resolvers) if resolvers else [None]
        self._via: dict[str, list[str | None]] = {}
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._paused: dict[str, float] = {}
        self._tested = 0.0

    async def _call(self, qname: str, r: str | None):
        return await (self.resolve(qname) if r is None else self.resolve(qname, r))

    def _named(self, r: str | None, why: str) -> str:
        return why if r is None or len(self.resolvers) == 1 else f"via {doh_host(r)}: {why}"

    def _pause(self, z: Zone, seconds: float, why: str) -> None:
        self._paused[z.name] = time.monotonic() + seconds
        self.log(f"{z.name}: {why}; paused for {seconds / 3600:.0f} h")

    def active(self) -> list[Zone]:
        now = time.monotonic()
        return [z for z in self.zones if self._paused.get(z.name, 0) <= now]

    async def selftest(self, force: bool = False) -> None:
        """Look up each zone's test point; pause a zone that does not list it."""
        if not force and self._tested and time.monotonic() - self._tested < SELFTEST_SECONDS:
            return
        self._tested = time.monotonic()
        for z in self.zones:
            if not z.test:
                self._via[z.name] = list(self.resolvers)
                continue
            passed: list[str | None] = []
            failures: list[tuple[float, str]] = []
            for r in self.resolvers:
                try:
                    address = await self._call(f"{z.test}.{z.name}", r)
                except ResolveError as exc:
                    failures.append((PAUSE_SECONDS, self._named(r, f"test lookup failed ({exc})")))
                    continue
                if address in z.refused:
                    failures.append((SELFTEST_SECONDS, self._named(
                        r, f"refused the lookup ({address}) - a key for the list may be needed")))
                elif not address or not z.reasons(address):
                    failures.append((SELFTEST_SECONDS, self._named(
                        r, f"did not list its own test point {z.test} (answer: {address or 'none'})"
                        " - the resolver may be refused silently")))
                else:
                    passed.append(r)
            self._via[z.name] = passed
            if passed:
                self._paused.pop(z.name, None)
                for _, why in failures:
                    self.log(f"{z.name}: {why}; that resolver is not used for this list")
            else:
                # only lookups that failed outright: try again in an hour; a refusal: later
                seconds = min(sec for sec, _ in failures)
                self._pause(z, seconds, "; ".join(why for _, why in failures))

    async def _ask(self, qname: str, z: Zone) -> str | None:
        now = time.monotonic()
        hit = self._cache.get(qname)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
        errors = []
        for r in self._via.get(z.name, self.resolvers):
            try:
                address = await self._call(qname, r)
            except ResolveError as exc:
                errors.append(str(exc))
                continue
            self._cache[qname] = (now, address)
            return address
        raise ResolveError("; ".join(errors) or "no resolver passed the test point")

    async def check(self, domain: str) -> list[Hit]:
        """Each active zone that lists ``domain``, with its reasons."""
        await self.selftest()
        out = []
        for z in self.active():
            try:
                address = await self._ask(f"{domain}.{z.name}", z)
            except ResolveError as exc:
                self.log(f"blocklist lookups skipped: {exc}")
                return out
            if address is None:
                continue
            if address in z.refused:
                self._pause(z, PAUSE_SECONDS, f"refused the lookup ({address})")
                continue
            reasons = z.reasons(address)
            if reasons:
                out.append(Hit(domain, z.name, reasons))
        return out
