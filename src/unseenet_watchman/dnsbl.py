"""URI blocklists (Spamhaus DBL, SURBL, URIBL ...), looked up through Tor.

A URI blocklist is a DNS zone: ``example.com.dbl.spamhaus.org`` has an A record when
``example.com`` is listed, and the address says why. Every lookup goes through Tor's
SOCKS port with Tor's RESOLVE extension (command 0xF0), so neither the lists nor a
resolver learn where the watchman runs.

Lists refuse some resolvers - Spamhaus, for one, answers queries from large public
resolvers with an error code instead, and Tor exits may count as such. Those codes are
``refused`` in a zone's config: the zone is then paused for an hour and the log says
so, instead of the answer being read as "listed". Check each list's terms of use;
several are free only for small, non-commercial use, and Spamhaus offers a free key
(DQS) whose zones work where the public ones refuse.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field

RESOLVE = 0xF0              # Tor's SOCKS5 extension: resolve a name, no connection
CACHE_SECONDS = 6 * 3600
PAUSE_SECONDS = 3600


@dataclass
class Zone:
    """One URI blocklist and how to read its answers.

    ``codes``: an answer address to a reason (exact match). ``bits``: the last octet as
    a bitmask, each bit to a reason (SURBL's and URIBL's multi zones). An answer that
    matches neither is ignored: a list that adds a code is never read as more than it
    says."""
    name: str
    codes: dict[str, str] = field(default_factory=dict)
    bits: dict[int, str] = field(default_factory=dict)
    refused: frozenset[str] = frozenset()
    enabled: bool = True

    def reasons(self, address: str) -> set[str]:
        if address in self.codes:
            return {self.codes[address]}
        out = set()
        if self.bits and address.startswith("127.0.0."):
            last = int(address.rsplit(".", 1)[1])
            out = {r for b, r in self.bits.items() if last & b}
        return out


# Defaults as the lists document their answers; a config replaces them ([[zone]]).
DEFAULT_ZONES = [
    Zone("dbl.spamhaus.org",
         codes={"127.0.1.2": "spam", "127.0.1.4": "phishing", "127.0.1.5": "malware",
                "127.0.1.6": "malware", "127.0.1.102": "spam", "127.0.1.103": "spam",
                "127.0.1.104": "phishing", "127.0.1.105": "malware", "127.0.1.106": "malware"},
         refused=frozenset({"127.255.255.252", "127.255.255.254", "127.255.255.255"})),
    Zone("multi.surbl.org", bits={8: "phishing", 16: "malware", 64: "spam", 128: "malware"},
         refused=frozenset({"127.0.0.1"})),
    Zone("multi.uribl.com", bits={2: "spam"}, refused=frozenset({"127.0.0.1"}), enabled=False),
]


class TorResolveError(OSError):
    """Tor could not be asked (not running, wrong port)."""


async def tor_resolve(name: str, host: str = "127.0.0.1", port: int = 9050,
                      timeout: float = 30.0) -> str | None:
    """The IPv4 address of ``name``, resolved by Tor; None when it does not exist."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise TorResolveError(f"Tor at {host}:{port}: {exc}") from exc
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\x05\x00":
            raise TorResolveError("Tor's SOCKS port refused the greeting")
        n = name.encode("ascii")
        writer.write(b"\x05" + bytes([RESOLVE, 0, 3, len(n)]) + n + b"\x00\x00")
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(4), timeout)
        if head[1] != 0:
            return None              # Tor answers a name that does not exist with an error
        atyp = head[3]
        if atyp == 1:
            raw = await asyncio.wait_for(reader.readexactly(4 + 2), timeout)
            return str(ipaddress.IPv4Address(raw[:4]))
        if atyp == 4:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout)
            return None              # blocklists answer in IPv4
        if atyp == 3:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
            return None
        return None
    except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
        raise TorResolveError(f"Tor did not answer: {exc}") from exc
    finally:
        writer.close()


@dataclass
class Hit:
    """A domain listed in a zone, and why."""
    domain: str
    zone: str
    reasons: set[str]


class Lookups:
    """Lookups with a cache, and zones paused when they refuse.

    ``resolve`` is ``tor_resolve`` bound to the Tor port; tests pass their own."""

    def __init__(self, zones: list[Zone], resolve, log=print):
        self.zones = [z for z in zones if z.enabled]
        self.resolve = resolve
        self.log = log
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._paused: dict[str, float] = {}

    async def _ask(self, qname: str) -> str | None:
        now = time.monotonic()
        hit = self._cache.get(qname)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
        address = await self.resolve(qname)
        self._cache[qname] = (now, address)
        return address

    async def check(self, domain: str) -> list[Hit]:
        """Each zone that lists ``domain``, with its reasons."""
        out = []
        for z in self.zones:
            until = self._paused.get(z.name, 0)
            if until > time.monotonic():
                continue
            address = await self._ask(f"{domain}.{z.name}")
            if address is None:
                continue
            if address in z.refused:
                self._paused[z.name] = time.monotonic() + PAUSE_SECONDS
                self.log(f"{z.name} refused the lookup ({address}); paused for an hour - "
                         "a key for the list (e.g. Spamhaus DQS) may be needed")
                continue
            reasons = z.reasons(address)
            if reasons:
                out.append(Hit(domain, z.name, reasons))
        return out
