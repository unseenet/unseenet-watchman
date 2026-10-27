"""Near-identical posts across groups and keys.

Spam is the same text, a little changed, many times: from many new keys (a wave), or
from one key in many groups (a flood). Each post gets a 64-bit SimHash of its words;
two posts are "the same" when their hashes differ in at most ``MAX_DISTANCE`` bits.

Finding them without comparing every pair: the hash is cut into four 16-bit bands.
Two hashes at most 3 bits apart share at least one band exactly (pigeonhole), so each
band is an index, and only posts sharing a band are compared.

Short posts are left out ("thanks!", "+1" are the same everywhere and are no spam),
and so are quoted lines (a reply repeats what it answers) and the signature.
Links become their host, so the same text pointing elsewhere still matches, and
numbers become 0, so counters and prices do not split a wave.

This is also a first try at reporting a fingerprint instead of each Message-ID
(unseenet/unseenet#123, UN-RFC 0045 section 12): ``Entry.fp`` is that fingerprint.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

BITS = 64
BANDS = 4
MAX_DISTANCE = 3
MIN_WORDS = 12
SHINGLE = 3


def normalize(text: str) -> list[str]:
    """The words of ``text`` that count: no quotes or signature, links as hosts."""
    lines = []
    for line in (text or "").splitlines():
        if line.rstrip() == "--":                 # the signature starts (UN-RFC 0031)
            break
        if line.lstrip().startswith(">"):
            continue
        lines.append(line)
    t = "\n".join(lines).lower()
    t = re.sub(r"(?:https?://|www\.)([^\s/?#<>()\[\]]+)\S*", r" \1 ", t)
    t = re.sub(r"\d+", "0", t)
    return re.findall(r"[\w.]+", t)


def simhash(words: list[str]) -> int:
    """The 64-bit SimHash of word shingles."""
    if len(words) < SHINGLE:
        grams = [" ".join(words)]
    else:
        grams = [" ".join(words[i:i + SHINGLE]) for i in range(len(words) - SHINGLE + 1)]
    weights = [0] * BITS
    for g in grams:
        h = int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "big")
        for b in range(BITS):
            weights[b] += 1 if h >> b & 1 else -1
    return sum(1 << b for b in range(BITS) if weights[b] > 0)


def fingerprint(text: str) -> int | None:
    """The post's fingerprint, or None when it is too short to judge."""
    words = normalize(text)
    if len(words) < MIN_WORDS:
        return None
    return simhash(words)


def distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def _bands(fp: int) -> list[tuple[int, int]]:
    width = BITS // BANDS
    return [(i, fp >> (i * width) & ((1 << width) - 1)) for i in range(BANDS)]


@dataclass
class Entry:
    fp: int
    message_id: str
    group: str
    key: str
    ts: float


class Index:
    """The recent posts' fingerprints, searchable by band."""

    def __init__(self, window_seconds: float = 3 * 86400, max_entries: int = 50_000):
        self.window = window_seconds
        self.max = max_entries
        self.entries: list[Entry] = []
        self._bands: dict[tuple[int, int], list[Entry]] = {}

    def add(self, e: Entry) -> list[Entry]:
        """Add a post; returns the earlier posts that are the same (not itself)."""
        near = self.near(e.fp)
        self.entries.append(e)
        for b in _bands(e.fp):
            self._bands.setdefault(b, []).append(e)
        if len(self.entries) > self.max:
            self.prune(oldest_first=len(self.entries) - self.max)
        return [x for x in near if x.message_id != e.message_id]

    def near(self, fp: int) -> list[Entry]:
        seen, out = set(), []
        for b in _bands(fp):
            for x in self._bands.get(b, ()):
                if id(x) not in seen and distance(x.fp, fp) <= MAX_DISTANCE:
                    seen.add(id(x))
                    out.append(x)
        return out

    def prune(self, now: float | None = None, oldest_first: int = 0) -> None:
        """Forget posts older than the window (or the ``oldest_first`` oldest)."""
        self.entries.sort(key=lambda x: x.ts)
        if oldest_first:
            self.entries = self.entries[oldest_first:]
        if now is not None:
            self.entries = [x for x in self.entries if now - x.ts <= self.window]
        self._bands = {}
        for x in self.entries:
            for b in _bands(x.fp):
                self._bands.setdefault(b, []).append(x)

    def to_json(self) -> list:
        return [[format(x.fp, "016x"), x.message_id, x.group, x.key, x.ts] for x in self.entries]

    @classmethod
    def from_json(cls, rows: list, **kw) -> "Index":
        ix = cls(**kw)
        for fp, mid, g, k, ts in rows:
            ix.entries.append(Entry(int(fp, 16), mid, g, k, ts))
        ix.prune()
        return ix
