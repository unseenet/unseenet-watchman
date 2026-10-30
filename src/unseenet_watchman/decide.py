"""From what the checks found to findings: which post, which reason, and why.

Reasons are UN-RFC 0045's, from the core's one list (``unseenet.core.reports.REASONS``,
unseenet/unseenet#659) - never a list of our own. Each reason belongs to one issuer:
spam and flood to the spam issuer, phishing and malware to the phishing issuer, so
readers can follow exactly the lists they want.

Posts first, keys later: a key is only reported after ``key_after`` findings within
``key_window`` days, and then only for ``key_days`` days (UN-RFC 0045 allows at most
365). One unlucky post never costs anyone their key.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from unseenet.core.reports import NOTE_MAX, REASONS

from .dnsbl import Hit
from .dupes import Entry

# which issuer publishes which reason; the rest (harassment, illegal ...) is for people
ISSUER_OF = {"spam": "spam", "flood": "spam", "phishing": "phishing", "malware": "phishing"}
# when one domain is listed for several things, the most serious one is reported
SEVERITY = ("malware", "phishing", "spam", "flood")
assert set(ISSUER_OF) <= set(REASONS), "a reason the core does not know"


@dataclass
class Rules:
    wave_keys: int = 5        # the same text from this many keys: spam
    flood_groups: int = 5     # the same text from one key in this many groups: flood
    key_after: int = 3        # findings about one key before the key is reported
    key_window: int = 7       # ... within this many days
    key_days: int = 30        # how long a key report lasts
    share_groups: int = 5     # one post shared by one key into this many groups: flood
    share_burst: int = 30     # plain shares of different posts by one key ...
    share_burst_minutes: int = 60   # ... within this many minutes: flood
    allow_keys: frozenset[str] = frozenset()      # never reported
    allow_domains: frozenset[str] = frozenset()   # never looked up


@dataclass
class Finding:
    """A post that should be reported, and why (``why`` becomes the report's note)."""
    message_id: str
    group: str
    key: str
    reason: str
    why: str

    @property
    def issuer(self) -> str:
        return ISSUER_OF[self.reason]


def _worst(reasons: set[str]) -> str:
    return next(r for r in SEVERITY if r in reasons)


def from_lists(message_id: str, group: str, key: str, hits: list[Hit]) -> list[Finding]:
    """A post with a link on a URI blocklist: one finding, the most serious reason."""
    if not hits:
        return []
    reason = _worst(set().union(*(h.reasons for h in hits)))
    h = next(h for h in hits if reason in h.reasons)
    return [Finding(message_id, group, key, reason, f"link to {h.domain}, on {h.zone}")]


def from_dupes(e: Entry, near: list[Entry], rules: Rules) -> list[Finding]:
    """The same text from many keys (spam) or from one key in many groups (flood).

    Returns findings for every post of the wave, earlier ones too - the wave is only
    seen once it is a wave."""
    same = near + [e]
    keys = {x.key for x in same}
    if len(keys) >= rules.wave_keys:
        why = f"the same text from {len(keys)} keys"
        return [Finding(x.message_id, x.group, x.key, "spam", why) for x in same]
    mine = [x for x in same if x.key == e.key]
    groups = {x.group for x in mine}
    if len(groups) >= rules.flood_groups:
        why = f"the same text in {len(groups)} groups"
        return [Finding(x.message_id, x.group, x.key, "flood", why) for x in mine]
    return []


def _kind(why: str) -> str:
    """What a finding's reason has in common with others': the list, not the domain."""
    if why.startswith("link to ") and ", on " in why:
        return "links on " + why.rsplit(", on ", 1)[1]
    return why


def note_for(findings: list[Finding]) -> str:
    """A report's note for people: the reasons, most common first, within NOTE_MAX."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[_kind(f.why)] = counts.get(_kind(f.why), 0) + 1
    parts = [f"{n} × {k}" if n > 1 else k
             for k, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    note = "automatic: " + "; ".join(parts)
    return note if len(note) <= NOTE_MAX else note[:NOTE_MAX - 1] + "…"


@dataclass
class KeyCounter:
    """Findings per key in time, to decide when a key is reported."""
    hits: dict[str, list[float]] = field(default_factory=dict)

    def add(self, key: str, ts: float, rules: Rules) -> bool:
        """Count a finding; True when the key has now earned a key report."""
        window = rules.key_window * 86400
        lst = [t for t in self.hits.get(key, []) if ts - t <= window] + [ts]
        self.hits[key] = lst
        return len(lst) >= rules.key_after
