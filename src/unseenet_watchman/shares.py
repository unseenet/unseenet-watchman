"""Shares, counted as NoCeM issuers counted crossposts (UN-RFC 0060 section 7.3, #30).

A share is an ordinary article and is judged as one: its comment's links and cards, and
its text among the waves. Two things only a share can do are counted here:

- **wide sharing**: one key sharing the same post into many groups. A well-behaved
  client stays within three groups besides the key's own feed, and a node should refuse
  a fourth, so ``share_groups`` (5) groups for one post is a flood;
- **share-flooding**: one key putting out many plain shares of different posts in a
  short time - ``share_burst`` (30) within ``share_burst_minutes`` (60).

Both are reported as ``flood``, every share of the run, earlier ones too - the run is
only seen once it is one. Nothing here counts how often a post is shared by different
people: that is what sharing is for (section 6: never a count).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .decide import Finding, Rules

KEEP_DAYS = 7               # how long a share is remembered for wide sharing


@dataclass
class Share:
    message_id: str
    group: str
    target: str              # the Message-ID it shares
    plain: bool              # without words of its own
    ts: float


def share_of(m) -> str | None:
    """The Message-ID a post shares, or None when it shares nothing."""
    target = getattr(m, "share_of", None)
    return target or None


def is_plain(m) -> bool:
    return getattr(m, "kind", None) == "share"


@dataclass
class ShareCounter:
    """Each key's recent shares."""
    by_key: dict[str, list[Share]] = field(default_factory=dict)

    def add(self, key: str, s: Share, rules: Rules) -> list[Finding]:
        """Count a share; the findings it completes (none for most)."""
        keep = max(KEEP_DAYS * 86400, rules.share_burst_minutes * 60)
        mine = [x for x in self.by_key.get(key, []) if s.ts - x.ts <= keep
                and x.message_id != s.message_id] + [s]
        self.by_key[key] = mine
        found: list[Finding] = []
        same = [x for x in mine if x.target == s.target]
        groups = {x.group for x in same}
        if len(groups) >= rules.share_groups:
            why = f"the same post shared into {len(groups)} groups"
            found += [Finding(x.message_id, x.group, key, "flood", why) for x in same]
        window = rules.share_burst_minutes * 60
        burst = [x for x in mine if x.plain and s.ts - x.ts <= window]
        if s.plain and len({x.target for x in burst}) >= rules.share_burst:
            why = f"{len(burst)} shares in {rules.share_burst_minutes} minutes"
            seen = {f.message_id for f in found}
            found += [Finding(x.message_id, x.group, key, "flood", why)
                      for x in burst if x.message_id not in seen]
        return found

    def prune(self, now: float) -> None:
        for key in list(self.by_key):
            lst = [x for x in self.by_key[key] if now - x.ts <= KEEP_DAYS * 86400]
            if lst:
                self.by_key[key] = lst
            else:
                del self.by_key[key]

    def to_json(self) -> dict:
        return {k: [asdict(x) for x in v] for k, v in self.by_key.items()}

    @classmethod
    def from_json(cls, d: dict) -> "ShareCounter":
        return cls({k: [Share(**x) for x in v] for k, v in d.items()})


def check(m, counter: ShareCounter, rules: Rules, now: float) -> list[Finding]:
    """The findings a post completes as a share; [] for a post that shares nothing."""
    target = share_of(m)
    if target is None or not m.author_key:
        return []
    return counter.add(m.author_key, Share(m.message_id, m.group, target, is_plain(m), now), rules)
