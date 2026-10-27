"""What the watchman remembers between looks, in one JSON file.

- ``seen``: posts already checked (Message-ID to when), forgotten after ``SEEN_DAYS``;
- ``dupes``: the fingerprints of recent posts (``dupes.Index``);
- ``pending``: findings waiting for the next batch, posts and keys;
- ``published``: each report article published, with what it named, so a mistake can
  be taken back (``unreport``) and the rest published again;
- ``reported_posts`` / ``reported_keys``: what is reported now, so nothing is twice;
- ``spared``: posts and keys a person said were no spam - never reported again.

A first run sets ``fresh``: everything already in the groups is seen but not judged,
as the help bot leaves earlier posts alone.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from .decide import Finding, KeyCounter
from .dupes import Index

SEEN_DAYS = 14


class State:
    def __init__(self, path: Path | None):
        self.path = path
        self.fresh = True
        self.seen: dict[str, float] = {}
        self.dupes = Index()
        self.pending: list[Finding] = []
        self.pending_keys: dict[str, dict] = {}        # key -> {reason, why, until}
        self.published: dict[str, dict] = {}           # report Message-ID -> what it names
        self.reported_posts: dict[str, str] = {}       # post -> report Message-ID
        self.reported_keys: dict[str, str] = {}        # key -> until (RFC 3339)
        self.spared: set[str] = set()                  # posts and keys never to report
        self.keys = KeyCounter()
        self.last_batch = 0.0
        self.pending_labels: list[dict] = []           # {id, group, labels, why}
        self.labelled: dict[str, dict] = {}            # post -> {group, article}
        self.high: dict[str, int] = {}                 # group -> last article number read

    @classmethod
    def load(cls, path: Path) -> "State":
        st = cls(path)
        if not path.exists():
            return st
        d = json.loads(path.read_text())
        st.fresh = d.get("fresh", False)
        st.seen = d.get("seen", {})
        st.dupes = Index.from_json(d.get("dupes", []))
        st.pending = [Finding(**f) for f in d.get("pending", [])]
        st.pending_keys = d.get("pending_keys", {})
        st.published = d.get("published", {})
        st.reported_posts = d.get("reported_posts", {})
        st.reported_keys = d.get("reported_keys", {})
        st.spared = set(d.get("spared", []))
        st.keys = KeyCounter(d.get("key_hits", {}))
        st.last_batch = d.get("last_batch", 0.0)
        st.pending_labels = d.get("pending_labels", [])
        st.labelled = d.get("labelled", {})
        st.high = d.get("high", {})
        return st

    def save(self) -> None:
        if self.path is None:
            return
        now = time.time()
        self.seen = {m: t for m, t in self.seen.items() if now - t <= SEEN_DAYS * 86400}
        self.dupes.prune(now)
        d = {"fresh": self.fresh, "seen": self.seen, "dupes": self.dupes.to_json(),
             "pending": [asdict(f) for f in self.pending], "pending_keys": self.pending_keys,
             "published": self.published, "reported_posts": self.reported_posts,
             "reported_keys": self.reported_keys, "spared": sorted(self.spared),
             "key_hits": self.keys.hits, "last_batch": self.last_batch,
             "pending_labels": self.pending_labels, "labelled": self.labelled,
             "high": self.high}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(d))
        os.replace(tmp, self.path)

    def has_pending(self) -> bool:
        return bool(self.pending or self.pending_keys or self.pending_labels)

    def queue(self, f: Finding) -> bool:
        """Queue a finding unless the post is reported, queued or spared already."""
        if f.message_id in self.spared or f.key in self.spared or f.message_id in self.reported_posts:
            return False
        if any(p.message_id == f.message_id for p in self.pending):
            return False
        self.pending.append(f)
        return True
