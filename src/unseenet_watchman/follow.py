"""Following the network by push, instead of walking every group.

Each node is asked to push every new article (``Session.watch("*")``, UN-RFC 0008):
it then says "group, Message-ID" the moment something arrives, and the watchman
fetches only that group, and only what is new in it. Watching ``*`` tells a node
nothing about which groups the watchman cares about.

A full sweep still runs now and then (``sweep_minutes``) to catch what a push missed
- a node that cannot push, a connection that was down. Where every connection stays
up, the sweep finds nothing.

Reconnects wait 1-30 s at first, growing to five minutes while a node stays away, as
the clients do (UN-RFC 0043 section 4.4).
"""

from __future__ import annotations

import asyncio
import random
import time

from unseenet.client.session import Session, SessionError

from .state import State
from .watch import Config, look, look_group, own_keys, publish, wanted

NETWORK = (SessionError, OSError, ConnectionError, asyncio.IncompleteReadError)
SAVE_SECONDS = 300            # how often the offline cache (high-water marks) is written


class Follower:
    def __init__(self, s: Session, cfg: Config, st: State, lookups, dry_run: bool, log=print):
        self.s, self.cfg, self.st, self.lookups = s, cfg, st, lookups
        self.dry, self.log = dry_run, log
        self.dirty: set[str] = set()
        self.wake = asyncio.Event()
        self.pushing: set[str] = set()       # nodes whose push is up
        self._saved = time.monotonic()

    async def _pushed(self, gid: str, message_id: str) -> None:
        if wanted(gid, self.cfg) and message_id not in self.st.seen:
            self.dirty.add(gid)
            self.wake.set()

    async def watch_node(self, node: str) -> None:
        """Keep a push connection to ``node``; returns if it cannot push at all."""
        wait = 0.0                                   # 0: the next wait is the first
        while node in self.s.nodes:
            started = time.monotonic()
            try:
                self.pushing.add(node)
                if await self.s.watch(self._pushed, node=node) is False:
                    self.log(f"{self.s.node_label(node)} cannot push; the sweeps read it")
                    return
            except NETWORK:
                pass
            finally:
                self.pushing.discard(node)
            if time.monotonic() - started > 60:      # it was up a while: start over
                wait = 0.0
            wait = random.uniform(1, 30) if wait == 0 else min(wait * 2, 300.0)
            await asyncio.sleep(max(wait, self.s.retry_in(node)))

    async def handle_dirty(self) -> None:
        mine = own_keys(self.s)
        checked = new = 0
        while self.dirty:
            gid = self.dirty.pop()
            c, n = await look_group(self.s, gid, self.cfg, self.st, self.lookups, mine, self.log)
            checked, new = checked + c, new + n
        if checked:
            self.log(f"pushed: checked {checked} new posts, {new} findings")
            self.st.save()

    def save_if_due(self, force: bool = False) -> None:
        if force or time.monotonic() - self._saved >= SAVE_SECONDS:
            self.s.save_offline()                # where each group got to, for a restart
            self.st.save()
            self._saved = time.monotonic()

    async def run(self) -> None:
        await look(self.s, self.cfg, self.st, self.lookups, self.log)      # notes where all is
        self.save_if_due(force=True)
        tasks = [asyncio.create_task(self.watch_node(n)) for n in list(self.s.nodes)]
        next_sweep = time.monotonic() + self.cfg.sweep_minutes * 60
        try:
            while True:
                timeout = max(1.0, min(next_sweep - time.monotonic(), 60.0))
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout)
                except asyncio.TimeoutError:
                    pass
                self.wake.clear()
                await self.handle_dirty()
                if time.monotonic() >= next_sweep:
                    await look(self.s, self.cfg, self.st, self.lookups, self.log)
                    next_sweep = time.monotonic() + self.cfg.sweep_minutes * 60
                due = time.time() - self.st.last_batch >= self.cfg.batch_minutes * 60
                if self.st.has_pending() and due:
                    await publish(self.s, self.st, self.cfg, self.dry, self.log)
                self.save_if_due()
        finally:
            for t in tasks:
                t.cancel()
            self.save_if_due(force=True)
