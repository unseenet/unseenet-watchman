import asyncio
from pathlib import Path

from unseenet.core.crypto import Identity
from unseenet.core.groups import make_group_id

from unseenet_watchman import runner
from unseenet_watchman.follow import Follower
from unseenet_watchman.state import State
from unseenet_watchman.watch import Config

from test_watch import SPAM, FakeSession, lookups, msg

PK = Identity.generate().public_key
OPEN = make_group_id("dk.snak", PK)
INBOX = make_group_id("inbox", PK)


def cfg(tmp_path: Path) -> Config:
    return Config(vault=tmp_path / "v", state_file=tmp_path / "s.json", batch_minutes=0)


async def test_a_push_marks_only_wanted_groups_dirty(tmp_path):
    st = State(tmp_path / "s.json")
    f = Follower(FakeSession({}), cfg(tmp_path), st, lookups(), True, log=lambda m: None)
    await f._pushed(INBOX, "<a@x>")
    assert not f.dirty
    await f._pushed(OPEN, "<b@x>")
    assert f.dirty == {OPEN} and f.wake.is_set()
    st.seen["<c@x>"] = 0.0
    f.dirty.clear()
    await f._pushed(OPEN, "<c@x>")                   # already checked: nothing to fetch
    assert not f.dirty


async def test_handle_dirty_fetches_only_the_pushed_group(tmp_path):
    s = FakeSession({OPEN: [msg(1, OPEN, "ed25519:a", SPAM)], "other@x": []})
    fetched = []
    real = s.fetch_group

    async def spy(gid, **kw):
        fetched.append(gid)
        return await real(gid, **kw)
    s.fetch_group = spy
    st = State(tmp_path / "s.json")
    st.fresh = False
    f = Follower(s, cfg(tmp_path), st, lookups(), True, log=lambda m: None)
    f.dirty.add(OPEN)
    await f.handle_dirty()
    assert fetched == [OPEN]
    assert [p.reason for p in st.pending] == ["phishing"]


def test_use_nodes_replaces_the_list(tmp_path):
    class S:
        def __init__(self):
            self.data = {"nodes": ["a.onion", "b.onion"]}

        def add_node(self, n):
            if n not in self.data["nodes"]:
                self.data["nodes"].append(n)

        def save(self):
            pass

    s = S()
    runner.use_nodes(s, Config(vault=tmp_path, state_file=tmp_path, nodes=["127.0.0.1:1119"]))
    assert s.data["nodes"] == ["127.0.0.1:1119"]
    assert runner.is_local("127.0.0.1:1119") and not runner.is_local("abc.onion")
