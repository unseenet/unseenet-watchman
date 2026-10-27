from datetime import datetime, timezone
from pathlib import Path

from unseenet.client.session import GroupInfo, Message

from unseenet_watchman import decide, dnsbl, watch
from unseenet_watchman.state import State

SPAM = ("Amazing offer today only: get rich quick with our crypto plan, "
        "send 100 coins to http://scam.example/join and receive 1000 back within days")


class FakeIdentity:
    def __init__(self, k):
        self.key_text = k


class FakeSession:
    """Just what watch.py uses."""

    def __init__(self, groups):
        self.groups = groups                     # group id -> [Message]
        self.data = {"identities": {"spam": {}, "phishing": {}}}
        self.published, self.withdrawn = [], []
        self._high = {}

    def identity(self, name=None):
        return FakeIdentity(f"ed25519:me-{name}")

    async def list_groups(self, pattern="*"):
        return [GroupInfo(g) for g in self.groups]

    async def fetch_group(self, gid, skip=None, keep=True):
        """As the core with keep=False: only what came after the last read."""
        msgs = self.groups[gid]
        start = self._high.get(gid, 0)
        self._high[gid] = len(msgs)
        return msgs[start:]

    async def skip_to_now(self, gid):
        self._high[gid] = len(self.groups[gid])
        return self._high[gid]

    def visible(self, msgs):
        return msgs

    async def publish_report(self, posts=(), keys=(), note="", issuer=None):
        self.published.append((issuer, list(posts), list(keys), note))
        return f"<r{len(self.published)}@x>"

    async def withdraw_report(self, mid, issuer=None):
        self.withdrawn.append((mid, issuer))


def msg(n, gid, key, body):
    return Message(n, f"<m{n}@x>", gid, author_key=key, body=body,
                   date=datetime.now(timezone.utc))


def cfg(tmp_path: Path, **rules) -> watch.Config:
    return watch.Config(vault=tmp_path / "v", state_file=tmp_path / "state.json",
                        rules=decide.Rules(**rules))


def lookups():
    async def resolve(q):
        return {"scam.example.K.dbl.dq.spamhaus.net": "127.0.1.4",
                "dbltest.com.K.dbl.dq.spamhaus.net": "127.0.1.2"}.get(q)
    return dnsbl.Lookups([dnsbl.spamhaus_dqs("K")], resolve, log=lambda m: None)


def test_wanted():
    from unseenet.core.crypto import Identity
    from unseenet.core.groups import make_group_id
    pk = Identity.generate().public_key
    c = watch.Config(vault=Path("v"), state_file=Path("s"), skip_groups=["alt.test*"])
    assert watch.wanted(make_group_id("dk.snak", pk), c)
    assert not watch.wanted(make_group_id("inbox", pk), c)
    assert not watch.wanted(make_group_id("reports", pk), c)
    assert watch.wanted(make_group_id("feed", pk), c)          # others comment there
    assert not watch.wanted(make_group_id("alt.test.x", pk), c)


async def test_first_look_leaves_earlier_posts_alone(tmp_path):
    s = FakeSession({"dk.snak@f": [msg(1, "dk.snak@f", "ed25519:a", SPAM)]})
    st, c = State(tmp_path / "state.json"), cfg(tmp_path)
    assert await watch.look(s, c, st, lookups(), log=lambda m: None) == 0
    assert not st.fresh and not st.pending and st.high == {"dk.snak@f": 1}   # remembered
    s.groups["dk.snak@f"].append(msg(2, "dk.snak@f", "ed25519:b", SPAM))
    await watch.look(s, c, st, lookups(), log=lambda m: None)
    assert [p.message_id for p in st.pending] == ["<m2@x>"]      # only what came after


async def test_phishing_link_found_and_published_as_phishing(tmp_path):
    s = FakeSession({"dk.snak@f": []})
    st, c = State(tmp_path / "state.json"), cfg(tmp_path)
    await watch.look(s, c, st, lookups(), log=lambda m: None)         # first look
    s.groups["dk.snak@f"] = [msg(2, "dk.snak@f", "ed25519:a", SPAM)]
    assert await watch.look(s, c, st, lookups(), log=lambda m: None) == 1
    assert [(f.reason, f.issuer) for f in st.pending] == [("phishing", "phishing")]
    # a dry run publishes nothing, and does not report it twice
    assert await watch.publish(s, st, c, dry_run=True, log=lambda m: None) == 1
    assert s.published == [] and not st.pending and "<m2@x>" in st.reported_posts
    assert not st.queue(decide.Finding("<m2@x>", "dk.snak@f", "ed25519:a", "phishing", "again"))


async def test_own_keys_allowed_keys_and_reactions_are_not_judged(tmp_path):
    s = FakeSession({"g@f": []})
    st, c = State(tmp_path / "s.json"), cfg(tmp_path, allow_keys=frozenset({"ed25519:friend"}))
    await watch.look(s, c, st, lookups(), log=lambda m: None)
    r = msg(5, "g@f", "ed25519:b", SPAM)
    r.kind = "reaction"
    s.groups["g@f"] = [msg(3, "g@f", "ed25519:me-spam", SPAM), msg(4, "g@f", "ed25519:friend", SPAM), r]
    assert await watch.look(s, c, st, lookups(), log=lambda m: None) == 0


async def test_publish_one_article_per_issuer_with_keys(tmp_path):
    st, c = State(tmp_path / "s.json"), cfg(tmp_path, key_after=2)
    found = [decide.Finding(f"<m{i}@x>", "g@f", "ed25519:bad", "spam", "the same text from 6 keys")
             for i in range(2)]
    found.append(decide.Finding("<m9@x>", "g@f", "ed25519:other", "malware", "link to x.example, on multi.surbl.org"))
    watch.queue_findings(found, st, c, 0.0, log=lambda m: None)
    assert "ed25519:bad" in st.pending_keys
    s = FakeSession({})
    assert await watch.publish(s, st, c, dry_run=False, log=lambda m: None) == 2
    issuers = {p[0]: p for p in s.published}
    assert set(issuers) == {"spam", "phishing"}
    spam = issuers["spam"]
    assert [p[0] for p in spam[1]] == ["<m0@x>", "<m1@x>"]
    assert [k[0] for k in spam[2]] == ["ed25519:bad"]
    assert spam[3].startswith("automatic: ")
    assert not st.pending and not st.pending_keys and "ed25519:bad" in st.reported_keys


async def test_unreport_withdraws_and_publishes_the_rest_again(tmp_path):
    st, c = State(tmp_path / "s.json"), cfg(tmp_path)
    for i in range(3):
        st.queue(decide.Finding(f"<m{i}@x>", "g@f", f"ed25519:k{i}", "spam", "the same text from 5 keys"))
    s = FakeSession({})
    await watch.publish(s, st, c, dry_run=False, log=lambda m: None)
    assert await watch.unreport(s, st, "<m1@x>", log=lambda m: None)
    assert s.withdrawn == [("<r1@x>", "spam")]
    assert sorted(f.message_id for f in st.pending) == ["<m0@x>", "<m2@x>"]
    assert "<m1@x>" in st.spared
    assert not st.queue(decide.Finding("<m1@x>", "g@f", "ed25519:k1", "spam", "again"))


def test_state_round_trip(tmp_path):
    st = State(tmp_path / "s.json")
    st.fresh = False
    st.queue(decide.Finding("<a@x>", "g@f", "k", "spam", "why"))
    st.spared.add("<b@x>")
    st.save()
    back = State.load(tmp_path / "s.json")
    assert not back.fresh and back.pending[0].message_id == "<a@x>" and "<b@x>" in back.spared


def test_restore_high_after_a_restart(tmp_path):
    st = State(tmp_path / "s.json")
    st.high = {"g@f": 42}
    s = FakeSession({})
    s._high = {"g@f": 7}
    watch.restore_high(s, st)
    assert s._high == {"g@f": 42}
