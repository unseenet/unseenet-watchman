"""Shares (UN-RFC 0060 section 7.3, #30): wide sharing of one post by one key, and
share-flooding; a plain share is never a wave by itself, many people sharing one post
is never a finding, and a share's comment is judged as any post."""

from datetime import datetime, timezone

from unseenet.client.session import Message

from unseenet_watchman import decide, shares, watch
from unseenet_watchman.state import State

from test_watch import SPAM, FakeSession, cfg, lookups

T = "<orig@x>"


def share(n, gid, key, target=T, body=None, plain=True):
    m = Message(n, f"<s{n}@x>", gid, author_key=key, date=datetime.now(timezone.utc),
                body=body if body is not None else f"unseenet:dk.snak@f?m={target.strip('<>')}\n",
                kind="share" if plain else "post")
    m.share_of, m.share_group = target, "dk.snak@f"
    return m


def test_wide_sharing_one_post_by_one_key():
    c, r = shares.ShareCounter(), decide.Rules()
    groups = ["feed@k", "a@f", "b@f", "c@f"]            # the feed and three more: fine
    for i, g in enumerate(groups):
        assert c.add("k", shares.Share(f"<s{i}@x>", g, T, True, 100.0 + i), r) == []
    found = c.add("k", shares.Share("<s9@x>", "d@f", T, True, 200.0), r)
    assert {f.message_id for f in found} == {f"<s{i}@x>" for i in range(4)} | {"<s9@x>"}
    assert {f.reason for f in found} == {"flood"} and "5 groups" in found[0].why
    # sharing again into the same group replaces, it is not counted twice
    c2 = shares.ShareCounter()
    for i in range(6):
        assert c2.add("k", shares.Share(f"<t{i}@x>", "feed@k", T, True, float(i)), r) == []


def test_many_people_sharing_one_post_is_never_a_finding():
    c, r = shares.ShareCounter(), decide.Rules()
    for i in range(50):
        assert c.add(f"k{i}", shares.Share(f"<s{i}@x>", f"feed@k{i}", T, True, float(i)), r) == []


def test_share_flooding():
    c, r = shares.ShareCounter(), decide.Rules(share_burst=5, share_burst_minutes=10)
    for i in range(4):
        assert c.add("k", shares.Share(f"<s{i}@x>", "feed@k", f"<t{i}@x>", True, i * 60.0), r) == []
    # a share with words of its own is not counted in a burst
    assert c.add("k", shares.Share("<c@x>", "feed@k", "<tc@x>", False, 250.0), r) == []
    found = c.add("k", shares.Share("<s4@x>", "feed@k", "<t4@x>", True, 300.0), r)
    assert len(found) == 5 and "5 shares in 10 minutes" in found[0].why
    # spread out over time: no burst
    c2 = shares.ShareCounter()
    for i in range(8):
        assert c2.add("k", shares.Share(f"<u{i}@x>", "feed@k", f"<t{i}@x>", True, i * 700.0), r) == []


def test_round_trip_and_prune(tmp_path):
    st = State(tmp_path / "s.json")
    st.fresh = False
    st.shares.add("k", shares.Share("<s@x>", "feed@k", T, True, 0.0), decide.Rules())
    st.shares.add("j", shares.Share("<t@x>", "feed@j", T, True, 4e9), decide.Rules())
    st.save()                                           # forgets what is older than a week
    back = State.load(tmp_path / "s.json")
    assert list(back.shares.by_key) == ["j"] and back.shares.by_key["j"][0].target == T


async def test_shares_through_look(tmp_path):
    s = FakeSession({"a@f": [], "b@f": [], "c@f": [], "d@f": [], "feed@k": []})
    st, c = State(tmp_path / "s.json"), cfg(tmp_path)
    await watch.look(s, c, st, lookups(), log=lambda m: None)         # the first look
    # five keys sharing the same post plainly: the same body, but no wave
    s.groups["feed@k"] = [share(i, "feed@k", f"ed25519:p{i}") for i in range(5)]
    assert await watch.look(s, c, st, lookups(), log=lambda m: None) == 0
    # one key sharing it into five groups: flood
    for n, g in enumerate(["a@f", "b@f", "c@f", "d@f", "feed@k"], start=10):
        s.groups[g] = s.groups[g] + [share(n, g, "ed25519:wide")]
    assert await watch.look(s, c, st, lookups(), log=lambda m: None) == 5
    assert {(p.key, p.reason) for p in st.pending} == {("ed25519:wide", "flood")}
    # a share's comment is judged as any post: its link is phishing
    s.groups["a@f"].append(share(30, "a@f", "ed25519:c", body=SPAM, plain=False))
    await watch.look(s, c, st, lookups(), log=lambda m: None)
    assert any(p.message_id == "<s30@x>" and p.reason == "phishing" for p in st.pending)
