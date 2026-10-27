import asyncio

import pytest

from unseenet_watchman import decide, dnsbl, dupes, uris


def test_hosts_from_links_markdown_and_www():
    text = ("Buy at https://Shop.Example.com/x?y=1 and [here](http://evil.test/a), "
            "www.cheap.example.org. Also http://10.0.0.1/ and http://abc.onion/ "
            "and https://user:pw@login.example.net:8443/p")
    assert uris.hosts(text) == ["shop.example.com", "evil.test", "www.cheap.example.org",
                                "login.example.net"]


def test_idna_host():
    assert uris.hosts("https://bücher.example/") == ["xn--bcher-kva.example"]


def test_lookup_names():
    assert uris.lookup_names("example.com") == ["example.com"]
    assert uris.lookup_names("www.example.com") == ["example.com"]
    assert uris.lookup_names("a.b.example.co.uk") == ["a.b.example.co.uk", "b.example.co.uk",
                                                     "example.co.uk"]


def test_allowed():
    allow = frozenset({"github.com"})
    assert uris.allowed("github.com", allow) and uris.allowed("gist.github.com", allow)
    assert not uris.allowed("notgithub.com", allow)


def test_zone_codes_and_bits():
    dbl = dnsbl.DEFAULT_ZONES[0]
    assert dbl.reasons("127.0.1.4") == {"phishing"}
    assert dbl.reasons("127.0.1.99") == set()          # an unknown code is never read
    surbl = dnsbl.DEFAULT_ZONES[1]
    assert surbl.reasons("127.0.0.24") == {"phishing", "malware"}


async def test_lookups_cache_and_pause():
    asked = []

    async def resolve(q):
        asked.append(q)
        return {"bad.example.dbl.spamhaus.org": "127.0.1.2",
                "x.example.multi.surbl.org": "127.0.0.1"}.get(q)

    logs = []
    lk = dnsbl.Lookups(dnsbl.DEFAULT_ZONES, resolve, log=logs.append)
    hits = await lk.check("bad.example")
    assert [(h.zone, h.reasons) for h in hits] == [("dbl.spamhaus.org", {"spam"})]
    await lk.check("bad.example")
    assert asked.count("bad.example.dbl.spamhaus.org") == 1       # cached
    assert await lk.check("x.example") == []                      # SURBL refused ...
    assert "paused" in logs[-1]
    await lk.check("y.example")
    assert "y.example.multi.surbl.org" not in asked               # ... and paused


async def test_tor_resolve_against_a_fake_socks_port():
    async def serve(reader, writer):
        assert await reader.readexactly(3) == b"\x05\x01\x00"
        writer.write(b"\x05\x00")
        head = await reader.readexactly(5)
        name = (await reader.readexactly(head[4])).decode()
        await reader.readexactly(2)
        if name == "listed.example.dbl.spamhaus.org":
            writer.write(b"\x05\x00\x00\x01" + bytes([127, 0, 1, 2]) + b"\x00\x00")
        else:
            writer.write(b"\x05\x04\x00\x01" + bytes(6))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert await dnsbl.tor_resolve("listed.example.dbl.spamhaus.org", port=port) == "127.0.1.2"
        assert await dnsbl.tor_resolve("clean.example.dbl.spamhaus.org", port=port) is None
    with pytest.raises(dnsbl.TorResolveError):
        await dnsbl.tor_resolve("x", port=port)


SPAM = ("Amazing offer today only: get rich quick with our crypto plan, "
        "send 100 coins to http://scam.example/join and receive 1000 back within days")


def test_fingerprint_ignores_quotes_numbers_and_link_paths():
    a = dupes.fingerprint(SPAM)
    b = dupes.fingerprint("> what someone said\n" + SPAM.replace("100", "250")
                          .replace("/join", "/other") + "\n--\nsignature")
    assert a is not None and dupes.distance(a, b) <= dupes.MAX_DISTANCE
    assert dupes.fingerprint("thanks, that helped!") is None


def test_wave_from_many_keys_reports_all_posts():
    ix, rules = dupes.Index(), decide.Rules(wave_keys=3)
    fp = dupes.fingerprint(SPAM)
    out = []
    for i in range(3):
        e = dupes.Entry(fp, f"<m{i}@x>", f"g{i}@fp", f"key{i}", 0.0)
        out = decide.from_dupes(e, ix.add(e), rules)
    assert sorted(f.message_id for f in out) == ["<m0@x>", "<m1@x>", "<m2@x>"]
    assert {f.reason for f in out} == {"spam"}


def test_flood_from_one_key():
    ix, rules = dupes.Index(), decide.Rules(flood_groups=3)
    fp = dupes.fingerprint(SPAM)
    out = []
    for i in range(3):
        e = dupes.Entry(fp, f"<m{i}@x>", f"g{i}@fp", "key", 0.0)
        out = decide.from_dupes(e, ix.add(e), rules)
    assert {f.reason for f in out} == {"flood"} and len(out) == 3


def test_index_round_trip_and_prune():
    ix = dupes.Index(window_seconds=10)
    ix.add(dupes.Entry(1, "<a@x>", "g@f", "k", 0.0))
    ix.add(dupes.Entry(1, "<b@x>", "g@f", "k", 100.0))
    ix.prune(now=105.0)
    back = dupes.Index.from_json(ix.to_json())
    assert [e.message_id for e in back.entries] == ["<b@x>"]
    assert back.near(1)


def test_from_lists_picks_the_most_serious_reason():
    hits = [dnsbl.Hit("x.example", "multi.surbl.org", {"spam"}),
            dnsbl.Hit("x.example", "dbl.spamhaus.org", {"phishing"})]
    [f] = decide.from_lists("<m@x>", "g@f", "k", hits)
    assert f.reason == "phishing" and f.issuer == "phishing"
    assert f.why == "link to x.example, on dbl.spamhaus.org"


def test_note():
    fs = [decide.Finding("<a@x>", "g", "k", "spam", "link to a.example, on dbl.spamhaus.org"),
          decide.Finding("<b@x>", "g", "k", "spam", "link to b.example, on dbl.spamhaus.org"),
          decide.Finding("<c@x>", "g", "k", "spam", "the same text from 7 keys")]
    assert decide.note_for(fs) == "automatic: 2 × links on dbl.spamhaus.org; the same text from 7 keys"
    long = [decide.Finding(f"<{i}@x>", "g", "k", "spam", f"reason number {i} " * 5) for i in range(20)]
    assert len(decide.note_for(long)) <= 200


def test_key_only_after_repeated_findings():
    kc, rules = decide.KeyCounter(), decide.Rules(key_after=3, key_window=7)
    assert not kc.add("k", 0, rules) and not kc.add("k", 3600, rules)
    assert kc.add("k", 7200, rules)
    kc2 = decide.KeyCounter()
    kc2.add("k", 0, rules), kc2.add("k", 1, rules)
    assert not kc2.add("k", 8 * 86400, rules)          # the first two are out of the window
