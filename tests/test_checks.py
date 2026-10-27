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
    dbl = dnsbl.spamhaus_dqs("KEY")
    assert dbl.name == "KEY.dbl.dq.spamhaus.net"
    assert dbl.reasons("127.0.1.4") == {"phishing"}
    assert dbl.reasons("127.0.1.99") == set()          # an unknown code is never read
    assert dnsbl.SURBL.reasons("127.0.0.24") == {"phishing", "malware"}
    assert [z.name for z in dnsbl.default_zones()] == ["multi.surbl.org", "multi.uribl.com"]


def test_read_dns_json():
    ok = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' \
         b'{"Status":0,"Answer":[{"name":"x","type":1,"data":"127.0.0.254"}]}'
    assert dnsbl.read_dns_json(ok) == "127.0.0.254"
    chunked = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
               b'c\r\n{"Status":3}\r\n0\r\n\r\n')
    assert dnsbl.read_dns_json(chunked) is None
    with pytest.raises(dnsbl.ResolveError):
        dnsbl.read_dns_json(b'HTTP/1.1 200 OK\r\n\r\n{"Status":2}')
    with pytest.raises(dnsbl.ResolveError):
        dnsbl.read_dns_json(b'HTTP/1.1 503 Busy\r\n\r\n')


async def test_lookups_cache_and_refusal_pause():
    asked = []
    zones = [dnsbl.spamhaus_dqs("K"), dnsbl.SURBL]

    async def resolve(q):
        asked.append(q)
        return {"bad.example.K.dbl.dq.spamhaus.net": "127.0.1.2",
                "dbltest.com.K.dbl.dq.spamhaus.net": "127.0.1.2",
                "surbl-org-permanent-test-point.com.multi.surbl.org": "127.0.0.254",
                "x.example.multi.surbl.org": "127.0.0.1"}.get(q)

    logs = []
    lk = dnsbl.Lookups(zones, resolve, log=logs.append)
    hits = await lk.check("bad.example")
    assert [(h.zone, h.reasons) for h in hits] == [("K.dbl.dq.spamhaus.net", {"spam"})]
    await lk.check("bad.example")
    assert asked.count("bad.example.K.dbl.dq.spamhaus.net") == 1     # cached
    assert await lk.check("x.example") == []                         # SURBL refused ...
    assert "paused" in logs[-1]
    await lk.check("y.example")
    assert "y.example.multi.surbl.org" not in asked                  # ... and paused


async def test_a_zone_that_does_not_list_its_test_point_is_paused():
    async def silent(q):                 # a resolver refused silently: "does not exist"
        return None

    logs = []
    lk = dnsbl.Lookups([dnsbl.SURBL], silent, log=logs.append)
    await lk.selftest(force=True)
    assert lk.active() == [] and "test point" in logs[-1]


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
