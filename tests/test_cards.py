"""watchman#27: deceptive link cards (UN-RFC 0059 section 11) - a card whose title has
nothing in common with its page is reported as phishing; anything less certain is not."""
import asyncio
import time
from types import SimpleNamespace

import pytest

from unseenet_watchman import cards, dnsbl, watch
from unseenet_watchman.state import State

from test_watch import cfg, msg

card_mod = pytest.importorskip("unseenet.core.cards")
BANK = "https://danske-bank-login.example/x"


def _card(url, title):
    return card_mod.Card(url=url, title=title)


@pytest.mark.parametrize("card,page,odd", [
    ("Log ind på Netbank - Danske Bank", "Cheap watches and pills online", True),
    ("Ansat i politiet snød Fleggaard: Nu er han dømt",
     "Ansat i politiet snød Fleggaard - nu er han dømt | B.T.", False),       # the same
    ("Breaking: famous actor dies", "Cookie consent", False),                  # a wall, not the page
    ("Breaking: famous actor dies", "Just a moment...", False),
    ("Breaking: famous actor dies", "Buy followers cheap today", True),
    ("Nyt fra kommunen", "Kommunen informerer om vejarbejde", False),          # a word shared
    ("Hej", "Cheap watches and pills online", False),                          # too short
    ("Log ind på Netbank - Danske Bank", "Home", False),                       # page says too little
])
def test_deceptive(card, page, odd):
    assert cards.deceptive(card, page) is odd


def test_the_site_name_and_description_count():
    assert not cards.deceptive("Proba-3 makes an artificial eclipse",
                               "Home page", "Proba-3 news and pictures", "ESA")


def _pages(found, asked):
    async def fetch(url):
        asked.append(url)
        if url not in found:
            raise OSError("did not answer")
        return SimpleNamespace(title=found[url], desc="", site="")
    return cards.Pages(fetch, log=lambda m: None)


def test_a_page_is_fetched_once_and_a_dead_one_is_no_finding():
    asked = []
    pages = _pages({BANK: "Cheap watches and pills online"}, asked)
    m = SimpleNamespace(card=_card(BANK, "Log ind på Netbank - Danske Bank"))
    why = asyncio.run(cards.check(m, pages))
    assert "danske-bank-login.example" in why and "Cheap watches" in why
    asyncio.run(cards.check(m, pages))
    assert asked == [BANK]                                     # kept, not fetched again
    gone = SimpleNamespace(card=_card("https://gone.example/", "Log ind på Netbank - Danske Bank"))
    assert asyncio.run(cards.check(gone, pages)) is None
    assert asyncio.run(cards.check(SimpleNamespace(card=None), pages)) is None


@pytest.mark.parametrize("on", [True, False])
def test_check_post_reports_it_as_phishing(tmp_path, on):
    m = msg(1, "dk.snak@x", "ed25519:spammer", f"Se {BANK}")
    m.card = _card(BANK, "Log ind på Netbank - Danske Bank")

    async def resolve(q):
        return None
    lk = dnsbl.Lookups([dnsbl.spamhaus_dqs("K")], resolve, log=lambda x: None)
    lk.card_pages = _pages({BANK: "Cheap watches and pills online"}, [])
    c = cfg(tmp_path)
    c.cards = on
    found = asyncio.run(watch.check_post(m, lk, State(tmp_path / "s.json"), c, time.time()))
    assert [f.reason for f in found] == (["phishing"] if on else [])
    if on:
        assert found[0].issuer == "phishing"
