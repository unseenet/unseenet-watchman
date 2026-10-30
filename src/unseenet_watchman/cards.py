"""Deceptive link cards (watchman#27, UN-RFC 0059 section 11).

A link card's title and description are the poster's: a card can claim to be a bank's
login page while its link goes somewhere else - the domain is always shown from the link,
but the title is what people read. With ``cards = true`` the watchman makes its own card
for the link, over Tor, and reports a post (reason ``phishing``: a scam or fake link)
whose card's title has nothing in common with the page: not a word of the page's title,
description or site name.

Careful by design: pages change their titles, answer Tor with a cookie wall or a
challenge, or give no title - none of that is reported. Only a card title of at least three words, against a page
that answered with a title of its own, sharing no word of four letters or more. The
picture is not compared (a picture says nothing a program can read reliably). Each link
is fetched once a day at most.
"""

from __future__ import annotations

import re
import time

MIN_WORDS = 3                 # a shorter card title is not judged
PAGE_TTL = 24 * 3600          # a page's card is kept this long
_WORD = re.compile(r"[^\W\d_]{4,}")
# what a page says when it is not answering Tor with itself: a wall, not the page
WALLS = frozenset({"cookie", "cookies", "consent", "captcha", "moment", "attention", "access",
                   "denied", "blocked", "robot", "robots", "verify", "verifying", "cloudflare",
                   "forbidden", "error", "found", "unavailable", "security", "checking",
                   "challenge", "privacy", "samtykke", "adgang", "fejl"})


def words(text: str) -> set[str]:
    """The words of four letters or more, folded: what two titles can share."""
    return {w.casefold() for w in _WORD.findall(text or "")}


def deceptive(card_title: str, page_title: str, page_desc: str = "", page_site: str = "") -> bool:
    """True when a card's title has nothing in common with its page - and only when
    there is enough on both sides to tell."""
    said, page = words(card_title), words(page_title)
    if len(said) < MIN_WORDS or len(page) < 2 or page & WALLS:
        return False
    return not said & words(" ".join((page_title, page_desc, page_site)))


class Pages:
    """The pages behind cards, made with ``fetch(url)`` (a coroutine giving an object with
    ``title``, ``desc`` and ``site``, or raising) and kept a day."""

    def __init__(self, fetch, log=print):
        self.fetch, self.log = fetch, log
        self._cache: dict[str, tuple[float, object | None]] = {}

    async def page(self, url: str):
        hit = self._cache.get(url)
        if hit and time.time() - hit[0] < PAGE_TTL:
            return hit[1]
        try:
            got = await self.fetch(url)
        except Exception as exc:  # noqa: BLE001 - an unreachable page is no finding
            self.log(f"card page not read: {url}: {exc}")
            got = None
        self._cache[url] = (time.time(), got)
        return got


async def check(m, pages: Pages) -> str | None:
    """Why a post's card is deceptive (the report's note), or None."""
    card = getattr(m, "card", None)
    if card is None or not card.url:
        return None
    page = await pages.page(card.url)
    if page is None or not deceptive(card.title, page.title, page.desc, page.site):
        return None
    return (f"link card says {card.title[:60]!r}, its page {card.domain} says "
            f"{page.title[:60]!r}")
