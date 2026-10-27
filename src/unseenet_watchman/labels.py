"""Content labels (UN-RFC 0053): which posts carry profanity.

A label describes, it never sanctions: no keys, no effect on nodes or postage, and
readers follow a labeller only by choice. This one only gives the warning label
``profanity`` (``unseenet.core.tags.WARNINGS``).

**Every list, always.** People mix languages - a Danish post with an English insult
in it is ordinary - so every list is checked on every post, and a place in the text
counts once however many lists name it.

**The language only removes false friends**: a word that is rude in one language and
ordinary in another ("slut" is rude in English and means "end" in Danish). The post's
language is told from its common small words ("og", "der", "und", "the" ...), and a
word on ``wordlists/harmless-<language>.txt`` is not counted in a post in that language.

**Never from the post's own language header** (``Content-Language``, unseenet#671):
anybody can write one thing there and swear in another language, so it decides
nothing here.

**Whole words and whole phrases only**, so a harmless word containing a rude one is
never a hit (the Scunthorpe problem). Compound words ("lortesystem") are missed on
purpose; better a missed label than a wrong one.

**A threshold**: one rude word in a long post is no reason to warn anybody. A post
gets the label with ``min_hits`` hits, or with one hit when it is a short post of at
most ``short_words`` words (a two-word insult is the whole post).

**The author first**: a post its author already tagged ``profanity`` (UN-RFC 0052)
needs no label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

LABEL = "profanity"
LANGS = ("da", "de", "en")

# Frequent small words that tell the languages apart (words shared by two of them,
# such as "in", "so", "man", "hat", are left out).
STOPWORDS = {
    "da": frozenset("og jeg det at en til er som på de med han af for ikke der var mig "
                    "sig men et har om vi min havde hun nu over da fra du ud sin dem "
                    "os op hvad skal selv her alle vil blev kunne ind når være dog noget "
                    "ville jo deres efter ned skulle denne end dette mit også under have "
                    "dig anden hende mine alt meget sit sine vor mod disse hvis din nogle "
                    "hos blive mange ad bliver hans jer sådan dit hvor".split()),
    "de": frozenset("und ich das ist nicht sie es der die den mit sich auf dem zu ein "
                    "eine einen auch wie als von bei nur noch nach wenn aber oder wir "
                    "ihr wird werden kann haben sind war mir mich dich dir uns euch "
                    "schon sehr immer doch dass weil diese dieser kein keine nichts "
                    "über unter gegen ohne durch heute hier jetzt warum".split()),
    "en": frozenset("the and is are was were be been to of that this it you he she we "
                    "they not with on at by from have has had do does did but or if "
                    "what which who would could should will can just about there their "
                    "them my your our very really because when then than these those "
                    "some any been being into out up".split()),
}
# Letters and digits, and the @ $ * that spellings like "@$$" and "f*ck" use; no
# other punctuation, so "lort," is "lort".
_WORD = re.compile(r"[\w@$*]+(?:['’-][\w@$*]+)*")


def looks_encoded(line: str) -> bool:
    """A line of encoded data (base64, uuencode, yEnc) rather than text: long, and
    without the spaces and the word lengths of a language. Its letter salad would
    otherwise be read as words ("h0r" in a uuencoded file, found on Usenet)."""
    s = line.strip()
    if len(s) < 40:
        return False
    if " " not in s:
        return True
    ws = s.split()
    return sum(len(w) for w in ws) / len(ws) > 12 or sum(len(w) <= 2 for w in ws) / len(ws) > 0.6


def words(text: str) -> list[str]:
    """The words of a post, lower case, without quoted lines, encoded data and the
    signature."""
    keep = []
    for line in (text or "").splitlines():
        if line.rstrip() == "--":
            break
        if not line.lstrip().startswith(">") and not looks_encoded(line):
            keep.append(line)
    return [w.lower() for w in _WORD.findall("\n".join(keep))]


def language(ws: list[str], min_hits: int = 3) -> str | None:
    """The post's language among LANGS, or None when it cannot be told: the language
    with most common small words, at least ``min_hits`` and twice the next one's."""
    counts = sorted(((sum(w in STOPWORDS[l] for w in ws), l) for l in LANGS), reverse=True)
    (best, lang), (second, _) = counts[0], counts[1]
    return lang if best >= min_hits and best >= 2 * second else None


@dataclass(frozen=True)
class WordList:
    single: frozenset[str]
    phrases: tuple[tuple[str, ...], ...]

    def spans(self, ws: list[str]) -> list[tuple[int, int, str]]:
        """Where the list's words and phrases are in ``ws``: (start, end, text)."""
        out = [(i, i + 1, w) for i, w in enumerate(ws) if w in self.single]
        for p in self.phrases:
            n = len(p)
            out += [(i, i + n, " ".join(p)) for i in range(len(ws) - n + 1) if tuple(ws[i:i + n]) == p]
        return out

    def hits(self, ws: list[str]) -> list[str]:
        """The words and phrases of the list in ``ws``; a word inside a matched phrase
        counts once, as the phrase."""
        return [t for _, _, t in merge(self.spans(ws))]


def merge(spans) -> list[tuple[int, int, str]]:
    """Spans without overlaps, the longest first: one place in the text, one hit."""
    out, taken = [], set()
    for i, j, t in sorted(spans, key=lambda x: (x[0] - x[1], x[0])):
        if not taken & set(range(i, j)):
            out.append((i, j, t))
            taken.update(range(i, j))
    return sorted(out)


@lru_cache(maxsize=None)
def harmless(lang: str) -> frozenset[str]:
    """Words that are on another language's list but ordinary in ``lang``."""
    try:
        text = files("unseenet_watchman").joinpath(f"wordlists/harmless-{lang}.txt").read_text("utf-8")
    except FileNotFoundError:
        return frozenset()
    return frozenset(w for line in text.splitlines() if not line.startswith("#") for w in words(line))


@lru_cache(maxsize=None)
def wordlist(lang: str) -> WordList:
    text = files("unseenet_watchman").joinpath(f"wordlists/profanity-{lang}.txt").read_text("utf-8")
    single, phrases = set(), []
    for line in text.splitlines():
        ws = words(line)
        if len(ws) == 1:
            single.add(ws[0])
        elif ws:
            phrases.append(tuple(ws))
    return WordList(frozenset(single), tuple(phrases))


@dataclass
class Rules:
    min_hits: int = 2        # rude words or phrases for the label ...
    short_words: int = 8     # ... or one, in a post of at most this many words


@dataclass
class Verdict:
    hits: list[str]
    lang: str | None         # the post's language, told from its text; None: not told

    @property
    def why(self) -> str:
        n = len(self.hits)
        return f"{n} rude word{'s' if n != 1 else ''}" + (f", {self.lang} text" if self.lang else "")


def enough(n_hits: int, n_words: int, rules: Rules) -> bool:
    return n_hits >= rules.min_hits or (n_hits >= 1 and n_words <= rules.short_words)


def profanity(text: str, rules: Rules | None = None, author_tags=()) -> Verdict | None:
    """A verdict when the post should carry ``profanity``, else None."""
    rules = rules or Rules()
    if LABEL in author_tags:
        return None                                   # its author said so already
    ws = words(text)
    if not ws:
        return None
    lang = language(ws)
    friends = harmless(lang) if lang else frozenset()
    own = wordlist(lang) if lang else None
    spans = []
    for l in LANGS:
        spans += [sp for sp in wordlist(l).spans(ws)
                  if not (sp[1] - sp[0] == 1 and sp[2] in friends and (own is None or sp[2] not in own.single))]
    hits = [t for _, _, t in merge(spans)]
    return Verdict(hits, lang) if enough(len(hits), len(ws), rules) else None
