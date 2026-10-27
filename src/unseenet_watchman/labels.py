"""Content labels (UN-RFC 0053): which posts carry profanity or sexual words.

A label describes, it never sanctions: no keys, no effect on nodes or postage, and
readers follow a labeller only by choice. This one gives two of the warning labels of
``unseenet.core.tags.WARNINGS``:

- ``profanity``: swearing, oaths and vulgar words (lort, fuck, scheiße, merde ...);
- ``sexual``: sexual and obscene words (porno, knulla, ficken ...).

Insults ("idiot", "tosse") are deliberately on neither list: they are rude behaviour
towards a person, not a kind of language a reader may want to be warned about - when
they become harassment, that is a report reason for people to judge (UN-RFC 0045).

**The watchman's own lists** (``wordlists/<label>-<language>.txt``), in nine languages:
Danish, Norwegian, Swedish, German, Dutch, English, French, Spanish and Italian. Words
that also mean something harmless in the same language (German "Schwanz", a tail;
Spanish "polla", a chick) are left out: better a missed label than a wrong one.

**Every list, always.** People mix languages - a Danish post with an English oath in
it is ordinary - so every list is checked on every post, and one place in the text
counts once however many lists name it.

**False friends** (``wordlists/false-friends.txt``) are words that are rude in one
language and ordinary in another ("slut" is rude in English and means "end" in Danish;
"fick" is rude in German and means "got" in Swedish). One of them counts only when the
post is in the language of the list that names it. The language is told from the
post's own small words, and by Lingua when they cannot tell (``detect``) - never from
its language header (unseenet#671): anybody can declare one language and swear in
another.

**Whole words and whole phrases only**, so a harmless word containing a rude one is
never a hit. Compound words ("lortesystem") are missed on purpose.

**A threshold**: one rude word in a long post is no reason to warn anybody. A post gets
a label with ``min_hits`` hits for it, or with one hit when it is a short post of at
most ``short_words`` words (a two-word insult is the whole post).

**The author first**: a label the author already gave the post as a tag (UN-RFC 0052)
is not given again.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

# Telling the language, and the words of a post: in the core since unseenet#686, so the
# clients' language suggestion and the watchman are the same code.
from unseenet.core.language import (LANGS, STOPWORDS, detect, language,  # noqa: F401
                                    lingua_language, looks_encoded, words)

LABELS = ("profanity", "sexual")

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


def merge(spans) -> list[tuple[int, int, str]]:
    """Spans without overlaps, the longest first: one place in the text, one hit."""
    out, taken = [], set()
    for i, j, t in sorted(spans, key=lambda x: (x[0] - x[1], x[0])):
        if not taken & set(range(i, j)):
            out.append((i, j, t))
            taken.update(range(i, j))
    return sorted(out)


def _lines(name: str) -> list[str]:
    text = files("unseenet_watchman").joinpath(f"wordlists/{name}").read_text("utf-8")
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


@lru_cache(maxsize=None)
def wordlist(label: str, lang: str) -> WordList:
    single, phrases = set(), []
    for line in _lines(f"{label}-{lang}.txt"):
        ws = words(line)
        if len(ws) == 1:
            single.add(ws[0])
        elif ws:
            phrases.append(tuple(ws))
    return WordList(frozenset(single), tuple(phrases))


@lru_cache(maxsize=None)
def false_friends() -> frozenset[str]:
    return frozenset(w for line in _lines("false-friends.txt") for w in words(line))


@dataclass
class Rules:
    min_hits: int = 2        # words or phrases of one label in a post ...
    short_words: int = 8     # ... or one, in a post of at most this many words


@dataclass
class Verdict:
    label: str
    hits: list[str]
    lang: str | None         # the post's language, told from its text; None: not told

    @property
    def why(self) -> str:
        n = len(self.hits)
        word = "word" if n == 1 else "words"
        return f"{n} {self.label} {word}" + (f", {self.lang} text" if self.lang else "")


def enough(n_hits: int, n_words: int, rules: Rules) -> bool:
    return n_hits >= rules.min_hits or (n_hits >= 1 and n_words <= rules.short_words)


def check(text: str, rules: Rules | None = None, author_tags=()) -> list[Verdict]:
    """The labels a post should carry, one verdict each (none: nothing to say)."""
    rules = rules or Rules()
    ws = words(text)
    if not ws:
        return []
    lang = detect(ws)
    friends = false_friends()
    out = []
    for label in LABELS:
        if label in author_tags:
            continue                                  # its author said so already
        spans = []
        for l in LANGS:
            spans += [sp for sp in wordlist(label, l).spans(ws)
                      if not (sp[2] in friends and l != lang)]
        hits = [t for _, _, t in merge(spans)]
        if enough(len(hits), len(ws), rules):
            out.append(Verdict(label, hits, lang))
    return out


def profanity(text: str, rules: Rules | None = None, author_tags=()) -> Verdict | None:
    """The ``profanity`` verdict alone, or None."""
    return next((v for v in check(text, rules, author_tags) if v.label == "profanity"), None)
