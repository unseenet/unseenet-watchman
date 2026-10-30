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

**Mentioned, not used** (#11). A word in quotation marks ("kneppe", 'slut', «fan»), in
``code`` or a code block, or right after "ordet", "the word", "das Wort" and the like is
talked about, not said - a debate about a word, the watchman's own release notes. It
does not count. A longer quotation (more than three words) is reported speech and does.

**Written to slip past** (#11): spelt apart ("f u c k"), digits for letters ("h0r",
"sh1t"), letters said three times ("fuuuck") and letters masked ("f*ck") are read as
the word they spell. In the post's own language, and in English, a listed word at the
start or end of a longer word counts too ("lortesystem", "scheißegal", "shitshow"), with
the lists of the post's language family (da/no/sv, de/nl; all when it cannot be told)
and English -
except the ordinary words of ``wordlists/harmless.txt`` (cockpit, Pissarro) and the
words marked whole-word only. Languages that do not join words (French, Spanish,
Italian) are left out of this: "disputa" is no compound of "puta".

**Weights and density** (#11). A word is strong (2) or mild (1); a list line ending in
``!`` is strong, ``~`` mild, and otherwise profanity is mild and sexual words strong.
A label needs a score of ``min_score`` - two mild words or one strong one - or any hit
in a short post of at most ``short_words`` words (a two-word insult is the whole post).
A post longer than ``long_words`` also needs ``min_density`` points per 100 words: a
few oaths in a long essay are no reason to warn anybody.

**The author first**: a label the author already gave the post as a tag (UN-RFC 0052)
is not given again.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

# Telling the language, and the words of a post: in the core since unseenet#686, so the
# clients' language suggestion and the watchman are the same code.
from unseenet.core.language import (LANGS, STOPWORDS, detect, language,  # noqa: F401
                                    lingua_language, looks_encoded, words)

LABELS = ("profanity", "sexual")
DEFAULT_WEIGHT = {"profanity": 1, "sexual": 2}
STRONG, MILD = 2, 1
# Languages that join words, by family: a short Danish post is easily told as
# Norwegian, so a post's compounds are read with its whole family's lists, and English.
FAMILIES = (("da", "no", "sv"), ("de", "nl"), ("en",))
_MIN_IN_COMPOUND = 4                                 # shorter words hide in too many


@dataclass(frozen=True)
class WordList:
    single: dict[str, int]                           # word -> weight
    phrases: dict[tuple[str, ...], int]
    whole_only: frozenset[str] = frozenset()         # never part of a compound

    def spans(self, ws: list[str]) -> list[tuple[int, int, str]]:
        """Where the list's words and phrases are in ``ws``: (start, end, text). One
        look-up a word, however long the lists grow."""
        out = []
        starts = _by_first(self.phrases)
        for i, w in enumerate(ws):
            if w in self.single:
                out.append((i, i + 1, w))
            for p in starts.get(w, ()):
                if tuple(ws[i:i + len(p)]) == p:
                    out.append((i, i + len(p), " ".join(p)))
        return out

    def weight(self, text: str) -> int:
        return self.single.get(text) or self.phrases.get(tuple(text.split()), 0)


@lru_cache(maxsize=None)
def _first_words(phrases: frozenset) -> dict[str, list[tuple[str, ...]]]:
    out: dict[str, list[tuple[str, ...]]] = {}
    for p in phrases:
        out.setdefault(p[0], []).append(p)
    return out


def _by_first(phrases: dict) -> dict[str, list[tuple[str, ...]]]:
    return _first_words(frozenset(phrases))


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
    single, phrases, whole = {}, {}, set()
    for line in _lines(f"{label}-{lang}.txt"):
        parts = line.split()
        flags = ""
        while parts and set(parts[-1]) <= set("!~="):
            flags += parts.pop()
        weight = STRONG if "!" in flags else MILD if "~" in flags else DEFAULT_WEIGHT[label]
        ws = words(" ".join(parts))
        if len(ws) == 1:
            single[ws[0]] = weight
            if "=" in flags:
                whole.add(ws[0])
        elif ws:
            phrases[tuple(ws)] = weight
    return WordList(single, phrases, frozenset(whole))


@dataclass(frozen=True)
class Combined:
    """Every language's list of one label in one look-up: each word or phrase with its
    highest weight and the languages that list it (for the false friends). The cost
    of a check grows with the post, not with the number of languages."""
    words: WordList
    langs: dict[str, frozenset[str]]


@lru_cache(maxsize=None)
def combined(label: str) -> Combined:
    single, phrases, langs = {}, {}, {}
    for l in LANGS:
        wl = wordlist(label, l)
        for w, weight in wl.single.items():
            single[w] = max(weight, single.get(w, 0))
            langs.setdefault(w, set()).add(l)
        for p, weight in wl.phrases.items():
            phrases[p] = max(weight, phrases.get(p, 0))
            langs.setdefault(" ".join(p), set()).add(l)
    return Combined(WordList(single, phrases), {t: frozenset(ls) for t, ls in langs.items()})


@lru_cache(maxsize=None)
def false_friends() -> frozenset[str]:
    return frozenset(w for line in _lines("false-friends.txt") for w in words(line))


@lru_cache(maxsize=None)
def harmless() -> frozenset[str]:
    return frozenset(w for line in _lines("harmless.txt") for w in words(line))


@lru_cache(maxsize=None)
def _all_single() -> dict[str, str]:
    """Every listed single word (false friends left out), and its label."""
    friends = false_friends()
    return {w: label for label in LABELS for l in LANGS for w in wordlist(label, l).single
            if w not in friends}


# --- mentioned, not used ------------------------------------------------------------

_FENCED = re.compile(r"```.*?```", re.S)
_INLINE = re.compile(r"`[^`\n]+`")
_QUOTED = re.compile(
    r"\"[^\"\n]{1,40}\"|“[^”\n]{1,40}”|„[^“”\n]{1,40}[“”]|«[^»\n]{1,40}»|»[^«\n]{1,40}«"
    r"|‘[^’\n]{1,40}’|(?<![\w'])'[^'\n]{1,40}'(?![\w'])")
_CUES = ("ordet", "ordene", "the word", "the words", "the term", "das wort",
         "die wörter", "het woord", "le mot", "les mots", "la palabra", "la parola")
_CUE = re.compile(r"\b(?:" + "|".join(re.escape(c) for c in _CUES) + r")\s+[\w@$*'’-]+", re.I)


def unmention(text: str) -> str:
    """The text with what is only talked about taken out: code, short quotations (at
    most three words) and the word right after "ordet", "the word" and the like."""
    def short_quote(m):
        return " " if len(m.group(0)[1:-1].split()) <= 3 else m.group(0)
    text = _FENCED.sub(" ", text or "")
    text = _INLINE.sub(" ", text)
    text = _QUOTED.sub(short_quote, text)
    return _CUE.sub(" ", text)


# --- written to slip past -----------------------------------------------------------

_SPELT_APART = re.compile(r"(?<![^\W\d_])(?:[^\W\d_][ .*_-]){3,}[^\W\d_](?![^\W\d_])")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                       "@": "a", "$": "s"})
_RUNS = re.compile(r"(.)\1{2,}")


def _listed(w: str) -> bool:
    return w in _all_single()


def join_spelt(text: str) -> str:
    """"f u c k" and "f.u.c.k" read as the word they spell, when it is listed."""
    def join(m):
        w = re.sub(r"[ .*_-]", "", m.group(0)).lower()
        w2 = w.translate(_LEET)
        return w2 if _listed(w2) else m.group(0)
    return _SPELT_APART.sub(join, text)


def unmask(w: str) -> str | None:
    """The listed word a disguised one stands for: "h0r", "fuuuck", "f*ck", or None."""
    if _listed(w):
        return None
    cands = [w.translate(_LEET)]
    cands += [_RUNS.sub(r"\1", c) for c in list(cands)] + [_RUNS.sub(r"\1\1", c) for c in list(cands)]
    for c in cands:
        if c != w and _listed(c):
            return c
    # masked inside only: "*is*" is markdown emphasis and "**at" bold, not a hidden word
    if "*" in w[1:-1] and w[0].isalpha() and w[-1].isalpha() and sum(ch.isalpha() for ch in w) >= 2:
        pat = re.compile("^" + "".join("." if ch == "*" else re.escape(ch) for ch in w) + "$")
        hits = [x for x in _all_single() if pat.match(x)]
        if len(hits) == 1:
            return hits[0]
    return None


@lru_cache(maxsize=None)
def _joinable(label: str, lang: str) -> dict[str, int]:
    """The words of one list that may be part of a compound, and their weights."""
    wl, friends = wordlist(label, lang), false_friends()
    return {x: w for x, w in wl.single.items()
            if len(x) >= _MIN_IN_COMPOUND and x not in friends and x not in wl.whole_only}


def compound_part(w: str, label: str, langs) -> tuple[str, int] | None:
    """A listed word (and its weight) at the start or end of a longer word, in the
    lists of ``langs``: "lortesystem" -> ("lorte", 1). None for a harmless word.
    Looks up the word's own beginnings and ends, so the cost grows with the length of
    the word, not with the number of listed words or languages."""
    if w in harmless() or _listed(w):
        return None
    core = w.replace("-", "")
    best = None
    for n in range(len(core) - 3, _MIN_IN_COMPOUND - 1, -1):     # the longest part first
        for part in (core[:n], core[-n:]):
            for lang in langs:
                weight = _joinable(label, lang).get(part)
                if weight and (best is None or weight > best[1]):
                    best = (part, weight)
        if best:
            return best
    return None


# --- the rules ----------------------------------------------------------------------

@dataclass
class Rules:
    min_score: int = 2         # two mild words, or one strong, for the label ...
    short_words: int = 8       # ... or any, in a post of at most this many words
    long_words: int = 150      # a longer post also needs ...
    min_density: float = 1.0   # ... this score per 100 words


@dataclass
class Verdict:
    label: str
    hits: list[str]
    lang: str | None         # the post's language, told from its text; None: not told
    score: int = 0

    @property
    def why(self) -> str:
        n = len(self.hits)
        word = "word" if n == 1 else "words"
        return (f"{n} {self.label} {word}, score {self.score}"
                + (f", {self.lang} text" if self.lang else ""))


def enough(score: int, n_words: int, rules: Rules) -> bool:
    if n_words <= rules.short_words:
        return score >= 1
    if score < rules.min_score:
        return False
    return n_words <= rules.long_words or score * 100 / n_words >= rules.min_density


def check(text: str, rules: Rules | None = None, author_tags=()) -> list[Verdict]:
    """The labels a post should carry, one verdict each (none: nothing to say)."""
    rules = rules or Rules()
    raw = words(join_spelt(unmention(text)))
    if not raw:
        return []
    lang = detect(raw)
    shown = {}                                        # index -> how it was written
    ws = []
    for i, w in enumerate(raw):
        u = unmask(w)
        if u:
            shown[i] = w
        ws.append(u or w)
    friends = false_friends()
    joining = [l for f in FAMILIES if lang is None or lang in f or f == ("en",) for l in f]
    out = []
    for label in LABELS:
        if label in author_tags:
            continue                                  # its author said so already
        both = combined(label)
        spans = [sp for sp in both.words.spans(ws)
                 if not (sp[2] in friends and lang not in both.langs[sp[2]])]
        hits, score, taken = [], 0, set()
        for i, j, t in merge(spans):
            weight = both.words.weight(t)
            hits.append(f"{t} ({shown[i]})" if i in shown and j == i + 1 else t)
            score += weight
            taken.update(range(i, j))
        for i, w in enumerate(raw):
            if i in taken:
                continue
            part = compound_part(w, label, joining)
            if part:
                hits.append(f"{part[0]} (in {w})")
                score += part[1]
        if hits and enough(score, len(raw), rules):
            out.append(Verdict(label, hits, lang, score))
    return out


def profanity(text: str, rules: Rules | None = None, author_tags=()) -> Verdict | None:
    """The ``profanity`` verdict alone, or None."""
    return next((v for v in check(text, rules, author_tags) if v.label == "profanity"), None)
