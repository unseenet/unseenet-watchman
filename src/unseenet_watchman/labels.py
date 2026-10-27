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

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

LABELS = ("profanity", "sexual")
LANGS = ("da", "no", "sv", "de", "nl", "en", "fr", "es", "it")

# Small words that tell the languages apart. Only words that are NOT common in a
# neighbour (Danish, Norwegian and Swedish share many, and so do German and Dutch,
# French, Spanish and Italian), so that a shared word never decides between them.
STOPWORDS = {
    "da": "af noget nogen nogle meget mere hvad hvor bliver havde end ud jer lidt måske "
          "uden mellem hende siger sige gør gøre vores jeres tak",
    "no": "av meg deg seg noe noen mye mer hva ble blir enn hadde litt kanskje uten "
          "mellom sier si gjør gjøre vårt våre takk ikkje eg kva sånn veldig",
    "sv": "och jag inte att är för till också mycket något någon några vad hur hade än "
          "lite kanske utan mellan säger säga gör göra tack ska väl bara hon sedan då",
    "de": "und ich das ist nicht sie zu ein eine einen auch wie von bei nur noch nach "
          "wenn aber oder wir ihr wird werden kann haben sind mir mich dich dir uns euch "
          "schon sehr immer doch dass weil diese dieser kein keine nichts über unter "
          "gegen ohne durch heute jetzt warum",
    "nl": "het een van ik niet dat zijn op voor maar ook wel nog naar heb hebben zo wat "
          "hoe waar omdat deze geen niets wij jullie uit bij veel worden wordt werd zou "
          "moet heel toch alleen gewoon eigenlijk",
    "en": "the and is are was were be been to of that this it you he she we they not "
          "with on by from have has had do does did but or if what which who would could "
          "should will can just about there their them my your our very really because "
          "when then than these those some any into out up",
    "fr": "le les des une est pas je il elle nous vous ils qui dans pour avec mais ce "
          "cette ces très tout tous bien aussi comme être avoir fait peu sans parce quand "
          "alors rien chez moi toi lui leur aux",           # not du, plus, sur, ton, au: Danish
    "es": "el los las una es por para pero más muy también como del al su sus yo este "
          "esta esto eso ese hay está están ser estar tiene tengo hace cuando porque nada "
          "todo siempre ahora aquí bueno pues sí",
    "it": "il gli di è che non per anche come sono essere ho hai abbiamo questo questa "
          "quello perché quando molto tutto sempre ancora già dove cosa niente nel nella "
          "della delle degli dei sul sua mio tuo suo ci",
}
STOPWORDS = {lang: frozenset(ws.split()) for lang, ws in STOPWORDS.items()}
# Letters and digits, and the @ $ * of spellings like "@$$" and "f*ck"; no other
# punctuation, so "lort," is "lort".
_WORD = re.compile(r"[\w@$*]+(?:['’-][\w@$*]+)*")


def looks_encoded(line: str) -> bool:
    """A line of encoded data (base64, uuencode, yEnc) rather than text: long, and
    without the spaces and the word lengths of a language. Its letter salad would
    otherwise be read as words (found on Usenet)."""
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


def language(ws: list[str], min_hits: int = 2) -> str | None:
    """The post's language among LANGS, or None when it cannot be told: the language
    with most of its own small words, at least ``min_hits`` and twice the next one's."""
    counts = sorted(((sum(w in STOPWORDS[l] for w in ws), l) for l in LANGS), reverse=True)
    (best, lang), (second, _) = counts[0], counts[1]
    return lang if best >= min_hits and best >= 2 * second else None


# Lingua (lingua-language-detector, offline; also what Emkay uses), when installed:
# asked only when the small words cannot tell, and only taken when it is sure. On 1999
# Usenet posts: small words alone 78 % right, 0.7 % wrong; with Lingua after them 89 %
# right, 1.2 % wrong. ``pip install "unseenet-watchman[lingua]"``.
LINGUA_CODES = {"da": "DA", "no": "NB", "sv": "SV", "de": "DE", "nl": "NL", "en": "EN",
                "fr": "FR", "es": "ES", "it": "IT"}
LINGUA_SURE = 0.8
_lingua = None


def _lingua_detector():
    """The Lingua detector for LANGS, built once; False when Lingua is not installed."""
    global _lingua
    if _lingua is None:
        try:
            from lingua import IsoCode639_1, LanguageDetectorBuilder
            _lingua = LanguageDetectorBuilder.from_iso_codes_639_1(
                *[getattr(IsoCode639_1, c) for c in LINGUA_CODES.values()]).build()
        except ImportError:
            _lingua = False
    return _lingua


def lingua_language(ws: list[str]) -> str | None:
    det = _lingua_detector()
    if not det:
        return None
    conf = det.compute_language_confidence_values(" ".join(ws))
    if not conf or conf[0].value < LINGUA_SURE:
        return None
    code = conf[0].language.iso_code_639_1.name.upper()
    return next((l for l, c in LINGUA_CODES.items() if c == code), None)


def detect(ws: list[str]) -> str | None:
    """The post's language: its own small words first, which are seldom wrong; Lingua
    when they cannot tell (if installed); None when neither is sure."""
    return language(ws) or lingua_language(ws)


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
