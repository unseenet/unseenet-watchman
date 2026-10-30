"""A language model as a second step for labels (#11) - measured first, publishes nothing.

Word lists are the first step: fast, predictable and explainable. What they cannot do
is context ("the word was used in a debate about the word"), compound words
("lortesystem") and spellings meant to slip past ("f u c k", "h0r"). A small local
guard model can, for the few posts where the lists are in doubt:

- ``doubt`` picks those posts: a word-list label (the model may confirm it, or say
  the word was only mentioned), one rude word too few for a label, a rude word hidden
  in a compound or spelt apart, or a longer post in a language the lists do not know.
- ``ask`` gives one of them to a guard model (Qwen3Guard-Gen) behind an
  OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM) on a private address. Nothing
  goes to an outside service.
- ``parse`` accepts only the guard model's fixed answer (``Safety: ...`` and
  ``Categories: ...``); anything else is "no opinion". A post is hostile input, and a
  model that was talked round answers in some other shape.

The model never sanctions: no report rests on it (a report needs a concrete signal),
and its labels, when they are published at all, go out under a key of their own so
each reader chooses whether to trust a judgement. Until the numbers are in, this
module only feeds ``unseenet-watchman model`` and ``contrib/model-eval.py``.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.request
from dataclasses import dataclass, field

from unseenet.core.language import detect, looks_encoded, words

from . import labels

# The guard model's categories (Qwen3Guard-Gen), and the label each one may give.
# Only ``sexual`` for now: violence and self-harm need new labels in UN-RFC 0053 first;
# "Politically Sensitive Topics" is a topic judgement and is never used; the rest is
# logged until real output has been seen.
SEXUAL = "Sexual Content or Sexual Acts"
JAILBREAK = "Jailbreak"
LABEL_FOR = {SEXUAL: "sexual"}

_ANSWER = re.compile(
    r"\A\s*Safety:\s*(Safe|Unsafe|Controversial)\s*\n\s*Categories:\s*([^\n]+?)\s*"
    r"(?:\n\s*Refusal:\s*(?:Yes|No)\s*)?\Z")
_KNOWN = {SEXUAL, JAILBREAK, "Violent", "Non-violent Illegal Acts", "PII",
          "Suicide & Self-Harm", "Unethical Acts", "Politically Sensitive Topics",
          "Copyright Violation", "None"}


@dataclass
class ModelConfig:
    url: str = "http://127.0.0.1:11434"   # an OpenAI-compatible server, on a private address
    model: str = ""                        # e.g. "qwen3guard-gen-0.6b"
    timeout: float = 120.0                 # seconds for one answer
    max_chars: int = 1500                  # of the post's own text, around the doubtful words


@dataclass(frozen=True)
class Opinion:
    safety: str                            # "safe", "controversial" or "unsafe"
    categories: tuple[str, ...]
    seconds: float = 0.0

    @property
    def labels(self) -> list[str]:
        """The labels the model would give: only for "unsafe", never "controversial"."""
        if self.safety != "unsafe":
            return []
        return sorted({LABEL_FOR[c] for c in self.categories if c in LABEL_FOR})

    @property
    def jailbreak(self) -> bool:
        """The post tries to talk a model round: a signal for a person, never a report."""
        return JAILBREAK in self.categories

    @property
    def why(self) -> str:
        return f"{self.safety}: {', '.join(self.categories) or 'None'}"


def parse(raw: str) -> Opinion | None:
    """The model's answer, or None when it is not exactly the guard model's format."""
    m = _ANSWER.match(raw or "")
    if not m:
        return None
    cats = tuple(c.strip() for c in m.group(2).split(","))
    if any(c not in _KNOWN for c in cats):
        return None
    return Opinion(m.group(1).lower(), tuple(c for c in cats if c != "None"))


def clean(text: str, max_chars: int = 1500) -> str:
    """The post's own text, as ``words`` reads it: no quoted lines (the author did not
    write them), no encoded data, no signature, and at most ``max_chars``."""
    keep = []
    for line in (text or "").splitlines():
        if line.rstrip() == "--":
            break
        if not line.lstrip().startswith(">") and not looks_encoded(line):
            keep.append(line.rstrip())
    out = re.sub(r"\n{3,}", "\n\n", "\n".join(keep)).strip()
    return out[:max_chars]


def excerpt(text: str, focus=(), max_chars: int = 1500) -> str:
    """At most ``max_chars`` of the post's own text, around the first of the ``focus``
    words when the post is longer: the context of a word is what the model is asked
    about, and a long post costs seconds a page on one core."""
    full = clean(text, 10**6)
    if len(full) <= max_chars:
        return full
    low = full.lower()
    at = min((i for i in (low.find(w.lower()) for w in focus) if i >= 0), default=0)
    start = max(0, min(at - max_chars // 3, len(full) - max_chars))
    return full[start:start + max_chars]


# --- which posts are in doubt -------------------------------------------------------

_SPELT_APART = re.compile(r"(?<![^\W\d_])(?:[^\W\d_][ .*_-]){3,}[^\W\d_](?![^\W\d_])")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
                       "@": "a", "$": "s"})
_MIN_IN_COMPOUND = 4                       # shorter words hide in too many harmless ones


def _single_words() -> dict[str, frozenset[str]]:
    """Every list's single words, by label, false friends left out."""
    friends = labels.false_friends()
    return {label: frozenset(w for l in labels.LANGS for w in labels.wordlist(label, l).single
                             if w not in friends)
            for label in labels.LABELS}


def _listed(word: str, singles: dict[str, frozenset[str]]) -> str | None:
    return next((label for label, ws in singles.items() if word in ws), None)


def hidden(text: str) -> list[str]:
    """Rude words the lists miss on purpose: spelt apart ("f u c k"), with digits for
    letters ("h0r"), or at either end of a compound ("lortesystem")."""
    singles = _single_words()
    found = []
    for m in _SPELT_APART.finditer(clean(text, 10**6)):
        w = re.sub(r"[ .*_-]", "", m.group(0)).lower()
        if _listed(w, singles):
            found.append(m.group(0))
    long_ones = {w for ws in singles.values() for w in ws if len(w) >= _MIN_IN_COMPOUND}
    for w in set(words(text)):
        if _listed(w, singles):
            continue                                  # a whole word: the lists saw it
        if any(c.isdigit() for c in w) and _listed(w.translate(_LEET), singles):
            found.append(w)
        elif any(len(w) > len(x) + 2 and (w.startswith(x) or w.endswith(x)) for x in long_ones):
            found.append(w)
    return sorted(found)


@dataclass
class Doubt:
    reasons: list[str] = field(default_factory=list)
    verdicts: list[labels.Verdict] = field(default_factory=list)   # the word lists' labels
    focus: list[str] = field(default_factory=list)                 # the words in doubt

    def __bool__(self) -> bool:
        return bool(self.reasons)


def doubt(text: str, rules: labels.Rules | None = None, author_tags=()) -> Doubt:
    """Why the word lists may be wrong about a post, if they may. Most posts: none."""
    rules = rules or labels.Rules()
    ws = words(text)
    d = Doubt(verdicts=labels.check(text, rules, author_tags))
    if not ws:
        return d
    if d.verdicts:
        d.reasons.append("labelled")                 # confirm, or only mentioned?
    loose = labels.check(text, labels.Rules(min_hits=1, short_words=0), author_tags)
    if {v.label for v in loose} - {v.label for v in d.verdicts}:
        d.reasons.append("one word")                 # just under the threshold
    d.focus = [h for v in loose for h in v.hits]
    if found := hidden(text):
        d.reasons.append("hidden")
        d.focus += found
    if len(ws) >= 20 and detect(ws) is None:
        d.reasons.append("language")                 # the lists may not know it
    return d


# --- asking the model ---------------------------------------------------------------

def _post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - our own config
        return json.loads(r.read())


async def ask(cfg: ModelConfig, text: str, focus=()) -> Opinion | None:
    """The guard model's opinion of a post's own text, or None (no answer, or an
    answer in another shape). The post goes in as the user's message alone - a guard
    model's own template is the fixed instruction around it - cut to ``max_chars``
    around the ``focus`` words (``Doubt.focus``)."""
    body = {"model": cfg.model, "temperature": 0, "max_tokens": 32,
            "messages": [{"role": "user", "content": excerpt(text, focus, cfg.max_chars)}]}
    url = cfg.url.rstrip("/") + "/v1/chat/completions"
    t = time.monotonic()
    try:
        r = await asyncio.to_thread(_post, url, body, cfg.timeout)
        raw = r["choices"][0]["message"]["content"]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return None
    op = parse(raw)
    if op is None:
        return None
    return Opinion(op.safety, op.categories, round(time.monotonic() - t, 2))
