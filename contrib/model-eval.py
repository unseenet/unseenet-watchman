"""Measure a guard model as the labels' second step (#11) - publishes nothing.

    python model-eval.py posts.jsonl --url http://127.0.0.1:11435 --model qwen3guard
    python model-eval.py posts.jsonl ... --sample 200 --extra more.txt --out results.jsonl

Reads posts (JSON lines with "Subject" and "body", as watchman-test/usenet/fetch.py
writes them), picks the doubtful ones (``model.doubt``), asks the model about each and
prints how often it would confirm, veto or add a word-list label, how long it took, and
examples. ``--sample N`` also asks about N posts that were *not* in doubt, to see what
the doubt rules miss. ``--extra`` adds texts of your own, separated by lines of "%%".
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
from collections import Counter

from unseenet_watchman import dupes, labels, model


def short(text: str, n: int = 110) -> str:
    return " ".join(model.clean(text).split())[:n]


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("posts")
    p.add_argument("--url", default="http://127.0.0.1:11434")
    p.add_argument("--model", required=True)
    p.add_argument("--sample", type=int, default=0)
    p.add_argument("--extra", default="")
    p.add_argument("--limit", type=int, default=0, help="ask about at most this many")
    p.add_argument("--out", default="")
    a = p.parse_args()
    cfg = model.ModelConfig(url=a.url, model=a.model)

    posts = []
    for line in open(a.posts, encoding="utf-8"):
        d = json.loads(line)
        subject = "" if d.get("Subject", "").lower().startswith("re:") else d.get("Subject", "")
        # the lists read a reply without its subject; the model always sees it
        posts.append({"id": d.get("Message-ID", ""), "group": d.get("group", ""),
                      "subject": d.get("Subject", ""), "text": f"{subject}\n{d.get('body', '')}"})
    if a.extra:
        chunks = open(a.extra, encoding="utf-8").read().split("\n%%\n")
        posts += [{"id": f"extra-{i}", "group": "extra", "text": t} for i, t in enumerate(chunks) if t.strip()]

    rules = labels.Rules()
    doubtful, calm = [], []
    reasons = Counter()
    for p_ in posts:
        d = model.doubt(p_["text"], rules)
        p_["doubt"], p_["lists"] = d.reasons, sorted(v.label for v in d.verdicts)
        p_["focus"] = d.focus
        (doubtful if d else calm).append(p_)
        reasons.update(d.reasons)
    random.seed(11)
    sample = random.sample(calm, min(a.sample, len(calm)))
    todo = doubtful + sample
    if a.limit:
        todo = todo[:a.limit]
    print(f"{len(posts)} posts; in doubt {len(doubtful)} ({len(doubtful) / len(posts):.1%}): "
          f"{dict(reasons)}; asking about {len(todo)} (with {len(sample)} not in doubt)\n", flush=True)

    out = open(a.out, "w", encoding="utf-8") if a.out else None
    seen: dict[str, model.Opinion | None] = {}     # one question a text, as in a wave
    for i, p_ in enumerate(todo, 1):
        fp = dupes.fingerprint(p_.get("subject", "") + "\n" + p_["text"])
        if fp is not None and fp in seen:
            op, p_["reused"] = seen[fp], True
        else:
            op = await model.ask(cfg, p_["text"], p_.get("focus", ()), p_.get("subject", ""))
            if fp is not None:
                seen[fp] = op
        p_["model"] = None if op is None else {"safety": op.safety, "categories": list(op.categories),
                                               "labels": op.labels, "seconds": op.seconds}
        if out:
            out.write(json.dumps({k: v for k, v in p_.items()}, ensure_ascii=False) + "\n")
            out.flush()
        if i % 25 == 0:
            secs = [q["model"]["seconds"] for q in todo[:i] if q.get("model") and not q.get("reused")]
            print(f"  {i}/{len(todo)}, {statistics.mean(secs) if secs else 0:.1f} s a post", flush=True)

    asked = [q for q in todo if "model" in q]
    answered = [q for q in asked if q["model"]]
    secs = sorted(q["model"]["seconds"] for q in answered if not q.get("reused"))
    print(f"\nanswers: {len(answered)} of {len(asked)} in the guard format; "
          f"{len(secs)} model calls, the rest the same text again")
    if secs:
        print(f"seconds a post: mean {statistics.mean(secs):.1f}, median {statistics.median(secs):.1f}, "
              f"95 % {secs[int(len(secs) * 0.95) - 1 if len(secs) > 1 else 0]:.1f}, max {secs[-1]:.1f}")

    def show(title, rows):
        print(f"\n{title}: {len(rows)}")
        for q in rows[:8]:
            m = q["model"]
            print(f"   [{q['group']}] lists {q['lists'] or '-'} | model {m['safety']}: "
                  f"{', '.join(m['categories']) or 'None'} | {short(q['text'])}")

    in_doubt = [q for q in answered if q["doubt"]]
    sexual_lists = [q for q in in_doubt if "sexual" in q["lists"]]
    show("sexual by the lists, CONFIRMED by the model", [q for q in sexual_lists if "sexual" in q["model"]["labels"]])
    show("sexual by the lists, VETOED by the model (safe)", [q for q in sexual_lists if q["model"]["safety"] == "safe"])
    show("sexual by the lists, model 'controversial' or other", [q for q in sexual_lists if q["model"]["safety"] != "safe" and "sexual" not in q["model"]["labels"]])
    show("model would ADD sexual (lists gave none)", [q for q in in_doubt if "sexual" in q["model"]["labels"] and "sexual" not in q["lists"]])
    show("profanity by the lists: model says safe (it has no profanity category)",
         [q for q in in_doubt if "profanity" in q["lists"] and q["model"]["safety"] == "safe"])
    show("JAILBREAK", [q for q in answered if "Jailbreak" in q["model"]["categories"]])
    cats = Counter(c for q in answered for c in q["model"]["categories"])
    print(f"\nall categories: {dict(cats.most_common())}")
    by_reason = {r: Counter(q["model"]["safety"] for q in in_doubt if r in q["doubt"]) for r in reasons}
    print(f"safety by doubt reason: { {r: dict(c) for r, c in by_reason.items()} }")
    if sample:
        missed = [q for q in answered if not q["doubt"] and q["model"]["safety"] == "unsafe"]
        show(f"NOT in doubt but 'unsafe' (of {len([q for q in answered if not q['doubt']])} sampled)", missed)


if __name__ == "__main__":
    asyncio.run(main())
