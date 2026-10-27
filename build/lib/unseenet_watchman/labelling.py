"""The watchman as a labeller (UN-RFC 0053): queueing, publishing and taking back labels.

A third identity in the vault, ``labels`` (*Unseenet watchman (labels)*), with its own
``labels@`` channel marked ``automatic``. Off until ``labels = true`` in the config, and
like the reports a dry run until ``publish = true``.

Labels go out in the same batches as reports: one article with every queued post, at
most 1000 entries, and a note. A label taken back is published again as ``[]`` for that
post (UN-RFC 0053 section 4) - no article is withdrawn, the rest of it stays.
"""

from __future__ import annotations

import json
import time

from unseenet.client.session import Session, SessionError
from unseenet.core.labels import MAX_ENTRIES, NOTE_MAX

from . import labels

NAME = "labels"
DISPLAY = "Unseenet watchman (labels)"
POLICY = ("Automatic. Labels posts with profanity (swearing, oaths) and sexual words, "
          "from its own word lists in nine languages: whole words and phrases only, at "
          "least two in a post or one in a very short post; insults are not labelled. "
          "Describes, never sanctions. https://github.com/unseenet/unseenet-watchman")


def check(m, st, rules: labels.Rules, log=print) -> bool:
    """Queue the labels a post should carry (profanity, sexual). True when queued."""
    if m.message_id in st.spared or m.author_key in st.spared or m.message_id in st.labelled:
        return False
    if any(p["id"] == m.message_id for p in st.pending_labels):
        return False
    # The subject is part of the post - but not in a reply, whose author kept the
    # subject of the post it answers ("Re: ..."), and did not choose it.
    subject = "" if getattr(m, "references", None) else (m.subject or "")
    verdicts = labels.check(f"{subject}\n{m.body or ''}", rules, getattr(m, "tags", ()) or ())
    if not verdicts:
        return False
    why = "; ".join(v.why for v in verdicts)
    st.pending_labels.append({"id": m.message_id, "group": m.group,
                              "labels": [v.label for v in verdicts], "why": why})
    log(f"label: {','.join(v.label for v in verdicts)} {m.message_id} in {m.group.partition('@')[0]}: {why}")
    return True


def note_for(entries: list[dict]) -> str:
    gone = sum(1 for e in entries if not e["labels"])
    counts = {}
    for e in entries:
        for label in e["labels"]:
            counts[label] = counts.get(label, 0) + 1
    parts = [f"{n} × {label}" for label, n in sorted(counts.items())]
    if parts:
        parts[-1] += " from word lists"
    if gone:
        parts.append(f"{gone} taken back")
    note = "automatic: " + "; ".join(parts)
    return note[:NOTE_MAX]


async def start(s: Session, contact: str, log=print) -> None:
    """The identity and its labels@ channel, once."""
    if NAME not in s.data.get("identities", {}):
        s.new_identity(NAME, DISPLAY)
        log(f"made the labeller's key: {s.identity(NAME).key_text}")
    if not s.is_labeller(NAME):
        gid = await s.start_labels(policy=POLICY, contact=contact, automatic=True, labeller=NAME)
        log(f"started the labels: {gid}")


async def publish(s: Session | None, st, dry_run: bool, log=print) -> int:
    """Publish the queued labels, at most MAX_ENTRIES an article. Returns articles."""
    done = 0
    while st.pending_labels:
        chunk = st.pending_labels[:MAX_ENTRIES]
        rows = [(e["id"], e["group"], e["labels"]) for e in chunk]
        note = note_for(chunk)
        if dry_run:
            log("would publish labels: " + json.dumps({"posts": rows, "note": note}, ensure_ascii=False))
            mid = f"dry-run:{int(time.time())}:{done}"
        else:
            try:
                mid = await s.publish_labels(rows, note=note, labeller=NAME)
            except (SessionError, OSError, ConnectionError) as exc:
                log(f"could not publish labels: {exc}")
                break
            log(f"published labels {mid}: {len(rows)} posts")
        for e in chunk:
            if e["labels"]:
                st.labelled[e["id"]] = {"group": e["group"], "article": mid}
            else:
                st.labelled.pop(e["id"], None)
        st.pending_labels = st.pending_labels[len(chunk):]
        done += 1
    st.save()
    return done


def unlabel(st, target: str, log=print) -> bool:
    """A post labelled by mistake: spare it from now on, and queue ``[]`` for it, which
    takes the label back in the next batch. True when there was a label to take back."""
    st.spared.add(target)
    st.pending_labels = [e for e in st.pending_labels if e["id"] != target or not e["labels"]]
    entry = st.labelled.get(target)
    if entry is None:
        return False
    st.pending_labels.append({"id": target, "group": entry["group"], "labels": [], "why": "taken back"})
    log(f"{target}: the label goes back in the next batch")
    return True
