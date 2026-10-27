"""One look at the network, and publishing what it found as reports.

A look: list the groups on the watchman's nodes, fetch what is new in each open
group, check every new post (links on URI blocklists, near-identical texts) and queue
what it finds. A batch, every ``batch_minutes``: one report article per issuer, with
the queued posts and keys and a note saying why (UN-RFC 0045 section 4). In a dry run
the batch is written to the log instead, and nothing leaves the machine but the reading.

Only open groups: closed groups and inboxes are ciphertext to it, and a sealed private
post is never reported (0045 section 4). Key-bound groups (inboxes, profiles, reports,
ripening chains ...) are left out too - except feeds, where others comment.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from unseenet.client.session import Session, SessionError
from unseenet.core.groups import KIND_REACTION, is_key_bound
from unseenet.core.reports import MAX_ENTRIES

from . import decide, dupes, uris
from .dnsbl import Lookups, Zone
from .state import State

ISSUERS = {   # identity name in the vault -> what its reports@ channel says it does
    "spam": ("Unseenet watchman (spam)",
             "Automatic. Reports posts that look like spam: the same text from many new "
             "keys, the same text from one key in many groups, or links to domains on URI "
             "blocklists for spam. A key only after repeated findings, for 30 days. "
             "https://github.com/unseenet/unseenet-watchman"),
    "phishing": ("Unseenet watchman (phishing)",
                 "Automatic. Reports posts with links to domains on URI blocklists for "
                 "phishing and malware. A key only after repeated findings, for 30 days. "
                 "https://github.com/unseenet/unseenet-watchman"),
}
MAX_AGE = timedelta(days=2)     # older posts arriving late are seen, not judged


@dataclass
class Config:
    vault: Path
    state_file: Path
    nodes: list[str] = field(default_factory=list)
    publish: bool = False
    interval_minutes: int = 10
    batch_minutes: int = 60
    groups: list[str] = field(default_factory=lambda: ["*"])
    skip_groups: list[str] = field(default_factory=list)
    contact: str = ""
    tor_socks: str = ""           # "": the Tor the session uses; or host:port
    doh: str = ""                 # the DNS-over-HTTPS resolver (dnsbl.DEFAULT_DOH)
    spamhaus_dqs_key: str = ""    # turns Spamhaus DBL on, through its DQS zones
    rules: decide.Rules = field(default_factory=decide.Rules)
    zones: list[Zone] | None = None


# Key-bound groups that others write in: comments under a feed's posts (UN-RFC 0034)
# are where spam reaches people in "Facebook mode". Inboxes, profiles, reports,
# ripening chains, state and sites are written by their owner alone, or sealed.
READ_KEY_BOUND = ("feed",)


def wanted(group_id: str, cfg: Config) -> bool:
    """An open group the config says to read: not key-bound (but feeds), matching
    ``groups`` and not ``skip_groups`` (patterns on the name, the part before @)."""
    name = group_id.partition("@")[0]
    if is_key_bound(group_id) and name not in READ_KEY_BOUND:
        return False
    return (any(fnmatch.fnmatchcase(name, p) for p in cfg.groups)
            and not any(fnmatch.fnmatchcase(name, p) for p in cfg.skip_groups))


@contextlib.contextmanager
def acting(s: Session, name: str):
    """Act as identity ``name`` for a moment (``Session.act_as``), then as the vault's
    default again - the watchman never acts as anyone else in between."""
    s.act_as(name)
    try:
        yield
    finally:
        s.act_as(None)


def own_keys(s: Session) -> set[str]:
    return {s.identity(n).key_text for n in s.data.get("identities", {})}


async def check_post(m, lookups: Lookups, st: State, cfg: Config, now: float) -> list[decide.Finding]:
    """The findings for one post: its links, then whether it is part of a wave."""
    found: list[decide.Finding] = []
    for host in uris.hosts(m.body):
        if uris.allowed(host, cfg.rules.allow_domains):
            continue
        for name in uris.lookup_names(host):
            hits = await lookups.check(name)
            if hits:
                found += decide.from_lists(m.message_id, m.group, m.author_key, hits)
                break
        if found:
            break
    fp = dupes.fingerprint(m.body)
    if fp is not None:
        e = dupes.Entry(fp, m.message_id, m.group, m.author_key, now)
        found += decide.from_dupes(e, st.dupes.add(e), cfg.rules)
    return found


def _judge(m, s_keys: set[str], cfg: Config) -> bool:
    if m.private or not m.readable or m.encrypted or m.kind == KIND_REACTION:
        return False
    if not m.author_key or m.author_key in s_keys or m.author_key in cfg.rules.allow_keys:
        return False
    if m.date and datetime.now(timezone.utc) - m.date > MAX_AGE:
        return False
    return True


def queue_findings(found: list[decide.Finding], st: State, cfg: Config, now: float, log) -> int:
    """Queue findings, and a key once it has earned it. Returns how many were new."""
    new = 0
    for f in found:
        if not st.queue(f):
            continue
        new += 1
        log(f"finding: {f.reason} {f.message_id} in {f.group.partition('@')[0]}: {f.why}")
        k = f.key
        if (st.keys.add(k, now, cfg.rules) and k not in st.reported_keys
                and k not in st.pending_keys and k not in st.spared):
            until = datetime.now(timezone.utc) + timedelta(days=cfg.rules.key_days)
            st.pending_keys[k] = {"reason": f.reason, "until": until.isoformat(),
                                  "why": f"{cfg.rules.key_after} findings in {cfg.rules.key_window} days"}
            log(f"key earned a report: {k} ({f.reason})")
    return new


async def look(s: Session, cfg: Config, st: State, lookups: Lookups, log=print) -> int:
    """Fetch what is new in every wanted group and check it. Returns new findings."""
    now = time.time()
    try:
        groups = await s.list_groups("*")
    except (SessionError, OSError, ConnectionError) as exc:
        log(f"could not list groups: {exc}")
        return 0
    mine = own_keys(s)
    checked = new = 0
    for g in groups:
        if not wanted(g.group_id, cfg):
            continue
        try:
            msgs = s.visible(await s.fetch_group(g.group_id))
        except (SessionError, OSError, ConnectionError) as exc:
            log(f"{g.group_id.partition('@')[0]}: {exc}")
            continue
        for m in msgs:
            if m.message_id in st.seen:
                continue
            st.seen[m.message_id] = now
            if st.fresh or not _judge(m, mine, cfg):
                continue
            checked += 1
            new += queue_findings(await check_post(m, lookups, st, cfg, now), st, cfg, now, log)
    if st.fresh:
        log(f"first look: {len(st.seen)} earlier posts left alone")
        st.fresh = False
    elif checked:
        log(f"checked {checked} new posts, {new} findings")
    _expire_keys(st)
    st.save()
    return new


def _expire_keys(st: State) -> None:
    now = datetime.now(timezone.utc)
    st.reported_keys = {k: u for k, u in st.reported_keys.items()
                        if datetime.fromisoformat(u) > now}


def batches(st: State) -> list[tuple[str, list[decide.Finding], list[tuple[str, str, str, str]]]]:
    """The queued posts and keys as report articles: (issuer, posts, keys), each with
    at most MAX_ENTRIES entries. Keys are (key, reason, until, why)."""
    by: dict[str, tuple[list, list]] = {}
    for f in st.pending:
        by.setdefault(f.issuer, ([], []))[0].append(f)
    for k, v in st.pending_keys.items():
        by.setdefault(decide.ISSUER_OF[v["reason"]], ([], []))[1].append(
            (k, v["reason"], v["until"], v["why"]))
    out = []
    for issuer, (posts, keys) in sorted(by.items()):
        entries = [("p", p) for p in posts] + [("k", k) for k in keys]
        for i in range(0, len(entries), MAX_ENTRIES):
            chunk = entries[i:i + MAX_ENTRIES]
            out.append((issuer, [e for t, e in chunk if t == "p"], [e for t, e in chunk if t == "k"]))
    return out


def _note(posts: list[decide.Finding], keys: list) -> str:
    fake = posts + [decide.Finding("", "", k, r, f"key: {why}") for k, r, _, why in keys]
    return decide.note_for(fake)


async def start_issuers(s: Session, cfg: Config, log=print) -> None:
    """Make sure both issuers' reports@ channels exist, marked automatic (0045 section 8)."""
    for name, (_, policy) in ISSUERS.items():
        if s.is_issuer(name):
            continue
        # start_reports acts as the identity in use (an issuer= is unseenet/unseenet#661)
        with acting(s, name):
            gid = await s.start_reports(policy=policy, contact=cfg.contact, automatic=True)
        log(f"started {name}'s reports: {gid}")


async def publish(s: Session | None, st: State, cfg: Config, dry_run: bool, log=print) -> int:
    """Publish the queued findings, one article per issuer. Returns articles published
    (or, in a dry run, that would be)."""
    done = 0
    for issuer, posts, keys in batches(st):
        note = _note(posts, keys)
        post_rows = [(f.message_id, f.group, f.reason) for f in posts]
        key_rows = [(k, r, u) for k, r, u, _ in keys]
        if dry_run:
            log("would publish as " + issuer + ": " + json.dumps(
                {"posts": post_rows, "keys": key_rows, "note": note}, ensure_ascii=False))
            mid = f"dry-run:{int(time.time())}:{done}"
        else:
            try:
                mid = await s.publish_report(
                    posts=post_rows,
                    keys=[(k, r, datetime.fromisoformat(u)) for k, r, u in key_rows],
                    note=note, issuer=issuer)
            except (SessionError, OSError, ConnectionError) as exc:
                log(f"could not publish {issuer}'s report: {exc}")
                return done
            log(f"published {issuer}'s report {mid}: {len(posts)} posts, {len(keys)} keys")
        st.published[mid] = {"issuer": issuer, "posts": [list(r) for r in post_rows],
                             "keys": [list(r) for r in key_rows], "note": note}
        for f in posts:
            st.reported_posts[f.message_id] = mid
        for k, _, u, _ in keys:
            st.reported_keys[k] = u
        done_mids = {f.message_id for f in posts}
        done_keys = {k for k, *_ in keys}
        st.pending = [p for p in st.pending if p.message_id not in done_mids]
        st.pending_keys = {k: v for k, v in st.pending_keys.items() if k not in done_keys}
        done += 1
    st.last_batch = time.time()
    st.save()
    return done


async def unreport(s: Session | None, st: State, target: str, log=print) -> bool:
    """Take back a post or a key reported by mistake: withdraw the article naming it,
    publish the rest of that article again, and never report it again."""
    st.spared.add(target)
    st.pending = [p for p in st.pending if p.message_id != target and p.key != target]
    st.pending_keys.pop(target, None)
    rid = st.reported_posts.pop(target, None)
    if rid is None and target in st.reported_keys:
        st.reported_keys.pop(target)
        rid = next((m for m, e in st.published.items() if any(k[0] == target for k in e["keys"])), None)
    if rid is None or rid not in st.published:
        st.save()
        log(f"{target}: not in a published report; spared from now on")
        return False
    entry = st.published.pop(rid)
    if not rid.startswith("dry-run:"):
        await s.withdraw_report(rid, issuer=entry["issuer"])
        log(f"withdrew {rid}")
    rest_posts = [r for r in entry["posts"] if r[0] != target]
    rest_keys = [r for r in entry["keys"] if r[0] != target]
    for r in rest_posts:          # published again in the next batch, as findings
        st.reported_posts.pop(r[0], None)
        st.pending.append(decide.Finding(r[0], r[1], "", r[2], "published again"))
    for k, reason, until in rest_keys:
        st.reported_keys.pop(k, None)
        st.pending_keys[k] = {"reason": reason, "until": until, "why": "published again"}
    st.save()
    log(f"{target}: spared; {len(rest_posts) + len(rest_keys)} other entries go out again")
    return True


def make_lookups(cfg: Config, s: Session | None = None, log=print) -> Lookups:
    """Lookups with DNS-over-HTTPS through ``tor_socks``, or - when it is empty -
    through the same Tor the session reads the nodes with (dnsbl explains why not
    plain DNS)."""
    from .dnsbl import DEFAULT_DOH, ResolveError, default_zones, doh_resolve
    zones = cfg.zones if cfg.zones is not None else default_zones(cfg.spamhaus_dqs_key)
    doh = cfg.doh or DEFAULT_DOH

    def socks() -> tuple[str, int]:
        if cfg.tor_socks:
            host, _, port = cfg.tor_socks.rpartition(":")
            return host or "127.0.0.1", int(port)
        t = s.tor_in_use() if s is not None else None
        if t is not None:
            return t.host, t.port
        if s is not None and s.tor is not None and s.tor.alive():
            return "127.0.0.1", s.tor.socks_port
        raise ResolveError("the session's Tor is not running yet")

    async def resolve(q: str):
        host, port = socks()
        return await doh_resolve(q, host, port, doh)
    return Lookups(zones, resolve, log=log)
