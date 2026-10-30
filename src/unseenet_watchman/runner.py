"""Run the watchman.

    unseenet-watchman -c watchman.toml init              # a vault with both issuers' keys
    unseenet-watchman -c watchman.toml check "text"      # check one text (links via Tor)
    unseenet-watchman -c watchman.toml run --once        # look once, batch, stop
    unseenet-watchman -c watchman.toml run               # keep watching (push)
    unseenet-watchman -c watchman.toml status            # what is queued and published
    unseenet-watchman -c watchman.toml unreport ID       # a post or key was no spam

Nothing is published unless ``publish = true`` in the config: until then every batch
is a dry run, written to the log. ``--dry-run`` forces one; ``--publish`` is refused
unless the config says so, so a typo never makes a report.

The vault's passphrase is read from UNSEENET_VAULT_PASSPHRASE.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
import tomllib
from datetime import datetime
from pathlib import Path

from unseenet.client.session import Session, SessionError
from unseenet.core.vault import Vault

from . import __version__, decide, dupes, labelling, labels, uris
from .dnsbl import Zone
from .state import State
from .watch import (ISSUERS, Config, acting, look, make_lookups, publish,
                    restore_high, start_issuers, unreport)

PASS_ENV = "UNSEENET_VAULT_PASSPHRASE"
ABOUT = """\
# Unseenet watchman :robot:

I read the open groups of **[Unseenet](https://unseenet.org)** and publish
**spam reports** ([UN-RFC 0045](https://unseenet.org/spec/un-rfc-0045/)) -
automatically, as a program.

## What I do - and don't

- I report posts that look like spam or link to phishing and malware, and a
  key only after repeated findings, for 30 days
- I never remove anything: you, your node or a group's owner decide whether to
  follow my reports, and hidden posts are always one click from being shown
- I only read open groups; closed groups and private posts are ciphertext to me
- I am a program and can be wrong. If I reported you by mistake, write to my
  inbox and a person will look at it
"""
PROFILE_LINKS = [{"kind": "github", "value": "https://github.com/unseenet/unseenet-watchman"}]


def _zones(rows: list[dict]) -> list[Zone]:
    return [Zone(r["name"], codes=dict(r.get("codes", {})),
                 bits={int(k): v for k, v in r.get("bits", {}).items()},
                 refused=frozenset(r.get("refused", [])), test=r.get("test", ""),
                 enabled=r.get("enabled", True))
            for r in rows]


def _label_rules(t: dict) -> labels.Rules:
    base = labels.Rules()
    return labels.Rules(min_hits=int(t.get("min_hits", base.min_hits)),
                        short_words=int(t.get("short_words", base.short_words)),
                        long_words=int(t.get("long_words", base.long_words)),
                        min_density=float(t.get("min_density", base.min_density)))


def load_config(path: str | Path) -> Config:
    d = tomllib.loads(Path(path).read_text())
    w, r = d.get("watchman", {}), d.get("rules", {})
    try:
        return Config(
            vault=Path(w["vault"]).expanduser(),
            state_file=Path(w.get("state_file", "~/.local/state/unseenet-watchman/state.json")).expanduser(),
            nodes=w.get("nodes", []), publish=bool(w.get("publish", False)),
            sweep_minutes=int(w.get("sweep_minutes", 60)),
            batch_minutes=int(w.get("batch_minutes", 60)),
            groups=w.get("groups", ["*"]), skip_groups=w.get("skip_groups", []),
            contact=w.get("contact", ""), tor_socks=w.get("tor_socks", ""),
            doh=w.get("doh", ""), spamhaus_dqs_key=w.get("spamhaus_dqs_key", ""),
            rules=decide.Rules(
                wave_keys=int(r.get("wave_keys", 5)), flood_groups=int(r.get("flood_groups", 5)),
                key_after=int(r.get("key_after", 3)), key_window=int(r.get("key_window", 7)),
                key_days=min(int(r.get("key_days", 30)), 365),
                share_groups=int(r.get("share_groups", 5)),
                share_burst=int(r.get("share_burst", 30)),
                share_burst_minutes=int(r.get("share_burst_minutes", 60)),
                allow_keys=frozenset(r.get("allow_keys", [])),
                allow_domains=frozenset(d.lower() for d in r.get("allow_domains", []))),
            zones=_zones(d["zone"]) if "zone" in d else None,
            labels=bool(w.get("labels", False)),
            cards=bool(w.get("cards", False)),
            label_rules=_label_rules(d.get("labels", {})),
            ripen_to=int(w["ripen_to"]) if "ripen_to" in w else None)
    except KeyError as exc:
        raise SystemExit(f"{path}: missing {exc}") from exc


def open_session(cfg: Config, log=print) -> Session:
    pw = os.environ.get(PASS_ENV)
    if not pw:
        raise SystemExit(f"set {PASS_ENV} to the watchman vault's passphrase")
    cfg.vault.parent.mkdir(parents=True, exist_ok=True)
    s = Session(Vault.open(cfg.vault, pw), status=log)
    s.service = True                 # a program: its names stay up when it posts (unseenet#592)
    return s


def cmd_init(cfg: Config) -> None:
    s = open_session(cfg)
    for name, (display, _) in ISSUERS.items():
        if name not in s.data.get("identities", {}):
            s.new_identity(name, display)
    nodes = cfg.nodes
    if not nodes:
        from unseenet.core.poster import known_node_addresses
        nodes = known_node_addresses()
    for n in nodes:
        s.add_node(n)
    s.save()
    print(f"vault: {cfg.vault}")
    for name in ISSUERS:
        print(f"{name:9} {s.identity(name).key_text}")
    print("nothing is published until publish = true in the config")


async def publish_profiles(s: Session, log=print) -> None:
    """Each issuer's public profile, with the bot mark (UN-RFC 0022), once."""
    from unseenet.core.profiles import make_profile
    for name in [*ISSUERS, labelling.NAME]:
        if name not in s.data["identities"]:
            continue                                  # the labeller, when labels are off
        flag = f"watchman_profile_{__version__.split('.dev')[0]}"
        if s.data["identities"][name].get(flag):
            continue
        prof = make_profile(about=ABOUT, links=PROFILE_LINKS, lang=["en"], bot=True, markdown=True)
        try:
            with acting(s, name):
                await s.publish_profile(prof)
        except (SessionError, OSError, ConnectionError) as exc:
            log(f"could not publish {name}'s profile yet: {exc}")
            continue
        s.data["identities"][name][flag] = True
        s.save()
        log(f"published {name}'s profile with the bot mark")


def use_nodes(s: Session, cfg: Config) -> None:
    """``nodes`` in the config, when given, are the nodes - all of them."""
    if cfg.nodes:
        for n in cfg.nodes:
            s.add_node(n)
        s.data["nodes"] = [n for n in s.data["nodes"] if n in cfg.nodes]
        s.save()


def is_local(address: str) -> bool:
    return not address.split(":")[0].endswith(".onion")


async def ripen_issuers(s, cfg: Config, log) -> None:
    """Ripen the issuers' and the labeller's keys, one after the other, to ``ripen_to``,
    else ``UNSEENET_RIPEN_TO``, else 3 (#21, unseenet#740), publishing each new level.
    By name, without act_as, so the watching goes on meanwhile; weeks for level 4."""
    from unseenet.client.runtime import service_ripen_to
    from unseenet.core import ripening as rp
    if not rp.available():
        return
    to = service_ripen_to(cfg.ripen_to)
    for name in [*ISSUERS, labelling.NAME]:
        if name not in s.data.get("identities", {}):
            continue
        try:
            while (lv := s.ripening(name).level) is None or lv < to:
                if not await s.ripen_segment(name):
                    break
                if s.ripening(name).level != s.published_level(name):
                    await s.publish_ripening(name)
                    log(f"{name}: key ripened to level {s.ripening(name).level}")
        except Exception as exc:  # noqa: BLE001 - posting still ripens what it needs
            log(f"ripening {name} stopped: {exc}")


async def cmd_run(cfg: Config, once: bool, dry_run: bool) -> None:
    from .follow import Follower
    log = lambda msg: print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)  # noqa: E731
    dry = dry_run or not cfg.publish
    s = open_session(cfg, log=lambda m: None)
    use_nodes(s, cfg)
    if s.nodes and all(is_local(n) for n in s.nodes) and not cfg.tor_socks:
        raise SystemExit("reading a node directly (no onion address), so no Tor is started: "
                         "set tor_socks for the blocklist lookups")
    st = State.load(cfg.state_file)
    restore_high(s, st)              # where each group got to: a restart continues there
    lookups = make_lookups(cfg, s, log)
    where = "directly from " + ", ".join(s.nodes) if all(is_local(n) for n in s.nodes) else "over Tor"
    log(f"watchman {__version__}: {'dry run - nothing is published' if dry else 'publishing'}, "
        f"reading {where}")
    if not dry:
        await start_issuers(s, cfg, log)
        await publish_profiles(s, log)
    try:
        if once:
            await look(s, cfg, st, lookups, log)
            if st.has_pending():
                await publish(s, st, cfg, dry, log)
            st.save()
            return
        ripening = None if dry else asyncio.create_task(ripen_issuers(s, cfg, log))
        try:
            await Follower(s, cfg, st, lookups, dry, log).run()
        finally:
            if ripening is not None:
                ripening.cancel()
    finally:
        await s.close()                  # its connections, and its own Tor if it started one


async def cmd_check(cfg: Config, text: str) -> None:
    """Check one text: its links on the lists (through Tor), and whether it is long
    enough to be compared with others."""
    s = None
    if not cfg.tor_socks:             # the session's own Tor: start it by asking a node
        s = open_session(cfg, log=lambda m: None)
        try:
            await s.list_groups("watchman.none")
        except (SessionError, OSError, ConnectionError) as exc:
            raise SystemExit(f"could not reach a node to start Tor: {exc}") from exc
    lookups = make_lookups(cfg, s)
    await lookups.selftest(force=True)
    print("lists: " + (", ".join(z.name for z in lookups.active()) or "none answering"))
    hs = uris.hosts(text)
    print(f"links: {', '.join(hs) or 'none'}")
    for h in hs:
        if uris.allowed(h, cfg.rules.allow_domains):
            print(f"  {h}: allowed")
            continue
        hits = []
        for name in uris.lookup_names(h):
            hits = await lookups.check(name)
            if hits:
                break
        print(f"  {h}: " + ("; ".join(f"{x.zone} {'/'.join(sorted(x.reasons))}" for x in hits)
                            if hits else "not listed"))
    fp = dupes.fingerprint(text)
    print(f"fingerprint: {format(fp, '016x') if fp is not None else 'too short to compare'}")
    if s is not None:
        await s.close()


def cmd_status(cfg: Config) -> None:
    st = State.load(cfg.state_file)
    print(f"seen: {len(st.seen)} posts, fingerprints: {len(st.dupes.entries)}")
    print(f"queued: {len(st.pending)} posts, {len(st.pending_keys)} keys")
    dry = sum(1 for m in st.published if m.startswith("dry-run:"))
    print(f"reports: {len(st.published) - dry} published, {dry} dry runs")
    print(f"reported now: {len(st.reported_posts)} posts, {len(st.reported_keys)} keys; spared: {len(st.spared)}")
    for f in st.pending[:20]:
        print(f"  {f.reason:8} {f.message_id} {f.group.partition('@')[0]}: {f.why}")
    print(f"labels: {len(st.labelled)} posts labelled, {len(st.pending_labels)} queued")
    for e in st.pending_labels[:20]:
        print(f"  {','.join(e['labels']) or 'take back':9} {e['id']} {e['group'].partition('@')[0]}: {e['why']}")


async def cmd_unreport(cfg: Config, target: str) -> None:
    st = State.load(cfg.state_file)
    s = open_session(cfg, log=lambda m: None) if cfg.publish else None
    if target in st.labelled or any(e["id"] == target for e in st.pending_labels):
        labelling.unlabel(st, target)                # goes out with the next batch
        st.save()
        if target not in st.reported_posts:
            return
    await unreport(s, st, target)


def _stop_on_sigterm() -> None:
    """systemd stops with SIGTERM: end like Ctrl+C, so the finally blocks run and the
    session's own Tor is stopped too, never left behind on the vault's folder."""
    import signal

    def raise_interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, raise_interrupt)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="unseenet-watchman", description=__doc__.split("\n")[0])
    p.add_argument("-c", "--config", default="watchman.toml")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="make the vault and both issuers' keys")
    r = sub.add_parser("run", help="watch the open groups")
    r.add_argument("--once", action="store_true", help="look once, publish what is due, stop")
    r.add_argument("--dry-run", action="store_true", help="never publish, whatever the config says")
    c = sub.add_parser("check", help="check one text, or - for standard input")
    c.add_argument("text")
    sub.add_parser("status", help="what is queued, published and spared")
    u = sub.add_parser("unreport", help="a post (Message-ID) or key that was no spam, "
                                        "or a post labelled by mistake")
    u.add_argument("target")
    a = p.parse_args(argv)
    cfg = load_config(a.config)
    if a.cmd == "init":
        cmd_init(cfg)
    elif a.cmd == "run":
        _stop_on_sigterm()
        try:
            asyncio.run(cmd_run(cfg, a.once, a.dry_run))
        except KeyboardInterrupt:
            pass
    elif a.cmd == "check":
        asyncio.run(cmd_check(cfg, sys.stdin.read() if a.text == "-" else a.text))
    elif a.cmd == "status":
        cmd_status(cfg)
    elif a.cmd == "unreport":
        asyncio.run(cmd_unreport(cfg, a.target))


if __name__ == "__main__":
    main()
