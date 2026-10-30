<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/unseenet/unseenet/main/assets/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/unseenet/unseenet/main/assets/logo-light.svg" alt="Unseenet" width="360">
  </picture>
</p>

<h1 align="center">unseenet-watchman</h1>

<p align="center"><b>Reads the open groups and calls out what looks like spam.</b><br>
Signed spam reports that readers, group owners and node operators may choose to follow - nobody has to.</p>

<p align="center">
  <a href="https://github.com/unseenet/unseenet-watchman/releases"><img src="https://img.shields.io/github/v/release/unseenet/unseenet-watchman?include_prereleases&label=release" alt="Release"></a>
  <a href="https://github.com/unseenet/unseenet-watchman/actions/workflows/tests.yml"><img src="https://github.com/unseenet/unseenet-watchman/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
</p>

> **Pre-alpha.** Nothing is stable yet, and Unseenet has not had a security
> review. Do not rely on it to protect anyone yet.

## What it is

Like the night watchmen of old towns, it walks the streets and calls out
what it sees - it does not arrest anyone. The watchman is an **automatic
issuer** of [UN-RFC 0045](https://unseenet.org/spec/un-rfc-0045/) spam
reports: it reads the open groups of [Unseenet](https://unseenet.org),
checks each new post, and publishes what looks like spam in its own
`reports@` channel, marked `automatic: true` (section 8). In the tradition of
the NoCeM notices of old Usenet.

**Status:** early. It finds links to domains on URI blocklists and the same
text posted from many keys or in many groups, and runs as a dry run until its
operator turns publishing on.

### Labels, too

With `labels = true` it is also a **labeller**
([UN-RFC 0053](https://unseenet.org/spec/un-rfc-0053/)) with a third key,
*Unseenet watchman (labels)*, giving two warning labels: **`profanity`** (swearing,
oaths, vulgar words) and **`sexual`** (sexual and obscene words). Labels **describe,
they never sanction** - no key is touched, no node acts on them, and a reader chooses
whether to follow the labeller and what to do with a label (show, blur or hide).

- **Its own word lists** in nine languages - Danish, Norwegian, Swedish, German,
  Dutch, English, French, Spanish, Italian - in
  [`wordlists/`](src/unseenet_watchman/wordlists/SOURCE.md). **Insults are not on
  them** ("idiot" is rude behaviour, not a kind of language), and neither are words
  with a harmless meaning in the same language.
- **Every list on every post** - people mix languages, and a Danish post with an
  English oath in it is ordinary. A place in the text counts once.
- **False friends** count only in their own language: "slut" is rude in English and
  means "end" in Danish, "fick" is rude in German and means "got" in Swedish. The
  language is told from a post's own small words, and by
  [Lingua](https://github.com/pemistahl/lingua-py) when they cannot tell (install
  `unseenet-watchman[lingua]`, about 170 MB; 89 % right on Usenet posts against 78 %
  for the small words alone) - never from its language header: anybody can declare
  Danish and swear in English.
- **Mentioned is not used**: a word in a short quotation (`"kneppe"`), in code, or right
  after "ordet", "the word", "das Wort" and the like is talked about, not said - a
  debate about a word, or the watchman's own release notes.
- **Written to slip past** is read as what it spells: "f u c k", "h0r", "fuuuck",
  "f\*ck", and compounds in the post's language family and English ("lortesystem",
  "scheißegal", "shitshow") - but not ordinary words that only look like one (cockpit,
  Pissarro, "fandenivoldsk"; [`harmless.txt`](src/unseenet_watchman/wordlists/harmless.txt)).
- **A threshold**: at least two words or phrases in a post, or one in a post of at most
  eight words. A post over 300 words also needs 0.5 points per 100 words - strong words
  (fuck, cunt) count 2, mild ones (damn, lort) 1 - so two mild oaths in a long essay are
  no label. The subject counts too, but not in a reply.
- **The author first**: a label the author already gave as a tag is not given again.
- A label given by mistake is taken back with `unreport` (it publishes `[]` for that
  post) and the post is never labelled again.

### Who watches the watchman?

You do. A report does nothing by itself (UN-RFC 0045 section 5):

- **You choose** whether to follow it, and can stop at once. A hierarchy or a
  group's owner may name it as a default for their groups; you can turn that off.
- **Nothing is removed.** Clients show a hidden post as hidden, with the
  issuer and the reason, one click from being shown. Posts from your contacts
  and your own are never hidden.
- **Node operators** follow it only if they write it into their config.
- **It cannot make anything cheaper or more trusted**, so following it gives
  it no power over anyone who doesn't.

### Two lists, one per kind

It keeps **one issuer key per kind of finding**, each with its own `reports@`
channel, so you can follow exactly what you want:

| Issuer | Reports | From |
|---|---|---|
| *Unseenet watchman (spam)* | `spam`, `flood` | the same text from many keys, the same text from one key in many groups, links on spam blocklists |
| *Unseenet watchman (phishing)* | `phishing`, `malware` | links on phishing and malware blocklists |

### Rules it follows

- **Posts first, keys later.** A key is reported only after repeated findings
  (3 in 7 days by default), and then for 30 days - never the 365 the RFC allows.
- **A reason with every report.** The note says why: "2 × links on
  dbl.spamhaus.org; the same text from 7 keys".
- **Only open groups.** Closed groups and private posts are ciphertext to it,
  and a sealed private post is never reported. Feeds are read, because others
  comment there.
- **Nothing from before its first look.** It leaves earlier posts alone.
- **Every lookup through Tor**, with DNS-over-HTTPS, so neither the lists nor
  the resolver learn where it runs. A list that fails its own test point is
  paused, never trusted to say "clean".
- **Mistakes are taken back.** `unreport` withdraws the report that named a
  post or key, publishes the rest of it again, and never reports it again.

## Run it

```sh
pip install "unseenet-watchman @ git+https://github.com/unseenet/unseenet-watchman.git"
cp watchman.example.toml watchman.toml      # read it: publish = false to begin with
export UNSEENET_VAULT_PASSPHRASE=...
unseenet-watchman -c watchman.toml init     # the vault and both issuers' keys
unseenet-watchman -c watchman.toml check "Visit http://example.com now"   # one text
unseenet-watchman -c watchman.toml run --once   # look once; the batch goes to the log
unseenet-watchman -c watchman.toml run      # keep watching
unseenet-watchman -c watchman.toml status   # what is queued, published and spared
unseenet-watchman -c watchman.toml unreport "<message-id>"   # it was no spam
```

**Upgrading:** upgrade the core with it - pip does not upgrade a dependency
named by a git URL by itself:

```sh
pip install --upgrade --force-reinstall --no-deps "unseenet @ git+https://github.com/unseenet/unseenet@main"
pip install --upgrade --force-reinstall --no-deps "unseenet-watchman @ git+https://github.com/unseenet/unseenet-watchman.git"
```

**Never restart it while a key is ripening** (a new issuer or the labeller: one CPU
busy for a long while, "made ... key" in the log and no channel started yet) - the
segment being proved starts over. Labels need nodes whose core knows `labels@`
(UN-RFC 0053, core 0.6.0); on an older node the watchman says so and goes on with
the reports.

It needs the `tor` program: like every Unseenet client it starts its own Tor
(or uses a running one, `tor_socks`), and looks the blocklists up through
it as well. Run it with
`publish = false` for a while and read the log: each batch is written there
as the report it would have been. Only when that looks right, set
`publish = true`. `contrib/unseenet-watchman.service` runs it under systemd.

### Beside a node

Over Tor every fetch is a round trip through an onion circuit, about a
second. Run the watchman on the same machine as a node and point it at the
node's local port instead - every fetch then takes milliseconds, and the node
pushes every new article the moment it lands:

```toml
[watchman]
nodes = ["127.0.0.1:1119"]       # the node's --listen
tor_socks = "127.0.0.1:9050"     # a Tor on the machine, for the blocklists
```

The blocklist lookups and the reports still go through Tor and the node like
anyone's. Think about one thing first: **an issuer that runs beside a node
stops publishing when that node is down**, so somebody watching both could
tie the issuer's key to the node by their uptime. For a node whose operator
is known anyway - the project's own, an organisation's backbone node - that
costs nothing. For a node that wants to stay hidden, run the watchman
elsewhere, over Tor.

### The blocklists

A URI blocklist is a DNS zone that answers with a 127.0.0.x address when a
domain is listed. **Tor drops such answers** when it resolves a name itself -
a safety rule of the Tor client - so through plain DNS every domain would look
clean. The watchman therefore asks a **DNS-over-HTTPS** resolver *through* Tor;
the resolver sees which domains are looked up - links in public posts - and a
Tor exit, never the watchman.

`doh` is a list of resolvers, tried in order. The default is four that answered
SURBL through Tor in October 2026: Google, Wikimedia DNS, AdGuard (unfiltered)
and DNS.SB. Cloudflare answers SURBL with SERVFAIL, and Quad9 and Mullvad only
speak HTTP/2, which the watchman does not. Requests are RFC 8484 wire format; a
URL ending in `/resolve` is asked in Google's JSON format instead. A lookup that fails - usually a bad exit or a circuit Tor could not
build - is asked once more on a fresh circuit, then through the next resolver.
Only when all fail are the blocklists skipped for that post, and the log says so.

Lists refuse big public resolvers, sometimes silently with "does not exist".
So each list has a **test point**, a domain it always lists, looked up at start
and every 6 hours, through each resolver. A resolver that fails it is not used
for that list; a list is paused only when no resolver passes, and the log says
why. So a fallback can never be a resolver that silently makes every domain
look clean. What that showed in October 2026:

| List | Through public DoH | Default |
|---|---|---|
| [SURBL](https://surbl.org/) `multi.surbl.org` | answers | on |
| [Spamhaus](https://www.spamhaus.org/) DBL | refuses (via Google silently) | on with a free DQS key (`spamhaus_dqs_key`) |
| URIBL `multi.uribl.com` | refuses | off |

Check each list's terms of use - several are free only for small,
non-commercial use. The lists, their answer codes and test points are in the
config (`[[zone]]`), so a list that changes is a config change, not a release.
`check` shows which lists answer before it checks a text.

### Deceptive link cards

A post can carry a preview of a link, a link card
([UN-RFC 0059](https://unseenet.org/spec/un-rfc-0059/)), whose title and
description are the poster's. With `cards = true` the watchman reads the
linked page over Tor itself (without its picture) and reports the post as
**phishing** when the card's title has nothing in common with the page: not a
word of four letters or more of the page's title, description or site name.
Careful on purpose: a card title of under three words, a page that gives no
title, or a cookie wall, captcha or error page instead of the page is never
reported. Each link is read once a day at most. Off by default - each card is
a fetch over Tor.

## How it works

- **Built on the core.** An ordinary Unseenet client on
  `unseenet.client.session.Session` from
  [unseenet/unseenet](https://github.com/unseenet/unseenet): reading,
  postage, ripening and publishing reports are the same code as everywhere.
  Reasons come from the core's one list, `unseenet.core.reports.REASONS`.
- **Links.** The hosts of the links in a post are looked up in each list,
  with their parent domains; the most serious reason wins.
- **Near-identical texts.** Each post gets a 64-bit SimHash of its words -
  without quotes, signature, link paths or numbers - and posts at most 3 bits
  apart are the same. Four 16-bit bands index them, so no pair is compared
  needlessly. A wave is reported as a whole, earlier posts too. This is also a
  first try at fingerprint reports
  ([unseenet#123](https://github.com/unseenet/unseenet/issues/123)).
- **Push, not walking the network.** Each node is asked to push every new
  article (`XUN-WATCH *`, UN-RFC 0008), and only the group it lands in is
  fetched, only what is new in it. A full sweep runs hourly to catch what a
  push missed. The first look starts every group at its newest post without
  fetching what is there, articles are read without being kept (the session's
  cache stays empty), and where each group got to is kept in the state, so a
  restart goes on from there.
- **Batches.** What it finds waits for the next batch (hourly by default):
  one report article per issuer, at most 1000 entries each.

Labels - profanity, adult content and the like, which describe and never
sanction - are a different thing and will get their own lists once
[unseenet#656](https://github.com/unseenet/unseenet/issues/656) is specified.

## Versions and releases

Versions follow [semantic versioning](https://semver.org/) on the same
principles as [unseenet](https://github.com/unseenet/unseenet/blob/main/docs/development.md#versioning):
tags `vX.Y.Z` on `main`, the changes in [CHANGELOG.md](CHANGELOG.md), a GitHub
release and a [PyPI](https://pypi.org/p/unseenet-watchman) release for each tag
(trusted publishing, no stored token). Each release names the minor version of
unseenet it works with (`unseenet>=0.6,<0.7`). The first, 0.1.0, comes with core
0.6.0 - until then it is built against unseenet `main`, and the release workflow
refuses to publish while the core is named by a git URL.

To release: move the entries under `## [Unreleased]` in `CHANGELOG.md` to a
new `## [X.Y.Z] - YYYY-MM-DD` section, set `__version__` in
`src/unseenet_watchman/__init__.py`, commit, then
`git tag -a vX.Y.Z -m "unseenet-watchman X.Y.Z" && git push origin vX.Y.Z`.

## Part of Unseenet

| Repository | What it is |
|---|---|
| [unseenet](https://github.com/unseenet/unseenet) | The protocol (UN-RFCs), the core library, the node and the command-line client |
| [unseenet-tui](https://github.com/unseenet/unseenet-tui) | The terminal client |
| [unseenet-gui](https://github.com/unseenet/unseenet-gui) | The graphical client - in a window, booted, or in a browser |
| [unseenet-portable](https://github.com/unseenet/unseenet-portable) | Builds the portable clients, Terminal and Graphical, with Tor inside |
| [unseenet-bootable](https://github.com/unseenet/unseenet-bootable) | Builds the bootable images, Terminal and Graphical |
| [unseenet-docs](https://github.com/unseenet/unseenet-docs) | The site [unseenet.org](https://unseenet.org) |
| [unseenet-entrance](https://github.com/unseenet/unseenet-entrance) | Web entrances: the graphical client in an ordinary browser |
| [unseenet-gateway](https://github.com/unseenet/unseenet-gateway) | Gateways to other networks: Usenet, Nostr, Matrix |
| [unseenet-bots](https://github.com/unseenet/unseenet-bots) | Bots that keep channels filled with current content |
| [unseenet-helpbot](https://github.com/unseenet/unseenet-helpbot) | The bot that answers questions in `unseenet.help` |
| [unseenet-watchman](https://github.com/unseenet/unseenet-watchman) | Automatic spam reports that readers may choose to follow |
| [unseenet-stats](https://github.com/unseenet/unseenet-stats) | Statistics for the network |
| [unseenet-mcp](https://github.com/unseenet/unseenet-mcp) | An MCP server, so a language model can read and post as you (planning) |
| [unseenet-demo](https://github.com/unseenet/unseenet-demo) | Demo people, feeds and sites, made with the command-line client |

## License

[Apache License 2.0](LICENSE). The Unseenet logo: CC BY 4.0.
