# Changelog

All notable changes to unseenet-watchman are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/) on the same principles as
[unseenet](https://github.com/unseenet/unseenet/blob/main/docs/development.md#versioning).

## [Unreleased]

- **Labels never stop the reports** (#9): when a node refuses the labels channel (a core
  before 0.6.0 does not know `labels@`), the watchman logs it, turns labels off and goes
  on with the reports, instead of exiting. README: upgrading the core too, and never
  restarting while a key ripens.
- **Labels, tried on 2400 Usenet posts** (#8): the subject counts too (not in a reply,
  whose author kept it); lines of encoded data (uuencode, yEnc, base64) are not read as
  words ("h0r" was found in one); "pis" is ordinary English (Raspberry Pis), so it is
  in `wordlists/harmless-en.txt`.
- **Following every group as the core now allows** (#7, unseenet#669): the first look
  starts each group at its newest post (`skip_to_now`) instead of fetching everything to
  leave it alone, and articles are read with `keep=False`, so nothing is cached and memory
  stays flat as the network grows. How far each group was read is kept in our state, as the
  session keeps it in memory only with `keep=False`. Issuers start with `issuer=` (unseenet#661).
- **Labels: every list on every post** (#6): a Danish post with an English
  insult was checked against the Danish list only. Now every list counts, a
  place in the text once; the language (told from the text, never from the
  post's language header) only keeps false friends like Danish "slut" from
  counting (`wordlists/harmless-<lang>.txt`).
- **Labeller** (#2): with `labels = true` a third key, *Unseenet watchman
  (labels)*, gives the warning label `profanity` (UN-RFC 0053) from the word
  lists of ovos-good-manners-pipeline-plugin (da, de, en). The language is
  told from a post's small words first, so only its own list is used; whole
  words and phrases only, at least two (one in a post of at most eight
  words); never when the author tagged it. Batched with the reports; taken
  back with `unreport`, which publishes `[]` for the post.
- **Push** (#4): new posts come by push from each node (`XUN-WATCH *`) and
  only that group is fetched; a full sweep runs hourly (`sweep_minutes`,
  replacing `interval_minutes`). Where each group got to is kept, so a restart
  goes on from there instead of fetching everything again.
- **Beside a node** (#4): `nodes = ["127.0.0.1:1119"]` reads a node directly,
  without Tor; `tor_socks` is then needed for the blocklists. The README says
  what that means for a node that wants to stay hidden.
- **The first watchman** (#1): an automatic issuer of UN-RFC 0045 spam reports.
  Reads the open groups and feeds, finds links to domains on URI blocklists
  (Spamhaus DBL, SURBL; looked up through Tor) and near-identical texts from
  many keys or from one key in many groups (SimHash), and publishes them in
  hourly batches - one issuer for spam and flood, one for phishing and malware,
  both `automatic: true`, each with a note saying why. Keys only after repeated
  findings, for 30 days. A dry run until `publish = true`; `unreport` takes a
  mistake back. Commands `init`, `check`, `run`, `status`, `unreport`.
- **Blocklists through DNS-over-HTTPS** (#1): Tor drops DNS answers that are
  127.0.0.x, which is every blocklist answer, so lookups go to a DoH resolver
  through Tor. Each list has a test point checked every 6 hours; a list that
  fails it is paused. SURBL on by default, Spamhaus DBL with a DQS key, URIBL off.
