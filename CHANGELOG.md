# Changelog

All notable changes to unseenet-watchman are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/) on the same principles as
[unseenet](https://github.com/unseenet/unseenet/blob/main/docs/development.md#versioning).

## [Unreleased]

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
