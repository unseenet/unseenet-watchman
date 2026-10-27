# Changelog

All notable changes to unseenet-watchman are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/) on the same principles as
[unseenet](https://github.com/unseenet/unseenet/blob/main/docs/development.md#versioning).

## [Unreleased]

- **The first watchman** (#1): an automatic issuer of UN-RFC 0045 spam reports.
  Reads the open groups and feeds, finds links to domains on URI blocklists
  (Spamhaus DBL, SURBL; looked up through Tor) and near-identical texts from
  many keys or from one key in many groups (SimHash), and publishes them in
  hourly batches - one issuer for spam and flood, one for phishing and malware,
  both `automatic: true`, each with a note saying why. Keys only after repeated
  findings, for 30 days. A dry run until `publish = true`; `unreport` takes a
  mistake back. Commands `init`, `check`, `run`, `status`, `unreport`.
