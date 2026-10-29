# The watchman

The watchman reads Unseenet's open groups and publishes **spam reports**
([UN-RFC 0045](https://unseenet.org/spec/un-rfc-0045/)) as an automatic
issuer. It calls out what looks like spam; it never removes anything.

## Following it

In the graphical and the terminal client, spam reports are under the report
issuers you follow. The watchman has two issuers, one per kind of finding:

- **Unseenet watchman (spam)** - posts that look like spam: the same text
  from many keys, the same text from one key in many groups, or links to
  domains on spam blocklists;
- **Unseenet watchman (phishing)** - posts with links to phishing or malware.

Follow either, both or neither. A post hidden by a report is shown as hidden,
with the issuer and the reason, one click from being shown; posts from your
contacts and your own are never hidden. Stop following at any time.

A hierarchy's maintainer or a group's owner may name the watchman as a
default for their groups (UN-RFC 0045 sections 7.1 and 7.5). You can still
turn it off.

## Reported by mistake?

Write to the issuer's inbox (its `contact`). A person looks at it, and a
mistake is taken back: the report is withdrawn and the post or key is never
reported again.

## Running your own

Anybody can run a watchman, with their own lists and thresholds; readers
then choose whose they follow. See the
[README](https://github.com/unseenet/unseenet-watchman#run-it) for
installing it, the config and the blocklists' terms. Start with
`publish = false`, read what it would have reported, and only then publish.

## In Docker

`ghcr.io/unseenet/watchman` has the watchman with `[lingua]`, the core and Tor,
for amd64 and arm64, published for releases only and signed with cosign. The
vault, `watchman.toml` and the state are in the volume at `/data`; the vault's
passphrase comes from a Docker secret (`unseenet_vault_passphrase`),
`UNSEENET_VAULT_PASSPHRASE_FILE` or `UNSEENET_VAULT_PASSPHRASE`.

```sh
docker run --rm -v watchman:/data ghcr.io/unseenet/watchman            # writes an example watchman.toml
docker run --rm -it -v watchman:/data -e UNSEENET_VAULT_PASSPHRASE=... ghcr.io/unseenet/watchman init
docker run -d --name watchman -v watchman:/data -e UNSEENET_VAULT_PASSPHRASE=... ghcr.io/unseenet/watchman
```

With [`compose.yaml`](https://github.com/unseenet/unseenet-watchman/blob/main/compose.yaml)
it runs beside a node in the same project (`nodes = ["node:1119"]`), with a
read-only root file system. As beside any hidden node, running it there ties the
two together by uptime (the README says more).
