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
