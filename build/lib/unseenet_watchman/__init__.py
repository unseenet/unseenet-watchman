"""unseenet-watchman: reads Unseenet's open groups and publishes spam reports.

An automatic issuer (UN-RFC 0045 section 8): it says what looks like spam, and
readers, hierarchy maintainers, group owners and node operators decide whether to
listen. It never removes anything itself.

Modules:

- ``uris``     links in a post, and the domain names to look up for them
- ``dnsbl``    URI blocklists (Spamhaus DBL, SURBL ...) looked up through Tor
- ``dupes``    near-identical posts across groups and keys (SimHash)
- ``decide``   from what the checks found to findings: post, reason, why
- ``state``    what has been seen, what waits to be published, what was published
- ``watch``    one look at the network, and publishing findings as reports
- ``runner``   the command line
"""

__version__ = "0.1.0.dev0"
