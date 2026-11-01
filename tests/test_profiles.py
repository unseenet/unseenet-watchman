"""Each identity's profile says what it does (watchman#25): the labeller labels and never
reports, the two issuers report, each its own kind; a changed text is published again."""

from unseenet_watchman import labelling, runner


def test_each_identity_says_what_it_does():
    spam, phishing, labeller = (runner.about_for(n) for n in ("spam", "phishing", labelling.NAME))
    assert len({spam, phishing, labeller}) == 3
    assert "content labels" in labeller and "UN-RFC 0053" in labeller
    assert "spam reports" not in labeller and "never name keys" in labeller
    assert "(spam)" in spam and "blocklists for spam" in spam
    assert "(phishing)" in phishing and "phishing and malware" in phishing


async def test_a_changed_text_is_published_again(monkeypatch):
    published = []

    class FakeSession:
        def __init__(self):
            self.data = {"identities": {"spam": {}, "phishing": {}, labelling.NAME: {}}}

        async def publish_profile(self, prof):
            published.append(prof)

        def save(self):
            pass

    from contextlib import contextmanager

    @contextmanager
    def acting(s, name):
        yield

    monkeypatch.setattr(runner, "acting", acting)
    s = FakeSession()
    await runner.publish_profiles(s, log=lambda *_: None)
    assert len(published) == 3
    await runner.publish_profiles(s, log=lambda *_: None)
    assert len(published) == 3                       # the same text: not again
    monkeypatch.setattr(runner, "LABELLER_ABOUT", runner.LABELLER_ABOUT + "\nmore\n")
    await runner.publish_profiles(s, log=lambda *_: None)
    assert len(published) == 4                       # only the labeller's changed
