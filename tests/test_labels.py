import pytest

from unseenet_watchman import labelling, labels
from unseenet_watchman.state import State

from test_watch import FakeSession, msg


def kinds(text, **kw):
    return {v.label for v in labels.check(text, **kw)}


@pytest.mark.parametrize("lang,text", [
    ("da", "Jeg har lidt travlt, og det er måske noget vi kan tage op senere hvis I vil"),
    ("no", "Jeg har litt dårlig tid, og det er kanskje noe vi kan ta opp senere hvis dere vil"),
    ("sv", "Jag har lite ont om tid och det är kanske något vi kan ta upp senare om ni vill"),
    ("de", "Ich habe wenig Zeit und das ist vielleicht etwas, das wir später machen können"),
    ("nl", "Ik heb het druk en dat is misschien iets wat we later kunnen doen als jullie willen"),
    ("en", "I am a bit busy, and this is something we could pick up later if you would like"),
    ("fr", "Je suis un peu occupé et c'est peut-être quelque chose que nous ferons plus tard"),
    ("es", "Estoy un poco ocupado y esto es algo que podemos hacer más tarde si queréis"),
    ("it", "Sono un po' occupato e questo è qualcosa che possiamo fare più tardi se volete"),
])
def test_language_from_its_own_small_words(lang, text):
    assert labels.language(labels.words(text)) == lang
    assert labels.check(text) == []


@pytest.mark.parametrize("text", [
    "Det er sgu noget lort, for fanden",
    "Fy faen, for noe dritt",
    "Fy fan, vilket jävla skit",
    "Verdammte Scheiße, was für ein Mist",
    "Godverdomme, wat een klote dag",
    "What the fuck, this is bullshit",
    "Putain, quelle merde",
    "Joder, qué mierda",
    "Che cazzo, porca miseria",
])
def test_swearing_in_nine_languages(text):
    assert "profanity" in kinds(text)


def test_insults_are_not_profanity():
    assert labels.check("Du er en idiot og en tosse, og det ved du godt selv, din idiot") == []


def test_sexual_is_its_own_label():
    assert kinds("Hun vil kneppe, og han ser porno") == {"sexual"}
    assert kinds("fuck, porn and more fucking porn") == {"profanity", "sexual"}


def test_every_list_on_every_post():
    mixed = "Hvad sker der, jeg synes meget af det er noget værre, og what the fuck, fuck"
    v = labels.profanity(mixed)
    assert v.lang == "da" and "what the fuck" in v.hits


def test_false_friends_only_in_their_own_language():
    assert labels.check("Slut for i dag, og jeg siger slut med det her, slut") == []   # Danish: end
    assert "sexual" in kinds("You are such a slut, a total slut")                    # English
    assert labels.check("Jag fick inte mycket gjort, men jag fick lite tid till det") == []  # Swedish: got
    assert labels.check("I tend to use those on my pis, and several just use pis for that") == []
    assert labels.check("I am a big fan, a real fan of this band") == []


def test_one_place_counts_once_across_lists():
    assert labels.profanity("what the fuck").hits == ["what the fuck"]


def test_whole_words_only():
    assert labels.check("Scunthorpe and Essex and the class assignment are fine") == []


def test_encoded_data_is_not_text():
    assert labels.looks_encoded("M9V]D;&5S(&]F('1H92!W;W)L9\"!A;F0@=&AE(&9I<G-T(&]F")
    assert labels.looks_encoded("j ofx r * m d h0r k r r u c bq 6 p _qv bj h0r f p ww i qz x")
    assert not labels.looks_encoded("This is an ordinary line of English text that goes on a while.")


def test_threshold_and_short_posts():
    long_one = "Det er noget lort, men jeg tror at det går over igen når vi har fået sovet lidt"
    assert labels.check(long_one) == []                      # one word, long post
    assert "profanity" in kinds("fuck dig")                  # short post


def test_the_authors_own_tag_wins():
    assert kinds("fuck this shit, fuck it", author_tags=("profanity",)) == set()


async def test_queue_publish_and_take_back(tmp_path):
    st = State(tmp_path / "s.json")
    m = msg(1, "dk.snak@f", "ed25519:a", "Det er sgu noget lort, for fanden, sikke noget lort")
    assert labelling.check(m, st, labels.Rules(), log=lambda x: None)
    assert not labelling.check(m, st, labels.Rules(), log=lambda x: None)   # queued once
    s = FakeSession({})
    published = []

    async def publish_labels(rows, note="", labeller=None):
        published.append((rows, note, labeller))
        return f"<l{len(published)}@x>"
    s.publish_labels = publish_labels
    assert await labelling.publish(s, st, dry_run=False, log=lambda x: None) == 1
    assert published[0][0] == [("<m1@x>", "dk.snak@f", ["profanity"])]
    assert published[0][2] == "labels" and published[0][1].startswith("automatic: ")
    assert labelling.unlabel(st, "<m1@x>", log=lambda x: None)
    await labelling.publish(s, st, dry_run=False, log=lambda x: None)
    assert published[1][0] == [("<m1@x>", "dk.snak@f", [])]     # [] takes it back
    assert not labelling.check(m, st, labels.Rules(), log=lambda x: None)   # spared now


async def test_the_subject_counts_but_not_a_replys(tmp_path):
    st = State(tmp_path / "s.json")
    m = msg(1, "g@f", "ed25519:a", "see the attachment")
    m.subject = "fuck dig"
    assert labelling.check(m, st, labels.Rules(), log=lambda x: None)
    r = msg(2, "g@f", "ed25519:b", "I agree with what you wrote")
    r.subject, r.references = "Re: fuck dig", ["<m1@x>"]
    assert not labelling.check(r, st, labels.Rules(), log=lambda x: None)


def test_detect_asks_lingua_only_when_the_small_words_cannot_tell(monkeypatch):
    asked = []

    def fake(ws):
        asked.append(ws)
        return "sv"
    import unseenet.core.language as core_language
    monkeypatch.setattr(core_language, "lingua_language", fake)
    assert labels.detect(labels.words("Jeg har lidt travlt, måske noget vi kan tage senere")) == "da"
    assert asked == []                                        # the small words were sure
    assert labels.detect(labels.words("hej hej")) == "sv"     # they were not: Lingua


def test_lingua_when_installed():
    pytest.importorskip("lingua")
    assert labels.lingua_language(labels.words("Tak for hjælpen, vi ses i morgen tidlig")) in ("da", "no", None)
    assert labels.lingua_language(labels.words("Thanks for the help, see you tomorrow morning")) == "en"
