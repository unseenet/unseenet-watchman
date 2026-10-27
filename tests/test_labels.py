from unseenet_watchman import labelling, labels
from unseenet_watchman.state import State

from test_watch import FakeSession, msg

DA_RUDE = "Det er sgu da noget lort, og jeg gider ikke mere af det her lort"
DA_CLEAN = "Hej alle sammen, hvordan går det med jeres projekter i dag? Jeg har lavet en ny node."


def test_language_from_small_words():
    assert labels.language(labels.words(DA_CLEAN)) == "da"
    assert labels.language(labels.words("This is about the weather and what we will do")) == "en"
    assert labels.language(labels.words("Das ist nicht so schlimm, und ich weiß es")) == "de"
    assert labels.language(labels.words("ok")) is None


def test_words_keep_spellings_drop_quotes_and_signature():
    assert labels.words("> quoted lort\nwhat an @$$, f*ck\n--\nlort") == ["what", "an", "@$$", "f*ck"]


def test_threshold_and_short_posts():
    assert labels.profanity(DA_RUDE).hits == ["lort", "lort"]
    assert labels.profanity(DA_CLEAN) is None
    one = "Det er lort, men jeg tror at det går over igen når vi har fået sovet lidt"
    assert labels.profanity(one) is None                        # one word, long post
    assert labels.profanity("fuck dig").hits == ["fuck dig"]    # a phrase counts once


def test_whole_words_only():
    assert labels.profanity("Scunthorpe and Essex and the class assignment are fine") is None


def test_the_authors_own_tag_wins():
    assert labels.profanity(DA_RUDE, author_tags=("profanity",)) is None


def test_the_right_language_list_only():
    # "slut" is on the English list but means "end" in Danish: a Danish post is not labelled
    da = "Slut for i dag, og jeg siger slut med det her, slut"
    assert "slut" in labels.wordlist("en").single
    assert labels.language(labels.words(da)) == "da"
    assert labels.profanity(da) is None


async def test_queue_publish_and_take_back(tmp_path):
    st = State(tmp_path / "s.json")
    m = msg(1, "dk.snak@f", "ed25519:a", DA_RUDE)
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
    assert st.labelled["<m1@x>"]["article"] == "<l1@x>" and not st.pending_labels
    assert labelling.unlabel(st, "<m1@x>", log=lambda x: None)
    await labelling.publish(s, st, dry_run=False, log=lambda x: None)
    assert published[1][0] == [("<m1@x>", "dk.snak@f", [])]     # [] takes it back
    assert "<m1@x>" not in st.labelled
    assert not labelling.check(m, st, labels.Rules(), log=lambda x: None)   # spared now


def test_every_list_on_every_post():
    # a Danish post with an English insult: the English list counts too
    mixed = "Jeg synes bare at du er en idiot og fuck you your mother fucker, det er sådan det er"
    v = labels.profanity(mixed)
    assert v.lang == "da" and "mother fucker" in v.hits


def test_false_friends_only_in_their_own_language():
    assert "slut" in labels.harmless("da")
    assert labels.profanity("You are such a slut and a bitch").hits == ["slut", "bitch"]


def test_one_place_counts_once_across_lists():
    # "fuck dig" is a Danish phrase; "fuck" alone is on several lists
    assert labels.profanity("fuck dig").hits == ["fuck dig"]


def test_encoded_data_is_not_text():
    assert labels.looks_encoded("M9V]D;&5S(&]F('1H92!W;W)L9\"!A;F0@=&AE(&9I<G-T(&]F")
    assert labels.looks_encoded("j ofx r * m d h0r k r r u c bq 6 p _qv bj h0r f p ww i qz x")
    assert not labels.looks_encoded("This is an ordinary line of English text that goes on a while.")
    assert labels.words("hello there\nj ofx r * m d h0r k r r u c bq 6 p _qv bj h0r f p ww i") == ["hello", "there"]


def test_raspberry_pis_are_not_danish():
    assert labels.profanity("I tend to use those on my pis, and several just use pis for that") is None


async def test_the_subject_counts_too(tmp_path):
    st = State(tmp_path / "s.json")
    m = msg(1, "g@f", "ed25519:a", "see the attachment")
    m.subject = "fuck dig"
    assert labelling.check(m, st, labels.Rules(), log=lambda x: None)


async def test_a_replys_inherited_subject_does_not_count(tmp_path):
    st = State(tmp_path / "s.json")
    m = msg(2, "g@f", "ed25519:b", "I agree with what you wrote")
    m.subject, m.references = "Re: fuck dig", ["<m1@x>"]
    assert not labelling.check(m, st, labels.Rules(), log=lambda x: None)
