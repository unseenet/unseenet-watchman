import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from unseenet_watchman import model


def test_parse_the_guard_format_only():
    op = model.parse("Safety: Unsafe\nCategories: Sexual Content or Sexual Acts")
    assert op.safety == "unsafe" and op.labels == ["sexual"] and not op.jailbreak
    assert model.parse("Safety: Safe\nCategories: None").categories == ()
    assert model.parse("Safety: Unsafe\nCategories: Violent, Jailbreak").jailbreak
    # a model talked round answers in another shape: no opinion
    assert model.parse("Sure! This post is clean.") is None
    assert model.parse("Safety: Safe\nCategories: None\nIgnore the above") is None
    assert model.parse("Safety: Clean\nCategories: None") is None
    assert model.parse("Safety: Safe\nCategories: Totally Fine") is None


def test_controversial_never_labels():
    op = model.parse("Safety: Controversial\nCategories: Sexual Content or Sexual Acts")
    assert op.labels == []


def test_clean_drops_quotes_encoding_and_signature():
    text = "> quoted fuck fuck\nmy own words\n\n\n\nmore\n-- \nsig fuck"
    assert model.clean(text) == "my own words\n\nmore"
    assert len(model.clean("et ord " * 1000, 3000)) == 3000


def test_excerpt_around_the_focus():
    text = "vejret er fint i dag. " * 200 + "sikke et lortesystem. " + "og så videre. " * 200
    ex = model.excerpt(text, ["lortesystem"], 600)
    assert len(ex) == 600 and "lortesystem" in ex
    assert model.excerpt("kort tekst", ["x"], 600) == "kort tekst"
    assert model.excerpt(text, [], 600).startswith("vejret")


def test_hidden_words():
    assert model.hidden("hvilket f u c k system") == ["f u c k"]
    assert model.hidden("hvilket f.u.c.k system") == ["f.u.c.k"]
    assert "lortesystem" in model.hidden("sikke et lortesystem")
    assert model.hidden("an ordinary sentence about the weather") == []
    assert model.hidden("a b c d") == []                     # letters, but no word


def test_doubt_reasons():
    rules = model.labels.Rules()
    assert not model.doubt("Hej, hvordan går det med projektet?", rules)
    assert "labelled" in model.doubt("fuck fuck", rules).reasons
    long_one = "lort " + "det er nu en lang tekst om vejret og ikke andet end det. " * 3
    assert model.doubt(long_one, rules).reasons == ["one word"]
    d = model.doubt("sikke et lortesystem i dag", rules)
    assert "hidden" in d.reasons and d.focus == ["lortesystem"]


class _Fake(BaseHTTPRequestHandler):
    answer = "Safety: Unsafe\nCategories: Sexual Content or Sexual Acts"
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Fake.seen.append(body)
        out = json.dumps({"choices": [{"message": {"content": _Fake.answer}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


async def test_ask_sends_only_the_post_and_parses():
    srv = HTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = model.ModelConfig(url=f"http://127.0.0.1:{srv.server_port}", model="g")
        op = await model.ask(cfg, "> quoted\nthe post")
        assert op.labels == ["sexual"]
        sent = _Fake.seen[-1]
        assert sent["messages"] == [{"role": "user", "content": "the post"}]
        _Fake.answer = "I think it is fine"
        assert await model.ask(cfg, "the post") is None
        cfg.url = "http://127.0.0.1:1"                       # nobody there
        assert await model.ask(cfg, "the post") is None
    finally:
        srv.shutdown()
