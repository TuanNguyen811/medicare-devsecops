from email.message import Message

import login


def headers(*set_cookies):
    msg = Message()
    for value in set_cookies:
        msg["Set-Cookie"] = value
    return msg


def test_extract_csrf_from_form_and_meta():
    form = '<input type="hidden" name="csrf_token" value="abc-123_x">'
    meta = '<meta name="csrf-token" content="meta-token">' + form
    assert login.extract_csrf(form) == "abc-123_x"
    assert login.extract_csrf(meta) == "meta-token"  # the rotated token of the page wins
    assert login.extract_csrf("<p>no token</p>") is None


def test_session_cookie_from_headers():
    h = headers("other=1; Path=/", "medicare_session=eyJhIjoxfQ==.Zx.sig; path=/; HttpOnly")
    assert login.session_cookie(h) == "eyJhIjoxfQ==.Zx.sig"
    assert login.session_cookie(headers("other=1")) is None
    assert login.session_cookie(headers()) is None


def test_main_requires_password(monkeypatch, capsys):
    monkeypatch.delenv("DEMO_PASSWORD", raising=False)
    assert login.main(["http://127.0.0.1:1", "bacsi1"]) == 1
    assert "DEMO_PASSWORD" in capsys.readouterr().err
