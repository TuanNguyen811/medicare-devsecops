import logging


def test_unhandled_error_is_generic(app, client, caplog):
    @app.get("/_boom")
    def boom():
        raise RuntimeError("secret detail 012345678901")

    with caplog.at_level(logging.ERROR):
        r = client.get("/_boom")
    assert r.status_code == 500
    assert "Đã có lỗi xảy ra" in r.text
    assert "Traceback" not in r.text and "secret detail" not in r.text
    assert "secret detail" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_404_page_generic(client):
    r = client.get("/khong-ton-tai")
    assert r.status_code == 404 and "Traceback" not in r.text


def test_404_api_is_json(client):
    r = client.get("/api/v1/khong-ton-tai")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_notfound_exception_html_and_api(app, client):
    from medicare.common.errors import NotFound

    @app.get("/_nf")
    def nf():
        raise NotFound()

    @app.get("/api/_nf")
    def api_nf():
        raise NotFound()

    assert client.get("/_nf").status_code == 404
    r = client.get("/api/_nf")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_unhandled_error_does_not_propagate_to_server(app, caplog):
    from fastapi.testclient import TestClient

    @app.get("/_boom2")
    def boom():
        raise RuntimeError("secret detail 012345678901")

    @app.get("/api/_boom2")
    def api_boom():
        raise RuntimeError("secret detail 012345678901")

    strict = TestClient(app)  # raise_server_exceptions=True: any re-raise fails the call
    with caplog.at_level(logging.ERROR):
        r = strict.get("/_boom2")
        ra = strict.get("/api/_boom2")
    assert r.status_code == 500 and "Đã có lỗi xảy ra" in r.text
    assert ra.status_code == 500 and ra.json() == {"detail": "Internal Server Error"}
    assert "secret detail" not in caplog.text
