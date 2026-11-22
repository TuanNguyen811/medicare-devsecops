import json

import export_routes


def test_export_lists_login_and_patient_routes(tmp_path):
    openapi, routes = export_routes.export(tmp_path)
    assert "paths" in openapi
    login = [r for r in routes if r["method"] == "POST" and r["path"] == "/login"]
    assert login and login[0]["file"] == "app/medicare/auth/router.py" and login[0]["line"] > 0
    assert any("{" in r["path"] for r in routes)
    assert all(r["method"] != "HEAD" for r in routes)
    saved = json.loads((tmp_path / "routes.json").read_text(encoding="utf-8"))
    assert saved == routes and (tmp_path / "openapi.json").is_file()


def test_split_bundle(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({"openapi": {"paths": {}}, "routes": [{"path": "/x"}]}),
                      encoding="utf-8")
    assert export_routes.main(["--split", str(bundle), str(tmp_path / "o")]) == 0
    assert json.loads((tmp_path / "o" / "routes.json").read_text(encoding="utf-8")) == [
        {"path": "/x"}]
