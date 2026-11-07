from fakes import REPO_ROOT, miniapp_repo, write_files

from secagent.tools.fs import RepoFS
from secagent.tools.pyast import find_callers, format_routes, get_function, list_routes

ROUTER = "app/medicare/demo/router.py"
SERVICE = "app/medicare/demo/service.py"


def test_list_routes_miniapp(tmp_path):
    routes = list_routes(RepoFS(miniapp_repo(tmp_path)))
    assert [(r.method, r.path, r.function, r.file, r.line, r.dependencies) for r in routes] == [
        ("GET", "/items/{item_id}", "item_detail", ROUTER, 12, ["get_current_user"]),
        ("POST", "/items", "create_item", ROUTER, 17,
         ["verify_csrf", "require_roles(Role.DOCTOR)"]),
        ("GET", "/items/{item_id}/export", "export", ROUTER, 22, ["get_current_user"]),
    ]
    assert routes[0].params == ["item_id: int", "user: User"]
    text = format_routes(routes)
    assert "POST /items → create_item" in text and "require_roles(Role.DOCTOR)" in text


def test_list_routes_skips_unparsable_files(tmp_path):
    repo = miniapp_repo(tmp_path)
    write_files(repo, {"app/medicare/broken/router.py": "def oops(:\n"})
    assert len(list_routes(RepoFS(repo))) == 3


def test_list_routes_real_app_contract_1():
    routes = list_routes(RepoFS(REPO_ROOT), glob="app/medicare/*router*.py")
    detail = next(r for r in routes if r.method == "GET" and r.path == "/patients/{patient_id}")
    assert detail.function == "patient_detail"
    assert "get_current_user" in detail.dependencies and detail.file.startswith("app/medicare/")


def test_get_function_and_find_callers(tmp_path):
    fs = RepoFS(miniapp_repo(tmp_path))
    create = get_function(fs, ROUTER, "create_item")
    assert '@router.post("/items", dependencies=[Depends(verify_csrf)])' in create
    assert "def create_item" in create and "item_detail" not in create
    assert "def run(self, data: dict) -> str:" in get_function(fs, SERVICE, "Exporter.run")
    assert get_function(fs, SERVICE, "nope").startswith("ERROR")
    callers = find_callers(fs, "load_item")
    assert callers.count("router.py:") == 2 and "service.load_item(item_id)" in callers
    exports = find_callers(fs, "export_item")
    assert "router.py:24:" in exports and "service.py:11:" in exports
    assert find_callers(fs, "never_called") == "(không tìm thấy lời gọi nào)"
