"""Export the app's OpenAPI document and a route → handler map for DAST (spec addendum 5.1).

The live app keeps /openapi.json disabled; this builds the same schema in-process instead.
Run with the app's environment (inside the app container in CI):

    python export_routes.py <out_dir>          # writes openapi.json and routes.json
    python - --stdout < export_routes.py       # prints {"openapi": ..., "routes": [...]}
    python export_routes.py --split <bundle.json> <out_dir>   # no app import needed
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path


def _api_routes(app) -> list:
    """(path, methods, endpoint) of every API route, including those of included routers.

    FastAPI >= 0.16x keeps included routers as nested entries of app.routes; its public
    iter_route_contexts flattens them. Older versions flatten app.routes themselves.
    """
    from fastapi import routing

    if hasattr(routing, "iter_route_contexts"):
        contexts = routing.iter_route_contexts(app.router.routes)
        return [(c.path, c.methods, c.endpoint) for c in contexts
                if isinstance(c.original_route, routing.APIRoute)]
    return [(r.path, r.methods, r.endpoint) for r in app.routes
            if isinstance(r, routing.APIRoute)]


def collect() -> tuple[dict, list[dict]]:
    import medicare
    from medicare.main import create_app

    app = create_app()
    package_parent = Path(medicare.__file__).resolve().parent.parent
    routes = []
    for path, methods, endpoint in _api_routes(app):
        func = inspect.unwrap(endpoint)
        source = Path(inspect.getsourcefile(func) or "").resolve()
        try:
            rel = "app/" + source.relative_to(package_parent).as_posix()
        except ValueError:
            rel = ""
        line = inspect.getsourcelines(func)[1] if rel else 0
        for method in sorted(set(methods or ()) - {"HEAD"}):
            routes.append({"method": method, "path": path, "function": func.__name__,
                           "file": rel, "line": line})
    return app.openapi(), routes


def write(out_dir: Path, openapi: dict, routes: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "openapi.json").write_text(json.dumps(openapi, indent=2, ensure_ascii=False),
                                          encoding="utf-8", newline="")
    (out_dir / "routes.json").write_text(json.dumps(routes, indent=2, ensure_ascii=False),
                                         encoding="utf-8", newline="")


def export(out_dir: Path) -> tuple[dict, list[dict]]:
    openapi, routes = collect()
    write(out_dir, openapi, routes)
    return openapi, routes


def main(argv: list[str]) -> int:
    if argv[:1] == ["--stdout"]:
        openapi, routes = collect()
        sys.stdout.write(json.dumps({"openapi": openapi, "routes": routes}, ensure_ascii=False))
        return 0
    if argv[:1] == ["--split"] and len(argv) == 3:
        bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        write(Path(argv[2]), bundle["openapi"], bundle["routes"])
        return 0
    if len(argv) == 1:
        export(Path(argv[0]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
