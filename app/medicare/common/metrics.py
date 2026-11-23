"""Prometheus metrics (spec 7.1), served on a separate port, never on the app port.

Labels never carry PII (R-10): routes are path templates, user ids are internal numbers.
"""

import threading
import time
from typing import TYPE_CHECKING
from wsgiref.simple_server import WSGIServer

from prometheus_client import Counter, Histogram, start_http_server
from starlette.types import ASGIApp, Message, Receive, Scope, Send

if TYPE_CHECKING:  # runtime import would cycle through medicare.common.auth
    from medicare.auth.models import User

HTTP_REQUESTS = Counter(
    "medicare_http_requests_total", "HTTP requests by route template", ["method", "route", "status"]
)
HTTP_DURATION = Histogram(
    "medicare_http_request_duration_seconds", "HTTP request latency by route template", ["route"]
)
LOGINS = Counter("medicare_login_total", "Login attempts by outcome", ["result"])
LOCKOUTS = Counter("medicare_account_lockouts_total", "Accounts locked after repeated failures")
RECORD_ACCESS = Counter(
    "medicare_record_access_total",
    "Audited accesses to clinical data",
    ["action", "role", "user_id"],
)
AUTHZ_DENIED = Counter(
    "medicare_authz_denied_total",
    "Requests for an existing object the user may not access",
    ["resource"],
)

LOGIN_SUCCESS = "success"
LOGIN_FAILURE = "failure"
LOGIN_LOCKED = "locked"
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
AUTHZ_RESOURCES = ("patient", "record", "prescription", "appointment", "invoice", "role")

# Export every known series at 0 from the start: increase() over a series that appears
# mid-window misses its first increments, which would blunt the brute-force and IDOR alerts.
for _result in (LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_LOCKED):
    LOGINS.labels(result=_result)
for _resource in AUTHZ_RESOURCES:
    AUTHZ_DENIED.labels(resource=_resource)


def login_attempt(result: str) -> None:
    LOGINS.labels(result=result).inc()


def account_locked() -> None:
    LOCKOUTS.inc()


def record_access(actor: "User", action: str) -> None:
    RECORD_ACCESS.labels(action=action, role=actor.role.value, user_id=str(actor.id)).inc()


def authz_denied(resource: str) -> None:
    """An existing object, or a role-restricted route, the user may not access.

    Missing objects are not counted: only refusals of things that exist signal probing.
    """
    AUTHZ_DENIED.labels(resource=resource).inc()


def _route_label(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str):
        return path
    if scope.get("path", "").startswith("/static/"):
        return "/static"
    return "unmatched"  # never the raw URL: unbounded label values


class MetricsMiddleware:
    """Outermost middleware: counts every HTTP response by method, route template and status."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        status = 500
        start = time.perf_counter()

        async def tracking_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        finally:
            route = _route_label(scope)
            method = scope["method"] if scope["method"] in HTTP_METHODS else "OTHER"
            HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
            HTTP_DURATION.labels(route=route).observe(time.perf_counter() - start)


def start_metrics_server(host: str, port: int) -> tuple[WSGIServer, threading.Thread]:
    """Serve /metrics from a daemon thread (uvicorn runs a single worker)."""
    return start_http_server(port, addr=host)
