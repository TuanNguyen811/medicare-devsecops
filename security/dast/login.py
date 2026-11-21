"""Log in as one demo account and print the session cookie and CSRF token for ZAP.

    DEMO_PASSWORD=... python3 login.py http://app:8000 bacsi1

Prints exactly two lines: ZAP_COOKIE=medicare_session=<...> and ZAP_CSRF=<token>. The password
is read from the environment and never printed. Exit 1 if the login fails.
Standard library only: runs inside the ZAP container (python3).
"""

from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie

COOKIE = "medicare_session"
_FORM_TOKEN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')
_META_TOKEN = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
TIMEOUT_S = 20


class LoginError(Exception):
    pass


def extract_csrf(html: str) -> str | None:
    match = _META_TOKEN.search(html) or _FORM_TOKEN.search(html)
    return match.group(1) if match else None


def session_cookie(headers) -> str | None:
    """The medicare_session value from the Set-Cookie headers of a response, if any."""
    for raw in headers.get_all("Set-Cookie") or []:
        jar = SimpleCookie()
        jar.load(raw)
        if COOKIE in jar and jar[COOKIE].value:
            return jar[COOKIE].value
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _request(url: str, cookie: str | None, data: dict | None = None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
    if cookie:
        req.add_header("Cookie", f"{COOKIE}={cookie}")
    try:
        resp = _opener.open(req, timeout=TIMEOUT_S)
    except urllib.error.HTTPError as exc:  # 3xx without redirect handling, or an error status
        resp = exc
    return resp.status, resp.headers, resp.read().decode("utf-8", errors="replace")


def login(base: str, username: str, password: str) -> tuple[str, str]:
    base = base.rstrip("/")
    status, headers, html = _request(f"{base}/login", None)
    cookie, token = session_cookie(headers), extract_csrf(html)
    if status != 200 or not cookie or not token:
        raise LoginError(f"GET /login: status {status}, cookie={bool(cookie)}, csrf={bool(token)}")
    status, headers, _ = _request(f"{base}/login", cookie,
                                  {"username": username, "password": password,
                                   "csrf_token": token})
    cookie = session_cookie(headers)
    if status != 303 or not cookie:
        raise LoginError(f"POST /login for {username}: status {status} (wrong password or locked)")
    status, headers, html = _request(f"{base}/", cookie)
    cookie = session_cookie(headers) or cookie
    token = extract_csrf(html)
    if status != 200 or not token:
        raise LoginError(f"GET / after login: status {status}, csrf={bool(token)}")
    return cookie, token


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    password = os.environ.get("DEMO_PASSWORD", "")
    if not password:
        print("login.py: DEMO_PASSWORD is not set", file=sys.stderr)
        return 1
    try:
        cookie, token = login(argv[0], argv[1], password)
    except (LoginError, OSError) as exc:
        print(f"login.py: {exc}", file=sys.stderr)
        return 1
    print(f"ZAP_COOKIE={COOKIE}={cookie}")
    print(f"ZAP_CSRF={token}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
