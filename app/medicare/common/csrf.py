import hmac
import secrets

from fastapi import HTTPException, Request

_SESSION_KEY = "csrf_token"


def get_csrf_token(request: Request) -> str:
    """Return the session's CSRF token, creating it on first use."""
    token = request.session.get(_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[_SESSION_KEY] = token
    return token


def rotate_csrf_token(request: Request) -> str:
    token = secrets.token_urlsafe(32)
    request.session[_SESSION_KEY] = token
    return token


async def verify_csrf(request: Request) -> None:
    """Dependency for every POST route: form field `csrf_token` or header `X-CSRF-Token`."""
    expected = request.session.get(_SESSION_KEY)
    supplied = request.headers.get("X-CSRF-Token")
    if supplied is None:
        form = await request.form()
        value = form.get("csrf_token")
        supplied = value if isinstance(value, str) else None
    if not expected or not supplied or not hmac.compare_digest(
        expected.encode(), supplied.encode()
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
