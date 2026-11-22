import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common import metrics
from medicare.common.csrf import rotate_csrf_token
from medicare.common.passwords import hash_password, verify_password
from medicare.db import get_db

logger = logging.getLogger("medicare.auth")

MAX_FAILED_LOGINS = 5
LOCK_DURATION = timedelta(minutes=15)

# Absolute session lifetime by shift. "hc" (office hours) uses SESSION_MAX_AGE; staff on
# 12-hour shifts or 24-hour duty choose a longer one at login so they are not signed out
# in the middle of a shift.
SHIFT_MAX_AGE = {"hc": None, "12h": 12 * 3600, "24h": 24 * 3600}
DEFAULT_SHIFT = "hc"

# Verified against when the username is unknown, so response time does not reveal
# whether an account exists. Computed once at import.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


class LoginRequired(Exception):
    """Raised when a request needs an authenticated user; handled in errors.py."""


def _now() -> float:
    return time.time()


def authenticate(db: Session, username: str, password: str, now: datetime) -> User | None:
    # Row lock: concurrent failed guesses must each count toward the lockout (R-07).
    # OF users: the joined department is the nullable side of an outer join.
    user = db.scalar(
        select(User).where(User.username == username).with_for_update(of=User)
    )
    if user is None:
        verify_password(_DUMMY_HASH, password)
        metrics.login_attempt(metrics.LOGIN_FAILURE)
        return None
    password_ok = verify_password(user.password_hash, password)
    if not user.is_active:
        metrics.login_attempt(metrics.LOGIN_FAILURE)
        return None
    if user.locked_until is not None and user.locked_until > now:
        metrics.login_attempt(metrics.LOGIN_LOCKED)
        return None
    if not password_ok:
        metrics.login_attempt(metrics.LOGIN_FAILURE)
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = now + LOCK_DURATION
            user.failed_login_count = 0
            metrics.account_locked()
        db.flush()
        return None
    user.failed_login_count = 0
    user.locked_until = None
    db.flush()
    metrics.login_attempt(metrics.LOGIN_SUCCESS)
    return user


def start_session(request: Request, user: User, shift: str = DEFAULT_SHIFT) -> None:
    """Fresh session after authentication (R-08: no fixation)."""
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["sv"] = user.session_version
    request.session["iat"] = int(_now())
    request.session["shift"] = shift if user.role != Role.PATIENT else DEFAULT_SHIFT
    rotate_csrf_token(request)


def revoke_sessions(user: User) -> None:
    """Invalidate every session issued to `user` so far (cookies are client-side)."""
    user.session_version += 1


def _max_age(request: Request) -> int:
    shift_age = SHIFT_MAX_AGE[request.session.get("shift", DEFAULT_SHIFT)]
    return shift_age or request.app.state.settings.session_max_age


def _session_user(request: Request, db: Session) -> User | None:
    """The session's user, or None when the session can no longer be used.

    The cookie is checked first, so expired sessions never cost a database query.
    """
    user_id = request.session.get("user_id")
    issued_at = request.session.get("iat")
    if not isinstance(user_id, int) or not isinstance(issued_at, int):
        return None
    # Absolute lifetime: the signed cookie is re-issued on every response, so its
    # max_age alone would only be an idle timeout.
    if not 0 <= _now() - issued_at <= _max_age(request):
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or request.session.get("sv") != user.session_version:
        return None
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    try:
        user = _session_user(request, db)
    except Exception as exc:  # noqa: BLE001
        # A fault in the check itself must not sign staff out in the middle of a shift:
        # keep the session's user and let the next request check again.
        logger.warning("Session check failed: %s", type(exc).__name__)
        user_id = request.session.get("user_id")
        user = db.get(User, user_id) if isinstance(user_id, int) else None
    if user is None:
        request.session.clear()
        raise LoginRequired
    request.state.current_user = user
    return user


def require_roles(*roles: Role) -> Callable[..., User]:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            metrics.authz_denied("role")
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency
