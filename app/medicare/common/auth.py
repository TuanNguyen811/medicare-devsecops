import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.auth import remember
from medicare.auth.models import Role, User
from medicare.common import metrics
from medicare.common.csrf import rotate_csrf_token
from medicare.common.passwords import hash_password, verify_password
from medicare.db import get_db

MAX_FAILED_LOGINS = 5
LOCK_DURATION = timedelta(minutes=15)

# Verified against when the username is unknown, so response time does not reveal
# whether an account exists. Computed once at import.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


class LoginRequired(Exception):
    """Raised when a request needs an authenticated user; handled in errors.py."""


def _now() -> float:
    return time.time()


def authenticate(
    db: Session, username: str, password: str, now: datetime, *, remembered_device: bool = False
) -> User | None:
    """Check credentials, counting failures toward the lockout (R-07).

    `remembered_device`: the login comes from a browser holding a remember-me token
    (a ward workstation shared by the staff on shift); see medicare.auth.remember for
    how such a browser is recognised.
    """
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
    locked = user.locked_until is not None and user.locked_until > now
    if locked and not remembered_device:
        metrics.login_attempt(metrics.LOGIN_LOCKED)
        return None
    if not password_ok:
        metrics.login_attempt(metrics.LOGIN_FAILURE)
        if not remembered_device:
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


def start_session(request: Request, user: User) -> None:
    """Fresh session after authentication (R-08: no fixation)."""
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["sv"] = user.session_version
    request.session["iat"] = int(_now())
    rotate_csrf_token(request)


def revoke_sessions(user: User) -> None:
    """Invalidate every session issued to `user` so far (cookies are client-side)."""
    user.session_version += 1


def _session_valid(request: Request, user: User | None) -> bool:
    if user is None or not user.is_active:
        return False
    if request.session.get("sv") != user.session_version:
        return False
    issued_at = request.session.get("iat")
    max_age = request.app.state.settings.session_max_age
    # Absolute lifetime: the signed cookie is re-issued on every response, so its
    # max_age alone would only be an idle timeout.
    return isinstance(issued_at, int) and 0 <= _now() - issued_at <= max_age


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if not _session_valid(request, user):
        request.session.clear()
        user = remember.remembered_user(db, request, datetime.now(UTC))
        if user is None:
            raise LoginRequired
        start_session(request, user)
    request.state.current_user = user
    return user


def require_roles(*roles: Role) -> Callable[..., User]:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            metrics.authz_denied("role")
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency
