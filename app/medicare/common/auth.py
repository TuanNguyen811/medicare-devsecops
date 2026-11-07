from collections.abc import Callable
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.passwords import hash_password, verify_password
from medicare.db import get_db

MAX_FAILED_LOGINS = 5
LOCK_DURATION = timedelta(minutes=15)

# Verified against when the username is unknown, so response time does not reveal
# whether an account exists. Computed once at import.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


class LoginRequired(Exception):
    """Raised when a request needs an authenticated user; handled in errors.py."""


def authenticate(db: Session, username: str, password: str, now: datetime) -> User | None:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        verify_password(_DUMMY_HASH, password)
        return None
    password_ok = verify_password(user.password_hash, password)
    if not user.is_active or (user.locked_until is not None and user.locked_until > now):
        return None
    if not password_ok:
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = now + LOCK_DURATION
            user.failed_login_count = 0
        db.flush()
        return None
    user.failed_login_count = 0
    user.locked_until = None
    db.flush()
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if user is None or not user.is_active:
        request.session.clear()
        raise LoginRequired
    request.state.current_user = user
    return user


def require_roles(*roles: Role) -> Callable[..., User]:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return dependency
