"""Remember-me: a long-lived random token in its own cookie restores the session.

The token is 256 random bits; the database keeps only its SHA-256, so a leaked table
cannot be replayed.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from medicare.auth.models import RememberToken, User

COOKIE = "medicare_remember"
REMEMBER_FOR = timedelta(days=30)
_MAX_TOKEN_LENGTH = 64


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue(db: Session, user: User, now: datetime) -> str:
    raw = secrets.token_urlsafe(32)
    db.add(RememberToken(user_id=user.id, token_hash=_digest(raw), expires_at=now + REMEMBER_FOR))
    db.flush()
    return raw


def set_cookie(request: Request, response: Response, raw: str) -> None:
    response.set_cookie(
        COOKIE,
        raw,
        max_age=int(REMEMBER_FOR.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=request.app.state.settings.env == "production",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE)


def _valid_token(db: Session, request: Request, now: datetime) -> RememberToken | None:
    raw = request.cookies.get(COOKIE)
    if not raw or len(raw) > _MAX_TOKEN_LENGTH:
        return None
    token = db.scalar(select(RememberToken).where(RememberToken.token_hash == _digest(raw)))
    if token is None or token.expires_at <= now:
        return None
    return token


def remembered_user(db: Session, request: Request, now: datetime) -> User | None:
    """The active user this browser was remembered for, if its token is still valid."""
    token = _valid_token(db, request, now)
    if token is None:
        return None
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        return None
    return user


def is_remembered_device(db: Session, request: Request, now: datetime) -> bool:
    return _valid_token(db, request, now) is not None


def revoke_all(db: Session, user: User) -> None:
    db.execute(delete(RememberToken).where(RememberToken.user_id == user.id))
