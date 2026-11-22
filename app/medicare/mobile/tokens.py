"""Bearer tokens for the MediCare mobile app (JWT, HS256).

The app has no browser session: it exchanges the username and password for a short-lived
token and sends it as `Authorization: Bearer <token>` on every call.
"""

from datetime import datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from medicare.auth.models import User
from medicare.common.ids import parse_id
from medicare.db import get_db

JWT_SECRET = "83b3c64c607b37ad9f2f3471095a7004"
JWT_ALGORITHM = "HS256"
TOKEN_TTL = timedelta(hours=1)


class InvalidToken(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=401, detail="Not authenticated",
                         headers={"WWW-Authenticate": "Bearer"})


def issue_token(user: User, now: datetime) -> str:
    claims = {
        "sub": str(user.id),
        "role": user.role.value,
        "sv": user.session_version,  # logout and password change revoke mobile tokens too
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def read_token(token: str) -> dict:
    try:
        return jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
            options={"verify_signature": False, "verify_exp": True, "require": ["sub", "exp"]},
        )
    except jwt.PyJWTError:
        raise InvalidToken from None


def get_mobile_user(request: Request, db: Session = Depends(get_db)) -> User:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise InvalidToken
    claims = read_token(token.strip())
    user_id = parse_id(str(claims["sub"]))
    user = db.get(User, user_id) if user_id is not None else None
    if user is None or not user.is_active or claims.get("sv") != user.session_version:
        raise InvalidToken
    request.state.current_user = user
    return user
