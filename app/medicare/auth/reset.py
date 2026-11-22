"""Self-service password reset by mail (R-18)."""

import hashlib
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare.auth.models import PasswordResetToken, User
from medicare.common.auth import revoke_sessions
from medicare.common.mailer import send_mail
from medicare.common.passwords import hash_password

RESET_TOKEN_TTL = timedelta(minutes=15)
TOKEN_BYTES = 32  # 256 bits
MAX_TOKEN_LENGTH = 64
SUBJECT = "Đặt lại mật khẩu MediCare"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def request_reset(db: Session, email: str, base_url: str) -> bool:
    """Mail a reset link to the active account registered with `email`.

    Returns False when no such account exists.
    """
    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    if user is None:
        return False
    token = secrets.token_urlsafe(TOKEN_BYTES)
    db.add(PasswordResetToken(user_id=user.id, token_hash=_digest(token)))
    db.flush()
    link = f"{base_url.rstrip('/')}/reset-password?token={token}"
    minutes = int(RESET_TOKEN_TTL.total_seconds() // 60)
    send_mail(user.email, SUBJECT, (
        f"Xin chào {user.full_name},\n\n"
        "Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.\n"
        f"Mở liên kết sau để đặt mật khẩu mới: {link}\n"
        f"Liên kết có hiệu lực trong {minutes} phút. Nếu bạn không yêu cầu, hãy bỏ qua email này.\n"
    ))
    return True


def user_for_token(db: Session, token: str) -> User | None:
    """The account a reset link belongs to, or None if the link is not valid."""
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    reset = db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == _digest(token))
    )
    if reset is None:
        return None
    user = db.get(User, reset.user_id)
    return user if user is not None and user.is_active else None


def reset_password(user: User, new_password: str) -> None:
    user.password_hash = hash_password(new_password)
    revoke_sessions(user)  # every session opened with the old password ends (R-08, R-18)
