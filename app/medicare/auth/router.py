from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth import reset
from medicare.auth.models import User
from medicare.common import metrics
from medicare.common.auth import (
    authenticate,
    get_current_user,
    revoke_sessions,
    start_session,
)
from medicare.common.csrf import verify_csrf
from medicare.common.passwords import hash_password, verify_password
from medicare.common.templating import flash, render
from medicare.db import get_db

router = APIRouter()

LOGIN_ERROR = "Tên đăng nhập hoặc mật khẩu không đúng"
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128  # bounds the work argon2 does on attacker-supplied input
MAX_EMAIL_LENGTH = 254


@router.get("/login")
def login_form(request: Request) -> Response:
    return render(request, "login.html", {})


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    user = None
    if (len(username) <= 50 and len(password) <= MAX_PASSWORD_LENGTH
            and "\x00" not in username and "\x00" not in password):
        user = authenticate(db, username, password, datetime.now(UTC))
    else:
        metrics.login_attempt(metrics.LOGIN_FAILURE)
    db.commit()  # persists the failed-attempt counter and lock
    if user is None:
        return render(request, "login.html", {"error": LOGIN_ERROR})
    start_session(request, user)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if user is not None and request.session.get("sv") == user.session_version:
        revoke_sessions(user)  # a copied cookie must not outlive the logout
        db.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/")
def home(request: Request, user: User = Depends(get_current_user)) -> Response:
    return render(request, "home.html", {"breadcrumbs": []})


@router.get("/account/password")
def password_form(request: Request, user: User = Depends(get_current_user)) -> Response:
    return render(request, "password.html", _password_ctx())


@router.post("/account/password", dependencies=[Depends(verify_csrf)])
def change_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    error = None
    if len(current_password) > MAX_PASSWORD_LENGTH or not verify_password(
        user.password_hash, current_password
    ):
        error = "Mật khẩu hiện tại không đúng"
    elif len(new_password) < MIN_PASSWORD_LENGTH:
        error = f"Mật khẩu mới phải có ít nhất {MIN_PASSWORD_LENGTH} ký tự"
    elif len(new_password) > MAX_PASSWORD_LENGTH:
        error = f"Mật khẩu mới không được dài quá {MAX_PASSWORD_LENGTH} ký tự"
    elif new_password != confirm_password:
        error = "Mật khẩu xác nhận không khớp"
    elif new_password == current_password:
        error = "Mật khẩu mới phải khác mật khẩu hiện tại"
    if error:
        return render(request, "password.html", _password_ctx() | {"error": error})
    user.password_hash = hash_password(new_password)
    revoke_sessions(user)  # sign out every other device
    db.commit()
    request.session["sv"] = user.session_version  # keep this session alive
    flash(request, "Đã đổi mật khẩu")
    return RedirectResponse("/", status_code=303)


def _password_ctx() -> dict:
    return {"breadcrumbs": [("Trang chủ", "/"), ("Đổi mật khẩu", None)]}


@router.get("/forgot-password")
def forgot_password_form(request: Request) -> Response:
    return render(request, "forgot_password.html", {})


@router.post("/forgot-password", dependencies=[Depends(verify_csrf)])
def forgot_password(
    request: Request,
    email: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    email = email.strip().lower()
    base_url = request.app.state.settings.public_base_url
    if len(email) > MAX_EMAIL_LENGTH or not reset.request_reset(db, email, base_url):
        return render(request, "forgot_password.html", {
            "email": email, "error": "Không tìm thấy tài khoản nào đăng ký với email này",
        })
    db.commit()
    flash(request, "Đã gửi liên kết đặt lại mật khẩu tới email của bạn")
    return RedirectResponse("/login", status_code=303)


@router.get("/reset-password")
def reset_password_form(
    request: Request, token: str = "", db: Session = Depends(get_db)
) -> Response:
    if reset.user_for_token(db, token) is None:
        return render(request, "reset_password.html", {"invalid": True}, status_code=400)
    return render(request, "reset_password.html", {"token": token})


@router.post("/reset-password", dependencies=[Depends(verify_csrf)])
def reset_password(
    request: Request,
    token: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    user = reset.user_for_token(db, token)
    if user is None:
        return render(request, "reset_password.html", {"invalid": True}, status_code=400)
    error = _new_password_error(new_password, confirm_password)
    if error:
        return render(request, "reset_password.html", {"token": token, "error": error})
    reset.reset_password(user, new_password)
    db.commit()
    flash(request, "Đã đặt lại mật khẩu. Vui lòng đăng nhập bằng mật khẩu mới")
    return RedirectResponse("/login", status_code=303)


def _new_password_error(new_password: str, confirm_password: str) -> str | None:
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return f"Mật khẩu mới phải có ít nhất {MIN_PASSWORD_LENGTH} ký tự"
    if len(new_password) > MAX_PASSWORD_LENGTH:
        return f"Mật khẩu mới không được dài quá {MAX_PASSWORD_LENGTH} ký tự"
    if new_password != confirm_password:
        return "Mật khẩu xác nhận không khớp"
    return None
