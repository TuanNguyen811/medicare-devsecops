from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import User
from medicare.common.auth import authenticate, get_current_user
from medicare.common.csrf import rotate_csrf_token, verify_csrf
from medicare.common.passwords import hash_password, verify_password
from medicare.common.templating import flash, render
from medicare.db import get_db

router = APIRouter()

LOGIN_ERROR = "Tên đăng nhập hoặc mật khẩu không đúng"
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128  # bounds the work argon2 does on attacker-supplied input


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
    if len(username) <= 50 and len(password) <= MAX_PASSWORD_LENGTH:
        user = authenticate(db, username, password, datetime.now(UTC))
    db.commit()  # persists the failed-attempt counter and lock
    if user is None:
        return render(request, "login.html", {"error": LOGIN_ERROR})
    request.session.clear()
    request.session["user_id"] = user.id
    rotate_csrf_token(request)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request) -> Response:
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
    db.commit()
    flash(request, "Đã đổi mật khẩu")
    return RedirectResponse("/", status_code=303)


def _password_ctx() -> dict:
    return {"breadcrumbs": [("Trang chủ", "/"), ("Đổi mật khẩu", None)]}
