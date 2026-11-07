import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.auth import require_roles, revoke_sessions
from medicare.common.csrf import verify_csrf
from medicare.common.errors import NotFound
from medicare.common.ids import ObjectId, parse_id
from medicare.common.passwords import hash_password
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.department.models import Department
from medicare.patient.models import Patient

router = APIRouter()

admin_user = require_roles(Role.ADMIN)

_USERNAME = re.compile(r"[a-z0-9_.]{3,50}")
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128


class AccountError(ValueError):
    """Invalid account data; the message is user-facing."""



def _new_account(db: Session, username, full_name, role, department_id, patient_id,
                 password) -> User:
    username, full_name = username.strip(), full_name.strip()
    if not (_USERNAME.fullmatch(username) and username.isascii()):
        raise AccountError("Tên đăng nhập: 3-50 ký tự a-z, 0-9, dấu chấm hoặc gạch dưới")
    if not 1 <= len(full_name) <= 100:
        raise AccountError("Họ tên: bắt buộc, tối đa 100 ký tự")
    if role not in Role.__members__:
        raise AccountError("Vai trò: giá trị không hợp lệ")
    role = Role(role)
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise AccountError(f"Mật khẩu: từ {MIN_PASSWORD_LENGTH} đến {MAX_PASSWORD_LENGTH} ký tự")
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise AccountError("Tên đăng nhập đã tồn tại")
    dept_id = pat_id = None
    if role in (Role.DOCTOR, Role.NURSE):
        dept_id = parse_id(department_id)
        if dept_id is None or db.get(Department, dept_id) is None:
            raise AccountError("Bác sĩ và điều dưỡng phải thuộc một khoa")
    if role == Role.PATIENT:
        pat_id = parse_id(patient_id)
        if pat_id is None or db.get(Patient, pat_id) is None:
            raise AccountError("Tài khoản bệnh nhân phải gắn với một hồ sơ bệnh nhân")
        if db.scalar(select(User.id).where(User.patient_id == pat_id)) is not None:
            raise AccountError("Hồ sơ bệnh nhân này đã có tài khoản")
    user = User(username=username, full_name=full_name, role=role, department_id=dept_id,
                patient_id=pat_id, password_hash=hash_password(password))
    try:
        with db.begin_nested():
            db.add(user)
            db.flush()
    except IntegrityError as exc:  # concurrent creation of the same username / link
        raise AccountError("Tên đăng nhập hoặc hồ sơ bệnh nhân đã được dùng") from exc
    return user


def _users_page(request: Request, db: Session, *, values=None, errors=None, status_code=200):
    users = db.scalars(select(User).order_by(User.role, User.username)).unique().all()
    patient_codes = dict(db.execute(select(Patient.id, Patient.code)).all())
    return render(request, "admin/users.html", {
        "users": users,
        "patient_codes": patient_codes,
        "departments": db.scalars(select(Department).order_by(Department.name)).all(),
        "roles": list(Role),
        "values": values or {},
        "errors": errors or [],
        "breadcrumbs": [("Trang chủ", "/"), ("Tài khoản", None)],
    }, status_code=status_code)


@router.get("/admin/users")
def users_page(
    request: Request, user: User = Depends(admin_user), db: Session = Depends(get_db)
) -> Response:
    return _users_page(request, db)


@router.post("/admin/users", dependencies=[Depends(verify_csrf)])
def create_user(
    request: Request,
    username: str = Form(""),
    full_name: str = Form(""),
    role: str = Form(""),
    department_id: str = Form(""),
    patient_id: str = Form(""),
    password: str = Form(""),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    try:
        created = _new_account(db, username, full_name, role, department_id, patient_id,
                               password)
    except AccountError as exc:
        values = {"username": username, "full_name": full_name, "role": role,
                  "department_id": department_id, "patient_id": patient_id}
        return _users_page(request, db, values=values, errors=[str(exc)], status_code=400)
    db.commit()
    flash(request, f"Đã tạo tài khoản {created.username}")
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/deactivate", dependencies=[Depends(verify_csrf)])
def deactivate_user(
    request: Request,
    user_id: ObjectId,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    target = db.get(User, user_id)
    if target is None:
        raise NotFound
    if target.id == user.id:
        return _users_page(request, db, errors=["Không thể tự vô hiệu hóa tài khoản của mình"],
                           status_code=400)
    target.is_active = False
    revoke_sessions(target)
    db.commit()
    flash(request, f"Đã vô hiệu hóa tài khoản {target.username}")
    return RedirectResponse("/admin/users", status_code=303)
