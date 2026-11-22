import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from medicare.department.models import Department

MAX_NAME = 100
MAX_DESCRIPTION = 500
_CODE = re.compile(r"[A-Z0-9_]{2,20}")


class DepartmentError(ValueError):
    """Invalid department data; the message is user-facing."""


def list_departments(db: Session) -> list[Department]:
    return list(db.scalars(select(Department).order_by(Department.name)))


def _clean(db: Session, name: str, description: str, *, exclude_id: int | None = None):
    name, description = name.strip(), description.strip()
    if not 1 <= len(name) <= MAX_NAME:
        raise DepartmentError(f"Tên khoa: bắt buộc, tối đa {MAX_NAME} ký tự")
    if len(description) > MAX_DESCRIPTION:
        raise DepartmentError(f"Mô tả: tối đa {MAX_DESCRIPTION} ký tự")
    same_name = select(Department.id).where(func.lower(Department.name) == name.lower())
    if exclude_id is not None:
        same_name = same_name.where(Department.id != exclude_id)
    if db.scalar(same_name) is not None:
        raise DepartmentError("Tên khoa đã tồn tại")
    return name, description or None


def create(db: Session, code: str, name: str, description: str) -> Department:
    code = code.strip().upper()
    if not (_CODE.fullmatch(code) and code.isascii()):
        raise DepartmentError("Mã khoa: 2-20 ký tự A-Z, 0-9 hoặc gạch dưới")
    if db.scalar(select(Department.id).where(Department.code == code)) is not None:
        raise DepartmentError("Mã khoa đã tồn tại")
    name, description = _clean(db, name, description)
    department = Department(code=code, name=name, description=description)
    db.add(department)
    db.flush()
    return department


def update(db: Session, department: Department, name: str, description: str) -> None:
    department.name, department.description = _clean(
        db, name, description, exclude_id=department.id
    )
    db.flush()
