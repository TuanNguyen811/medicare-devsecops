from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.auth import require_roles
from medicare.common.csrf import verify_csrf
from medicare.common.errors import NotFound
from medicare.common.ids import ObjectId
from medicare.common.templating import flash, render
from medicare.db import get_db
from medicare.department import service
from medicare.department.models import Department

router = APIRouter()

admin_user = require_roles(Role.ADMIN)
_CRUMBS = [("Trang chủ", "/"), ("Khoa", "/admin/departments")]


def _list_page(request: Request, db: Session, *, values=None, errors=None, status_code=200):
    return render(request, "department/list.html", {
        "departments": service.list_departments(db),
        "values": values or {},
        "errors": errors or [],
        "breadcrumbs": [("Trang chủ", "/"), ("Khoa", None)],
    }, status_code=status_code)


def _get_department(db: Session, department_id: int) -> Department:
    department = db.get(Department, department_id)
    if department is None:
        raise NotFound
    return department


@router.get("/admin/departments")
def departments_page(
    request: Request, user: User = Depends(admin_user), db: Session = Depends(get_db)
) -> Response:
    return _list_page(request, db)


@router.post("/admin/departments", dependencies=[Depends(verify_csrf)])
def create_department(
    request: Request,
    code: str = Form(""),
    name: str = Form(""),
    description: str = Form(""),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    try:
        department = service.create(db, code, name, description)
    except service.DepartmentError as exc:
        values = {"code": code, "name": name, "description": description}
        return _list_page(request, db, values=values, errors=[str(exc)], status_code=400)
    db.commit()
    flash(request, f"Đã thêm {department.name}")
    return RedirectResponse("/admin/departments", status_code=303)


def _edit_page(request, department, *, values=None, errors=None, status_code=200):
    return render(request, "department/edit.html", {
        "department": department,
        "values": values or {"name": department.name,
                             "description": department.description or ""},
        "errors": errors or [],
        "breadcrumbs": [*_CRUMBS, (department.code, None)],
    }, status_code=status_code)


@router.get("/admin/departments/{department_id}/edit")
def edit_department_form(
    request: Request,
    department_id: ObjectId,
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    return _edit_page(request, _get_department(db, department_id))


@router.post("/admin/departments/{department_id}/edit", dependencies=[Depends(verify_csrf)])
def edit_department(
    request: Request,
    department_id: ObjectId,
    name: str = Form(""),
    description: str = Form(""),
    user: User = Depends(admin_user),
    db: Session = Depends(get_db),
) -> Response:
    department = _get_department(db, department_id)
    try:
        service.update(db, department, name, description)
    except service.DepartmentError as exc:
        values = {"name": name, "description": description}
        return _edit_page(request, department, values=values, errors=[str(exc)],
                          status_code=400)
    db.commit()
    flash(request, f"Đã cập nhật {department.name}")
    return RedirectResponse("/admin/departments", status_code=303)
