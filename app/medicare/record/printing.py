"""Printed examination slip ("phiếu khám") with a layout each doctor can customize."""

from datetime import date

from jinja2 import Environment, TemplateSyntaxError
from sqlalchemy.orm import Session

from medicare.auth.models import Role, User
from medicare.common.templating import date_vn
from medicare.patient.models import Patient
from medicare.record.models import MedicalRecord, SlipTemplate

MAX_TEMPLATE_LENGTH = 20_000
GENDERS = {"M": "Nam", "F": "Nữ"}

DEFAULT_TEMPLATE = """\
<h2 style="text-align:center">PHIẾU KHÁM BỆNH</h2>
<p style="text-align:center">Số: {{ record.id }}</p>
<p>Họ tên người bệnh: <b>{{ patient.full_name }}</b> - Mã BN: {{ patient.code }}</p>
<p>Ngày sinh: {{ patient.date_of_birth }} - Giới tính: {{ patient.gender }}</p>
<p>Khoa: {{ patient.department }}</p>
<p>Ngày khám: {{ record.visit_date }}</p>
<p>Triệu chứng: {{ record.symptoms }}</p>
<p>Chẩn đoán: {{ record.diagnosis_code }} - {{ record.diagnosis_text }}</p>
<p>Lời dặn: {{ record.notes }}</p>
<p style="text-align:right">Ngày {{ today }}<br>Bác sĩ khám bệnh<br><br><br>
{{ doctor.full_name }}</p>
"""

# Variables a slip template can use (shown on the settings page).
VARIABLES = {
    "patient": ("code", "full_name", "date_of_birth", "gender", "department"),
    "record": ("id", "visit_date", "symptoms", "diagnosis_code", "diagnosis_text", "notes"),
    "doctor": ("full_name",),
    "today": (),
}

_env = Environment(autoescape=True)


class SlipTemplateError(ValueError):
    """Template rejected on save; the message is user-facing."""


def validate(body: str) -> None:
    if len(body) > MAX_TEMPLATE_LENGTH:
        raise SlipTemplateError(f"Mẫu in tối đa {MAX_TEMPLATE_LENGTH} ký tự")
    try:
        _env.parse(body)
    except TemplateSyntaxError as exc:
        raise SlipTemplateError(f"Mẫu in sai cú pháp ở dòng {exc.lineno}") from exc


def get_custom(db: Session, user: User) -> SlipTemplate | None:
    return db.get(SlipTemplate, user.id) if user.role == Role.DOCTOR else None


def save_custom(db: Session, user: User, body: str) -> None:
    """Store the doctor's own template; an empty body goes back to the default."""
    current = db.get(SlipTemplate, user.id)
    if not body.strip():
        if current is not None:
            db.delete(current)
    elif current is None:
        db.add(SlipTemplate(doctor_id=user.id, body=body))
    else:
        current.body = body
    db.flush()


def _context(record: MedicalRecord, patient: Patient) -> dict:
    # Plain values only: CCCD and BHYT numbers never reach a slip (R-11).
    return {
        "patient": {
            "code": patient.code,
            "full_name": patient.full_name,
            "date_of_birth": date_vn(patient.date_of_birth),
            "gender": GENDERS.get(patient.gender, ""),
            "department": patient.department.name if patient.department else "",
        },
        "record": {
            "id": record.id,
            "visit_date": date_vn(record.visit_date),
            "symptoms": record.symptoms,
            "diagnosis_code": record.diagnosis_code,
            "diagnosis_text": record.diagnosis_text,
            "notes": record.notes,
        },
        "doctor": {"full_name": record.doctor.full_name},
        "today": date_vn(date.today()),
    }


def render_slip(db: Session, user: User, record: MedicalRecord, patient: Patient) -> str:
    custom = get_custom(db, user)
    body = custom.body if custom is not None else DEFAULT_TEMPLATE
    return _env.from_string(body).render(_context(record, patient))
