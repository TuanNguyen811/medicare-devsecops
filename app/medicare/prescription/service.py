from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare import policy
from medicare.audit import service as audit
from medicare.auth.models import User
from medicare.common import metrics
from medicare.common.errors import NotFound
from medicare.patient.models import Patient
from medicare.prescription.models import Medicine, Prescription, PrescriptionItem
from medicare.record.models import MedicalRecord

ENTITY = "prescription"
MAX_ITEMS = 20

# Ward templates for common orders on rounds: (label, [(medicine code, quantity, dosage)]).
QUICK_TEMPLATES = {
    "ha-sot": ("Hạ sốt", [
        ("PARA500", 10, "Uống 1 viên khi sốt trên 38,5°C, cách nhau ít nhất 4 giờ"),
    ]),
    "tieu-chay": ("Tiêu chảy cấp", [
        ("ORS", 6, "Pha 1 gói với 200 ml nước, uống sau mỗi lần đi ngoài"),
        ("SMEC", 6, "Uống 1 gói x 3 lần/ngày"),
    ]),
    "di-ung": ("Dị ứng nhẹ", [
        ("LORA10", 5, "Uống 1 viên buổi tối"),
    ]),
    "da-day": ("Đau dạ dày", [
        ("OMEP20", 14, "Uống 1 viên trước ăn sáng 30 phút"),
        ("DOMP10", 9, "Uống 1 viên x 3 lần/ngày trước ăn"),
    ]),
}


class PrescriptionError(ValueError):
    """Invalid prescription or medicine data; the message is user-facing."""


def get_record_for_prescribing(db: Session, user: User, record_id: int) -> MedicalRecord:
    """Only the attending doctor may prescribe on a record (R-03); others get NotFound."""
    record = db.get(MedicalRecord, record_id)
    if record is None:
        raise NotFound
    if not policy.can_prescribe(user, db.get(Patient, record.patient_id)):
        metrics.authz_denied("prescription")
        raise NotFound
    return record


def create_prescription(
    db: Session,
    user: User,
    record_id: int,
    items: list[tuple[int, int, str]],
    note: str,
    ip: str | None,
) -> Prescription:
    record = get_record_for_prescribing(db, user, record_id)
    return _save_prescription(db, user, record, items, note, ip)


def quick_prescribe(
    db: Session, user: User, record_id: int, template_key: str, ip: str | None
) -> Prescription:
    """One-click prescription from a ward template, for orders given on rounds."""
    record = db.get(MedicalRecord, record_id)
    if record is None:
        raise NotFound
    if not policy.can_view_record(user, db.get(Patient, record.patient_id)):
        metrics.authz_denied("prescription")
        raise NotFound
    template = QUICK_TEMPLATES.get(template_key)
    if template is None:
        raise PrescriptionError("Đơn mẫu không tồn tại")
    label, lines = template
    items = []
    for code, quantity, dosage in lines:
        medicine_id = db.scalar(
            select(Medicine.id).where(Medicine.code == code, Medicine.is_active.is_(True))
        )
        if medicine_id is None:
            raise PrescriptionError(f"Đơn mẫu {label}: thuốc {code} không còn trong danh mục")
        items.append((medicine_id, quantity, dosage))
    return _save_prescription(db, user, record, items, f"Đơn mẫu: {label}", ip)


def _save_prescription(
    db: Session,
    user: User,
    record: MedicalRecord,
    items: list[tuple[int, int, str]],
    note: str,
    ip: str | None,
) -> Prescription:
    if not items:
        raise PrescriptionError("Đơn thuốc phải có ít nhất một thuốc")
    if len(items) > MAX_ITEMS:
        raise PrescriptionError(f"Đơn thuốc tối đa {MAX_ITEMS} thuốc")
    if len(note) > 500:
        raise PrescriptionError("Lời dặn: tối đa 500 ký tự")
    lines = []
    for medicine_id, quantity, dosage in items:
        medicine = db.get(Medicine, medicine_id)
        if medicine is None or not medicine.is_active:
            raise PrescriptionError("Thuốc: không có trong danh mục đang sử dụng")
        if quantity < 1 or quantity > 1000:
            raise PrescriptionError("Số lượng: phải từ 1 đến 1000")
        if not dosage or len(dosage) > 200:
            raise PrescriptionError("Liều dùng: bắt buộc, tối đa 200 ký tự")
        lines.append(PrescriptionItem(medicine_id=medicine.id, quantity=quantity, dosage=dosage))
    prescription = Prescription(record_id=record.id, patient_id=record.patient_id,
                                doctor_id=user.id, note=note, items=lines)
    db.add(prescription)
    db.flush()
    audit.log_access(db, user, audit.CREATE_PRESCRIPTION, ENTITY, prescription.id, ip)
    return prescription


def prescription_total(p: Prescription) -> Decimal:
    return sum((item.medicine.unit_price * item.quantity for item in p.items), Decimal(0))


def get_prescription_for(
    db: Session, user: User, prescription_id: int, ip: str | None
) -> Prescription:
    """Readable by whoever may read the underlying record (R-03, R-12); audited (R-05)."""
    prescription = db.get(Prescription, prescription_id)
    if prescription is None:
        raise NotFound
    if not policy.can_view_record(user, db.get(Patient, prescription.patient_id)):
        metrics.authz_denied("prescription")
        raise NotFound
    audit.log_access(db, user, audit.VIEW_PRESCRIPTION, ENTITY, prescription.id, ip)
    return prescription


def list_for_record(db: Session, record_id: int) -> list[Prescription]:
    stmt = (
        select(Prescription)
        .where(Prescription.record_id == record_id)
        .order_by(Prescription.created_at, Prescription.id)
    )
    return list(db.scalars(stmt).unique())


def list_medicines(db: Session, *, active_only: bool) -> list[Medicine]:
    stmt = select(Medicine).order_by(Medicine.name)
    if active_only:
        stmt = stmt.where(Medicine.is_active.is_(True))
    return list(db.scalars(stmt))


def add_medicine(db: Session, code: str, name: str, unit: str, unit_price: str) -> Medicine:
    code, name, unit = code.strip().upper(), name.strip(), unit.strip()
    if not (1 <= len(code) <= 20 and 1 <= len(name) <= 100 and 1 <= len(unit) <= 20):
        raise PrescriptionError("Mã, tên và đơn vị thuốc là bắt buộc")
    unit_price = unit_price.strip()
    if not (unit_price.isascii() and unit_price.isdigit() and len(unit_price) <= 12):
        raise PrescriptionError("Đơn giá: số nguyên không âm (đồng)")
    if db.scalar(select(Medicine.id).where(Medicine.code == code)) is not None:
        raise PrescriptionError("Mã thuốc đã tồn tại")
    medicine = Medicine(code=code, name=name, unit=unit, unit_price=Decimal(unit_price))
    db.add(medicine)
    db.flush()
    return medicine
