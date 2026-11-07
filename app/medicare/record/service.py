from sqlalchemy import select
from sqlalchemy.orm import Session

from medicare import policy
from medicare.audit import service as audit
from medicare.auth.models import User
from medicare.common.errors import NotFound
from medicare.patient.models import Patient
from medicare.patient.service import get_patient_for
from medicare.record.models import MedicalRecord
from medicare.record.schemas import RecordForm

ENTITY = "record"


def _load(db: Session, record_id: int) -> tuple[MedicalRecord, Patient] | None:
    record = db.get(MedicalRecord, record_id)
    if record is None:
        return None
    return record, db.get(Patient, record.patient_id)


def get_record_for(db: Session, user: User, record_id: int, ip: str | None) -> MedicalRecord:
    """Load a record the user may read and audit the access (R-02, R-05, R-12, R-15)."""
    loaded = _load(db, record_id)
    if loaded is None or not policy.can_view_record(user, loaded[1]):
        raise NotFound
    audit.log_access(db, user, audit.VIEW_RECORD, ENTITY, record_id, ip)
    return loaded[0]


def get_writable_record(db: Session, user: User, record_id: int) -> MedicalRecord:
    """Only the attending doctor may edit (R-02); anyone else gets NotFound."""
    loaded = _load(db, record_id)
    if loaded is None or not policy.can_write_record(user, loaded[1]):
        raise NotFound
    return loaded[0]


def get_patient_for_records(db: Session, user: User, patient_id: int) -> Patient:
    patient = get_patient_for(db, user, patient_id)
    if not policy.can_view_record(user, patient):
        raise NotFound
    return patient


def get_patient_for_new_record(db: Session, user: User, patient_id: int) -> Patient:
    patient = get_patient_for(db, user, patient_id)
    if not policy.can_write_record(user, patient):
        raise NotFound
    return patient


def list_records(db: Session, user: User, patient: Patient, ip: str | None) -> list[MedicalRecord]:
    """Records of a patient the user may read; the listing itself is audited (R-05)."""
    audit.log_access(db, user, audit.LIST_RECORDS, "patient", patient.id, ip)
    stmt = (
        select(MedicalRecord)
        .where(MedicalRecord.patient_id == patient.id)
        .order_by(MedicalRecord.visit_date.desc(), MedicalRecord.id.desc())
    )
    return list(db.scalars(stmt).unique())


def create_record(
    db: Session, user: User, patient: Patient, data: RecordForm, ip: str | None
) -> MedicalRecord:
    record = MedicalRecord(patient_id=patient.id, doctor_id=user.id, **data.model_dump())
    db.add(record)
    db.flush()
    audit.log_access(db, user, audit.CREATE_RECORD, ENTITY, record.id, ip)
    return record


def update_record(
    db: Session, user: User, record: MedicalRecord, data: RecordForm, ip: str | None
) -> MedicalRecord:
    for field, value in data.model_dump().items():
        setattr(record, field, value)
    db.flush()
    audit.log_access(db, user, audit.UPDATE_RECORD, ENTITY, record.id, ip)
    return record
