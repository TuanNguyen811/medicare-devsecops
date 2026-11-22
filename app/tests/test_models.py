from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role
from tests.factories import make_patient, make_user


def test_migration_creates_all_tables(db):
    names = set(db.execute(text("select tablename from pg_tables where schemaname='public'")).scalars())
    assert {"users", "departments", "patients", "appointments", "medical_records", "medicines",
            "prescriptions", "prescription_items", "invoices", "audit_logs"} <= names


def test_appointment_duration_defaults_to_thirty_minutes(db):
    doc = make_user(db, Role.DOCTOR)
    p = make_patient(db)
    t = datetime.now(UTC).replace(microsecond=0) + timedelta(days=1)
    db.execute(text(
        "insert into appointments (patient_id, doctor_id, scheduled_at, reason, status, "
        "created_by_id) values (:p, :d, :t, 'x', 'REQUESTED', :d)"
    ), {"p": p.id, "d": doc.id, "t": t})
    assert db.execute(text("select duration_minutes from appointments")).scalar_one() == 30


def test_status_stored_as_plain_string(db):
    doc = make_user(db, Role.DOCTOR)
    p = make_patient(db)
    t = datetime.now(UTC).replace(microsecond=0) + timedelta(days=2)
    db.add(Appointment(patient_id=p.id, doctor_id=doc.id, scheduled_at=t, reason="x",
                       status=AppointmentStatus.REQUESTED, created_by_id=doc.id))
    db.flush()
    assert db.execute(text("select status from appointments")).scalar_one() == "REQUESTED"


def test_patient_national_id_unique(db):
    p = make_patient(db)
    with pytest.raises(IntegrityError):
        make_patient(db, national_id=p.national_id)


def test_audit_timestamp_comes_from_database_clock(db):
    """R-05/R-06: the time of an audit row is set by the DB, not by the app process."""
    at = db.execute(text(
        "INSERT INTO audit_logs (actor_id, action, entity_type, entity_id) "
        "VALUES (1, 'VIEW_RECORD', 'record', 1) RETURNING at"
    )).scalar_one()
    db_now = db.execute(text("SELECT now()")).scalar_one()
    assert at is not None and abs((db_now - at).total_seconds()) < 5
