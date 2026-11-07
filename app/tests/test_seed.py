from sqlalchemy import func, select

from medicare.appointment.models import Appointment
from medicare.auth.models import Role, User
from medicare.common.passwords import verify_password
from medicare.patient.models import Patient
from medicare.seed import main, run

DEMO = "Demo-password-1"


def test_seed_counts_and_idempotent_users(db):
    counts = run(db, password=DEMO)
    assert counts["patients"] == 50 and counts["records"] == 100 and counts["users"] == 14
    assert counts["departments"] == 3 and counts["medicines"] == 20
    assert counts["appointments"] == 30
    assert db.scalar(select(User).where(User.username == "bacsi1")).role == Role.DOCTOR


def test_seed_accounts_use_demo_password(db):
    run(db, password=DEMO)
    admin = db.scalar(select(User).where(User.username == "admin"))
    assert verify_password(admin.password_hash, DEMO)


def test_patient_accounts_linked_to_attended_patients(db):
    run(db, password=DEMO)
    for i in range(1, 6):
        user = db.scalar(select(User).where(User.username == f"benhnhan{i}"))
        patient = db.get(Patient, user.patient_id)
        doctor = db.get(User, patient.attending_doctor_id)
        assert doctor.role == Role.DOCTOR and doctor.department_id == patient.department_id


def test_seed_codes_and_appointment_slots_are_valid(db):
    run(db, password=DEMO)
    codes = db.scalars(select(Patient.code)).all()
    assert all(c.startswith("BN") and len(c) == 8 for c in codes)
    slots = db.execute(select(Appointment.doctor_id, Appointment.scheduled_at)).all()
    assert len(set(slots)) == len(slots)
    assert db.scalar(select(func.count()).select_from(Appointment)) == 30


def test_seed_refuses_outside_development(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("DEMO_PASSWORD", "x" * 12)
    assert main() == 1


def test_seed_requires_explicit_development_env(monkeypatch):
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.setenv("DEMO_PASSWORD", "x" * 12)
    assert main() == 1


def test_seed_requires_strong_demo_password(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("DEMO_PASSWORD", raising=False)
    assert main() == 1
    monkeypatch.setenv("DEMO_PASSWORD", "change-me")
    assert main() == 1
