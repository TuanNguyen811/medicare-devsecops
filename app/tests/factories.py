import itertools
from datetime import date

from medicare.auth.models import Role, User
from medicare.common.passwords import hash_password
from medicare.department.models import Department
from medicare.patient.models import Patient
from medicare.prescription.models import Medicine
from medicare.record.models import MedicalRecord

TEST_PASSWORD = "Passw0rd!"

_seq = itertools.count(1)
_PASSWORD_HASH = hash_password(TEST_PASSWORD)  # hashed once: argon2 is deliberately slow


def make_department(db, code="NOI") -> Department:
    dep = Department(code=code, name=f"Khoa {code}")
    db.add(dep)
    db.flush()
    return dep


def make_user(db, role: Role, *, department=None, patient=None, username=None) -> User:
    n = next(_seq)
    user = User(
        username=username or f"{role.value.lower()}{n}",
        password_hash=_PASSWORD_HASH,
        full_name=f"Người dùng {n}",
        role=role,
        department_id=department.id if department else None,
        patient_id=patient.id if patient else None,
    )
    db.add(user)
    db.flush()
    return user


def make_patient(db, *, department=None, attending=None,
                 insurance_number="DN4010123456789", national_id=None) -> Patient:
    n = next(_seq)
    patient = Patient(
        code=f"BN{n:06d}",
        full_name=f"Bệnh nhân {n}",
        date_of_birth=date(1990, 1, 1),
        gender="M",
        national_id=national_id or f"{n:012d}",
        insurance_number=insurance_number,
        phone=f"09{n:08d}",
        address="Hà Nội",
        department_id=department.id if department else None,
        attending_doctor_id=attending.id if attending else None,
    )
    db.add(patient)
    db.flush()
    return patient


def make_record(db, patient, doctor) -> MedicalRecord:
    rec = MedicalRecord(
        patient_id=patient.id,
        doctor_id=doctor.id,
        visit_date=date.today(),
        symptoms="Ho, sốt nhẹ",
        diagnosis_code="J06.9",
        diagnosis_text="Viêm đường hô hấp trên cấp",
        notes="Theo dõi thêm",
    )
    db.add(rec)
    db.flush()
    return rec


def make_medicine(db, price=10000) -> Medicine:
    n = next(_seq)
    med = Medicine(code=f"MED{n:05d}", name=f"Thuốc {n}", unit="viên", unit_price=price)
    db.add(med)
    db.flush()
    return med
