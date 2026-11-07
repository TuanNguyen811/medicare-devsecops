"""Demo data for development: `python -m medicare.seed` (ENV=development only).

All people, identifiers and clinical data are fake (Faker vi_VN, fixed seed).
"""

import os
import random
import secrets
import sys
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from faker import Faker
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role, User
from medicare.common.passwords import hash_password
from medicare.common.templating import VN_TZ
from medicare.department.models import Department
from medicare.patient.models import Patient
from medicare.prescription.models import Medicine, Prescription, PrescriptionItem
from medicare.record.models import MedicalRecord

DEPARTMENTS = [("NOI", "Khoa Nội"), ("NGOAI", "Khoa Ngoại"), ("NHI", "Khoa Nhi")]
DOCTORS = [("bacsi1", "NOI"), ("bacsi2", "NOI"), ("bacsi3", "NGOAI"), ("bacsi4", "NHI")]
NURSES = [("yta1", "NOI"), ("yta2", "NGOAI"), ("yta3", "NHI")]
PATIENT_ACCOUNTS = 5
N_PATIENTS, N_RECORDS, N_APPOINTMENTS = 50, 100, 30

MEDICINES = [
    ("PARA500", "Paracetamol 500mg", "viên", 1_500),
    ("AMOX500", "Amoxicillin 500mg", "viên", 2_500),
    ("IBU400", "Ibuprofen 400mg", "viên", 2_000),
    ("OMEP20", "Omeprazol 20mg", "viên", 3_000),
    ("METF500", "Metformin 500mg", "viên", 1_200),
    ("AMLO5", "Amlodipin 5mg", "viên", 1_800),
    ("LORA10", "Loratadin 10mg", "viên", 1_000),
    ("CEFU500", "Cefuroxim 500mg", "viên", 8_500),
    ("AZIT250", "Azithromycin 250mg", "viên", 9_000),
    ("SALB2", "Salbutamol 2mg", "viên", 600),
    ("ORS", "Oresol", "gói", 2_500),
    ("VITC500", "Vitamin C 500mg", "viên", 800),
    ("DOMP10", "Domperidon 10mg", "viên", 1_500),
    ("SMEC", "Diosmectit 3g", "gói", 4_000),
    ("ATOR20", "Atorvastatin 20mg", "viên", 3_500),
    ("LOSA50", "Losartan 50mg", "viên", 2_800),
    ("PRED5", "Prednisolon 5mg", "viên", 700),
    ("CETI10", "Cetirizin 10mg", "viên", 900),
    ("ALPH", "Alpha chymotrypsin", "viên", 1_200),
    ("NACL09", "Natri clorid 0,9%", "chai", 12_000),
]

DIAGNOSES = [
    ("J06.9", "Viêm đường hô hấp trên cấp", "Sốt, ho, đau họng"),
    ("J18.9", "Viêm phổi", "Sốt cao, ho có đờm, khó thở"),
    ("I10", "Tăng huyết áp vô căn", "Đau đầu, chóng mặt"),
    ("E11.9", "Đái tháo đường type 2", "Khát nhiều, tiểu nhiều, mệt mỏi"),
    ("K29.7", "Viêm dạ dày", "Đau thượng vị, ợ chua"),
    ("A09", "Tiêu chảy nhiễm khuẩn", "Tiêu chảy, đau bụng, sốt nhẹ"),
    ("M54.5", "Đau thắt lưng", "Đau lưng khi vận động"),
    ("S52.5", "Gãy đầu dưới xương quay", "Đau, sưng cổ tay sau ngã"),
    ("L50.9", "Mày đay", "Ngứa, nổi mẩn đỏ"),
    ("H66.9", "Viêm tai giữa", "Đau tai, sốt"),
]

_INSURANCE_PREFIXES = ["DN", "HT", "GD", "HS", "CB", "TE"]


def _user(username: str, full_name: str, role: Role, password_hash: str, **kw) -> User:
    return User(username=username, full_name=full_name, role=role, password_hash=password_hash,
                **kw)


def run(db: Session, *, password: str, rng_seed: int = 42) -> dict[str, int]:
    """Populate an empty database with deterministic demo data; returns row counts."""
    fake = Faker("vi_VN")
    fake.seed_instance(rng_seed)
    rng = random.Random(rng_seed)  # demo data only, not security-relevant
    pw_hash = hash_password(password)

    depts = {code: Department(code=code, name=name) for code, name in DEPARTMENTS}
    db.add_all(depts.values())
    db.flush()

    users = [
        _user("admin", "Quản trị hệ thống", Role.ADMIN, pw_hash),
        _user("letan1", fake.name(), Role.RECEPTIONIST, pw_hash),
    ]
    doctors = [_user(u, fake.name(), Role.DOCTOR, pw_hash, department_id=depts[d].id)
               for u, d in DOCTORS]
    nurses = [_user(u, fake.name(), Role.NURSE, pw_hash, department_id=depts[d].id)
              for u, d in NURSES]
    db.add_all(users + doctors + nurses)
    db.flush()
    receptionist = users[1]

    used_ids: set[str] = set()
    patients = []
    for i in range(N_PATIENTS):
        doctor = doctors[i % len(doctors)]
        national_id = f"{rng.randrange(10**11, 10**12):012d}"
        while national_id in used_ids:
            national_id = f"{rng.randrange(10**11, 10**12):012d}"
        used_ids.add(national_id)
        insurance = (
            f"{rng.choice(_INSURANCE_PREFIXES)}{rng.randint(1, 5)}{rng.randrange(10**12):012d}"
            if rng.random() < 0.8 else None
        )
        patients.append(Patient(
            code=f"TMP{secrets.token_hex(6)}",
            full_name=fake.name(),
            date_of_birth=fake.date_between(date(1940, 1, 1), date(2020, 12, 31)),
            gender=rng.choice("MF"),
            national_id=national_id,
            insurance_number=insurance,
            phone=f"09{rng.randrange(10**8):08d}",
            address=fake.address().replace("\n", ", ")[:255],
            department_id=doctor.department_id,
            attending_doctor_id=doctor.id,
        ))
    db.add_all(patients)
    db.flush()
    for p in patients:
        p.code = f"BN{p.id:06d}"
    patient_users = [
        _user(f"benhnhan{i + 1}", patients[i].full_name, Role.PATIENT, pw_hash,
              patient_id=patients[i].id)
        for i in range(PATIENT_ACCOUNTS)
    ]
    db.add_all(patient_users)

    medicines = [Medicine(code=c, name=n, unit=u, unit_price=Decimal(price))
                 for c, n, u, price in MEDICINES]
    db.add_all(medicines)
    db.flush()

    today = date.today()
    prescriptions = 0
    for _ in range(N_RECORDS):
        patient = rng.choice(patients)
        code, text, symptoms = rng.choice(DIAGNOSES)
        record = MedicalRecord(
            patient_id=patient.id, doctor_id=patient.attending_doctor_id,
            visit_date=today - timedelta(days=rng.randint(1, 365)),
            symptoms=symptoms, diagnosis_code=code, diagnosis_text=text,
            notes=rng.choice(["", "Tái khám sau 7 ngày", "Theo dõi tại nhà"]),
        )
        db.add(record)
        db.flush()
        if rng.random() < 0.6:
            items = [PrescriptionItem(medicine_id=m.id, quantity=rng.randint(5, 20),
                                      dosage="1 viên x 2 lần/ngày, sau ăn")
                     for m in rng.sample(medicines, rng.randint(1, 3))]
            db.add(Prescription(record_id=record.id, patient_id=patient.id,
                                doctor_id=record.doctor_id, items=items))
            prescriptions += 1

    taken: set[tuple[int, datetime]] = set()
    while len(taken) < N_APPOINTMENTS:
        patient = rng.choice(patients)
        day = today + timedelta(days=rng.randint(1, 14))
        slot = time(8 + rng.randint(0, 8), rng.choice((0, 30)))
        when = datetime.combine(day, slot, tzinfo=VN_TZ)
        key = (patient.attending_doctor_id, when)
        if key in taken:
            continue
        taken.add(key)
        db.add(Appointment(
            patient_id=patient.id, doctor_id=patient.attending_doctor_id, scheduled_at=when,
            reason=rng.choice(["Khám định kỳ", "Tái khám", "Đau đầu", "Ho kéo dài"]),
            status=rng.choice([AppointmentStatus.REQUESTED, AppointmentStatus.CONFIRMED]),
            created_by_id=receptionist.id,
        ))
    db.flush()

    return {
        "departments": len(depts),
        "users": len(users) + len(doctors) + len(nurses) + len(patient_users),
        "patients": len(patients),
        "medicines": len(medicines),
        "records": N_RECORDS,
        "prescriptions": prescriptions,
        "appointments": N_APPOINTMENTS,
    }


def main() -> int:
    if os.environ.get("ENV") != "development":
        print("Từ chối: chỉ chạy seed khi ENV=development", file=sys.stderr)
        return 1
    password = os.environ.get("DEMO_PASSWORD", "")
    if len(password) < 10 or "change-me" in password.lower():
        print("Từ chối: DEMO_PASSWORD phải có ít nhất 10 ký tự và không phải giá trị mẫu",
              file=sys.stderr)
        return 1

    from medicare.config import Settings
    from medicare.db import create_db

    engine, session_factory = create_db(Settings().database_url)
    try:
        with session_factory() as db:
            if db.scalar(select(func.count()).select_from(User)):
                print("Cơ sở dữ liệu đã có tài khoản, bỏ qua seed.")
                return 0
            counts = run(db, password=password)
            db.commit()
    finally:
        engine.dispose()
    print("Đã tạo dữ liệu mẫu: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
