"""Authorization matrix tests for medicare.policy (pure functions, no DB)."""

import pytest

from medicare import policy
from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role, User
from medicare.patient.models import Patient

DEPT_A, DEPT_B = 1, 2
PATIENT_ID = 100
ATTENDING_ID = 10


def make_patient(**kw) -> Patient:
    fields = {"id": PATIENT_ID, "department_id": DEPT_A, "attending_doctor_id": ATTENDING_ID}
    fields.update(kw)
    return Patient(**fields)


def user_for(role: str, relation: str) -> User:
    """Build a user standing in `relation` to the default patient."""
    r = Role(role)
    if relation == "self":
        return User(id=50, role=r, patient_id=PATIENT_ID)
    if relation == "other":
        return User(id=51, role=r, patient_id=PATIENT_ID + 1)
    if relation == "attending":
        return User(id=ATTENDING_ID, role=r, department_id=DEPT_A)
    if relation == "attending_other_dept":
        return User(id=ATTENDING_ID, role=r, department_id=DEPT_B)
    if relation == "same_dept":
        return User(id=11, role=r, department_id=DEPT_A)
    if relation == "other_dept":
        return User(id=12, role=r, department_id=DEPT_B)
    if relation == "any":
        return User(id=13, role=r)
    raise ValueError(relation)


MATRIX = [
    # (role, relation, function, expected)
    ("PATIENT", "self", "can_view_record", True),
    ("PATIENT", "other", "can_view_record", False),
    ("DOCTOR", "attending", "can_write_record", True),
    ("DOCTOR", "same_dept", "can_write_record", False),
    ("DOCTOR", "same_dept", "can_view_record", True),
    ("DOCTOR", "other_dept", "can_view_record", False),
    ("DOCTOR", "attending_other_dept", "can_view_record", True),
    ("NURSE", "same_dept", "can_view_record", True),
    ("NURSE", "other_dept", "can_view_record", False),
    ("NURSE", "same_dept", "can_write_record", False),
    ("NURSE", "same_dept", "can_prescribe", False),
    ("DOCTOR", "attending", "can_prescribe", True),
    ("DOCTOR", "same_dept", "can_prescribe", False),
    ("RECEPTIONIST", "any", "can_view_record", False),
    ("ADMIN", "any", "can_view_record", False),
    ("RECEPTIONIST", "any", "can_view_identifiers", True),
    ("ADMIN", "any", "can_view_identifiers", True),
    ("PATIENT", "self", "can_view_identifiers", True),
    ("PATIENT", "other", "can_view_identifiers", False),
    ("DOCTOR", "attending", "can_view_identifiers", False),
    ("NURSE", "same_dept", "can_view_identifiers", False),
    ("PATIENT", "self", "can_view_invoice", True),
    ("PATIENT", "other", "can_view_invoice", False),
    ("RECEPTIONIST", "any", "can_view_invoice", True),
    ("ADMIN", "any", "can_view_invoice", True),
    ("NURSE", "same_dept", "can_view_invoice", False),
    ("DOCTOR", "attending", "can_view_invoice", False),
    ("RECEPTIONIST", "any", "can_view_patient", True),
    ("ADMIN", "any", "can_view_patient", True),
    ("DOCTOR", "same_dept", "can_view_patient", True),
    ("DOCTOR", "attending_other_dept", "can_view_patient", True),
    ("DOCTOR", "other_dept", "can_view_patient", False),
    ("NURSE", "same_dept", "can_view_patient", True),
    ("NURSE", "other_dept", "can_view_patient", False),
    ("PATIENT", "self", "can_view_patient", True),
    ("PATIENT", "other", "can_view_patient", False),
]


@pytest.mark.parametrize("role,relation,fn,expected", MATRIX)
def test_policy_matrix(role, relation, fn, expected):
    assert getattr(policy, fn)(user_for(role, relation), make_patient()) is expected


@pytest.mark.parametrize("fn", ["can_view_patient", "can_view_record"])
def test_missing_department_on_both_sides_is_not_same_department(fn):
    nurse = User(id=11, role=Role.NURSE, department_id=None)
    patient = make_patient(department_id=None, attending_doctor_id=None)
    assert getattr(policy, fn)(nurse, patient) is False


def test_patient_account_without_link_sees_nothing():
    unlinked = User(id=52, role=Role.PATIENT, patient_id=None)
    assert policy.can_view_patient(unlinked, make_patient()) is False


@pytest.mark.parametrize(
    "role,expected",
    [("RECEPTIONIST", True), ("ADMIN", True), ("DOCTOR", False), ("NURSE", False),
     ("PATIENT", False)],
)
def test_can_edit_patient(role, expected):
    assert policy.can_edit_patient(User(id=1, role=Role(role))) is expected


def appt(status: AppointmentStatus, patient_id: int = PATIENT_ID) -> Appointment:
    return Appointment(id=7, patient_id=patient_id, doctor_id=ATTENDING_ID, status=status)


@pytest.mark.parametrize(
    "role,relation,status,expected",
    [
        ("PATIENT", "self", AppointmentStatus.REQUESTED, True),
        ("PATIENT", "self", AppointmentStatus.CONFIRMED, False),
        ("PATIENT", "other", AppointmentStatus.REQUESTED, False),
        ("RECEPTIONIST", "any", AppointmentStatus.REQUESTED, True),
        ("RECEPTIONIST", "any", AppointmentStatus.CONFIRMED, True),
        ("RECEPTIONIST", "any", AppointmentStatus.COMPLETED, False),
        ("RECEPTIONIST", "any", AppointmentStatus.CANCELLED, False),
        ("ADMIN", "any", AppointmentStatus.CONFIRMED, True),
        ("DOCTOR", "attending", AppointmentStatus.REQUESTED, False),
        ("NURSE", "same_dept", AppointmentStatus.REQUESTED, False),
    ],
)
def test_can_cancel_appointment(role, relation, status, expected):
    assert policy.can_cancel_appointment(user_for(role, relation), appt(status)) is expected
