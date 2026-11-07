"""Object-level authorization rules (see docs/security-requirements.md).

Every object-level access decision in the application goes through one of the
`can_*` functions below. They are pure functions over already-loaded objects:
no database access, no side effects. Each docstring names the rule(s) it enforces.
"""

from medicare.appointment.models import Appointment, AppointmentStatus
from medicare.auth.models import Role, User
from medicare.patient.models import Patient

_ACTIVE_APPOINTMENT = {AppointmentStatus.REQUESTED, AppointmentStatus.CONFIRMED}


def _is_own(user: User, patient: Patient) -> bool:
    return (
        user.role == Role.PATIENT
        and user.patient_id is not None
        and user.patient_id == patient.id
    )


def _same_department(user: User, patient: Patient) -> bool:
    return user.department_id is not None and user.department_id == patient.department_id


def _is_attending(user: User, patient: Patient) -> bool:
    return (
        user.role == Role.DOCTOR
        and patient.attending_doctor_id is not None
        and patient.attending_doctor_id == user.id
    )


def _clinical_scope(user: User, patient: Patient) -> bool:
    """Who may see clinical content: R-01, R-02, R-03, R-12."""
    if user.role == Role.DOCTOR:
        return _same_department(user, patient) or _is_attending(user, patient)
    if user.role == Role.NURSE:
        return _same_department(user, patient)
    return _is_own(user, patient)


def can_view_patient(user: User, patient: Patient) -> bool:
    """R-01, R-12: staff see patients in their scope, patients see only themselves."""
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return True
    return _clinical_scope(user, patient)


def can_edit_patient(user: User) -> bool:
    """Only reception and admin maintain administrative patient data."""
    return user.role in (Role.ADMIN, Role.RECEPTIONIST)


def can_view_record(user: User, patient: Patient) -> bool:
    """R-01, R-02, R-12: clinical scope only; reception and admin never see records.

    Also governs viewing prescriptions (R-03).
    """
    return _clinical_scope(user, patient)


def can_write_record(user: User, patient: Patient) -> bool:
    """R-02: only the attending doctor creates or edits medical records."""
    return _is_attending(user, patient)


def can_prescribe(user: User, patient: Patient) -> bool:
    """R-03: only the attending doctor prescribes."""
    return _is_attending(user, patient)


def can_view_invoice(user: User, patient: Patient) -> bool:
    """R-01, R-04: billing staff and the patient themself."""
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return True
    return _is_own(user, patient)


def can_view_identifiers(user: User, patient: Patient) -> bool:
    """R-11: full CCCD / BHYT number only for reception, admin and the patient themself."""
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return True
    return _is_own(user, patient)


def can_view_appointment(user: User, appt: Appointment, patient: Patient) -> bool:
    """R-01, R-13: staff see all; a doctor their own; a nurse their department's; a patient theirs.

    appointment.service._scoped is the SQL mirror of this rule for list queries.
    """
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return True
    if user.role == Role.DOCTOR:
        return appt.doctor_id == user.id
    if user.role == Role.NURSE:
        return _same_department(user, patient)
    return _is_own(user, patient) and appt.patient_id == patient.id


def can_cancel_appointment(user: User, appt: Appointment) -> bool:
    """R-13: staff cancel active appointments; a patient only their own REQUESTED ones."""
    if user.role in (Role.ADMIN, Role.RECEPTIONIST):
        return appt.status in _ACTIVE_APPOINTMENT
    if user.role == Role.PATIENT:
        return (
            user.patient_id is not None
            and user.patient_id == appt.patient_id
            and appt.status == AppointmentStatus.REQUESTED
        )
    return False
