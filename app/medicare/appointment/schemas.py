from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from medicare.common.templating import VN_TZ

FIELD_LABELS = {
    "patient_id": "Bệnh nhân",
    "doctor_id": "Bác sĩ",
    "scheduled_at": "Thời gian hẹn",
    "reason": "Lý do khám",
}


class AppointmentForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    patient_id: int | None = None
    doctor_id: int
    scheduled_at: datetime
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("patient_id", mode="before")
    @classmethod
    def _blank_is_none(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("scheduled_at")
    @classmethod
    def _vietnam_wall_clock(cls, v: datetime) -> datetime:
        """The form sends local (Vietnam) time without an offset."""
        return v.replace(tzinfo=VN_TZ) if v.tzinfo is None else v
