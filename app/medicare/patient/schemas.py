from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from medicare.common.ids import FormId
from medicare.validators import is_valid_insurance_number, is_valid_national_id

FIELD_LABELS = {
    "full_name": "Họ tên",
    "date_of_birth": "Ngày sinh",
    "gender": "Giới tính",
    "national_id": "CCCD",
    "insurance_number": "Mã BHYT",
    "phone": "Số điện thoại",
    "address": "Địa chỉ",
    "department_id": "Khoa",
    "attending_doctor_id": "Bác sĩ phụ trách",
}

_PHONE = r"^0\d{9,10}$"


class PatientForm(BaseModel):
    """Administrative patient data submitted by reception (create and edit)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    full_name: str = Field(min_length=1, max_length=100)
    date_of_birth: date
    gender: Literal["M", "F"]
    national_id: str
    insurance_number: str | None = None
    phone: str = Field(pattern=_PHONE)
    address: str = Field(min_length=1, max_length=255)
    department_id: FormId | None = None
    attending_doctor_id: FormId | None = None

    @field_validator("insurance_number", "department_id", "attending_doctor_id", mode="before")
    @classmethod
    def _blank_is_none(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("date_of_birth")
    @classmethod
    def _plausible_birth_date(cls, v: date) -> date:
        if v > date.today() or v.year < 1900:
            raise ValueError("ngày sinh không hợp lệ")
        return v

    @field_validator("national_id")
    @classmethod
    def _national_id(cls, v: str) -> str:
        if not is_valid_national_id(v):
            raise ValueError("CCCD phải gồm đúng 12 chữ số")
        return v

    @field_validator("insurance_number")
    @classmethod
    def _insurance_number(cls, v: str | None) -> str | None:
        if v is not None and not is_valid_insurance_number(v):
            raise ValueError("Mã BHYT không đúng định dạng")
        return v


def form_errors(exc: ValidationError) -> list[str]:
    """Vietnamese one-line messages naming the offending field; never echoes input."""
    messages = []
    for err in exc.errors(include_input=False):
        field = str(err["loc"][0]) if err["loc"] else ""
        messages.append(f"{FIELD_LABELS.get(field, field)}: giá trị không hợp lệ")
    return messages
