from datetime import date

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

FIELD_LABELS = {
    "visit_date": "Ngày khám",
    "symptoms": "Triệu chứng",
    "diagnosis_code": "Mã ICD-10",
    "diagnosis_text": "Chẩn đoán",
    "notes": "Ghi chú",
}

_ICD10 = r"^[A-Z][0-9]{2}(\.[0-9A-Z]{1,4})?$"


class RecordForm(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    visit_date: date
    symptoms: str = Field(min_length=1, max_length=2000)
    diagnosis_code: str = Field(pattern=_ICD10, max_length=20)
    diagnosis_text: str = Field(min_length=1, max_length=500)
    notes: str = Field(default="", max_length=5000)

    @field_validator("visit_date")
    @classmethod
    def _not_in_future(cls, v: date) -> date:
        if v > date.today():
            raise ValueError("ngày khám không được ở tương lai")
        return v


def form_errors(exc: ValidationError) -> list[str]:
    """One message per invalid field; never echoes the submitted (clinical) text."""
    return [
        f"{FIELD_LABELS.get(str(e['loc'][0]), e['loc'][0])}: giá trị không hợp lệ"
        for e in exc.errors(include_input=False)
    ]
