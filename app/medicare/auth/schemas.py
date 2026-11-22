from pydantic import BaseModel, ConfigDict, Field, field_validator

PHONE_PATTERN = r"^0\d{9,10}$"


class ProfileForm(BaseModel):
    """Account details a user edits on their own profile page."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="allow")

    full_name: str = Field(min_length=1, max_length=100)
    phone: str | None = Field(default=None, pattern=PHONE_PATTERN)

    @field_validator("phone", mode="before")
    @classmethod
    def _blank_is_none(cls, v):
        return None if isinstance(v, str) and not v.strip() else v
