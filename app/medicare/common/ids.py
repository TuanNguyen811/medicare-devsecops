"""Database id types bounded to PostgreSQL INTEGER, for path params and form fields.

An id outside 1..INT4_MAX can never exist; rejecting it up front keeps "too large"
indistinguishable from "missing" (R-15) instead of failing inside the database.
"""

from typing import Annotated

from fastapi import Path
from pydantic import Field

INT4_MAX = 2**31 - 1

ObjectId = Annotated[int, Path(ge=1, le=INT4_MAX)]
FormId = Annotated[int, Field(ge=1, le=INT4_MAX)]


def parse_id(value: str) -> int | None:
    """Strict parse of a form value into a valid id, or None."""
    value = value.strip()
    if not (value.isascii() and value.isdigit() and len(value) <= 10):
        return None
    number = int(value)
    return number if 1 <= number <= INT4_MAX else None
