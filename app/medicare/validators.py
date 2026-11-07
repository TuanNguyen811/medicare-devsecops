"""Format validators and display helpers for Vietnamese identifiers."""

import re
from decimal import Decimal

_NATIONAL_ID = re.compile(r"\d{12}")
_INSURANCE_NUMBER = re.compile(r"[A-Z]{2}[1-5]\d{12}")

# R-04: benefit level is the 3rd character of the BHYT card number.
_COVERAGE_BY_LEVEL = {
    "1": Decimal("1.00"),
    "2": Decimal("1.00"),
    "3": Decimal("0.95"),
    "4": Decimal("0.80"),
    "5": Decimal("1.00"),
}
_NO_COVERAGE = Decimal("0.00")


def is_valid_national_id(value: str) -> bool:
    """CCCD: exactly 12 ASCII digits."""
    return bool(_NATIONAL_ID.fullmatch(value)) and value.isascii()


def is_valid_insurance_number(value: str) -> bool:
    """BHYT card number: 2 uppercase letters, benefit level 1-5, 12 digits."""
    return bool(_INSURANCE_NUMBER.fullmatch(value)) and value.isascii()


def coverage_rate(insurance_number: str | None) -> Decimal:
    """Share of the bill paid by BHYT, derived server-side from the card number (R-04)."""
    if insurance_number is None or not is_valid_insurance_number(insurance_number):
        return _NO_COVERAGE
    return _COVERAGE_BY_LEVEL[insurance_number[2]]


def mask(value: str | None, visible: int = 4) -> str:
    """Hide all but the last `visible` characters (R-11)."""
    if value is None:
        return ""
    hidden = max(len(value) - visible, 0)
    return "*" * hidden + value[hidden:]
