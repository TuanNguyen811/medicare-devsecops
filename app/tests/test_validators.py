from decimal import Decimal

import pytest

from medicare.validators import (
    coverage_rate,
    is_valid_insurance_number,
    is_valid_national_id,
    mask,
)


@pytest.mark.parametrize(
    "code,rate",
    [
        ("DN1010123456789", "1.00"),
        ("DN3010123456789", "0.95"),
        ("HT4010123456789", "0.80"),
        ("CB5010123456789", "1.00"),
        ("XX9010123456789", "0.00"),
        (None, "0.00"),
        ("dn4010123456789", "0.00"),
        ("DN40101234", "0.00"),
    ],
)
def test_coverage_rate(code, rate):
    assert coverage_rate(code) == Decimal(rate)


def test_coverage_rate_level_2_is_full():
    assert coverage_rate("GD2010123456789") == Decimal("1.00")


def test_mask():
    assert mask("012345678901") == "********8901"
    assert mask(None) == ""


def test_mask_custom_visible():
    assert mask("DN4010123456789", visible=2) == "*************89"


def test_national_id():
    assert is_valid_national_id("012345678901") and not is_valid_national_id("12345")


@pytest.mark.parametrize("value", ["01234567890a", "0123456789012", "", "012345678901\n"])
def test_national_id_rejects_malformed(value):
    assert not is_valid_national_id(value)


@pytest.mark.parametrize(
    "value,ok",
    [
        ("DN4010123456789", True),
        ("dn4010123456789", False),
        ("DN6010123456789", False),
        ("DN401012345678", False),
        ("DN4010123456789\n", False),
    ],
)
def test_insurance_number_format(value, ok):
    assert is_valid_insurance_number(value) is ok
