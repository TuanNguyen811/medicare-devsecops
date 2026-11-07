from datetime import UTC, date, datetime
from decimal import Decimal

from medicare.common.templating import date_vn, datetime_vn, vnd


def test_vnd_filter():
    assert vnd(Decimal(230000)) == "230.000 ₫"


def test_date_vn_filter():
    assert date_vn(date(2026, 1, 5)) == "05/01/2026"


def test_datetime_vn_filter_converts_to_vietnam_time():
    assert datetime_vn(datetime(2026, 1, 5, 2, 30, tzinfo=UTC)) == "05/01/2026 09:30"
