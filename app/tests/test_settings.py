import pytest
from pydantic import ValidationError

from medicare.config import Settings

URL = "postgresql+psycopg://u:p@h/db"
KEY = "x" * 32


def _loc(exc_info):
    return exc_info.value.errors()[0]["loc"]


def test_secret_key_31_chars_rejected_on_secret_key_field():
    with pytest.raises(ValidationError) as ei:
        Settings(database_url=URL, secret_key="x" * 31)
    assert _loc(ei) == ("secret_key",)


@pytest.mark.parametrize("env", ["development", "test", "production"])
def test_placeholder_secret_key_rejected_in_every_env(env):
    with pytest.raises(ValidationError) as ei:
        Settings(env=env, database_url=URL, secret_key="Change-Me-" + "a" * 30)
    assert _loc(ei) == ("secret_key",)


def test_change_me_40_chars_rejected():
    key = "change-me" + "a" * 31
    assert len(key) == 40
    with pytest.raises(ValidationError) as ei:
        Settings(database_url=URL, secret_key=key)
    assert _loc(ei) == ("secret_key",)


def test_validation_error_does_not_leak_secret():
    secret = "change-me-super-secret-value-0123456789"
    with pytest.raises(ValidationError) as ei:
        Settings(database_url=URL, secret_key=secret)
    assert secret not in str(ei.value)


@pytest.mark.parametrize("age", [299, 86401])
def test_session_max_age_out_of_range_rejected(age):
    with pytest.raises(ValidationError) as ei:
        Settings(database_url=URL, secret_key=KEY, session_max_age=age)
    assert _loc(ei) == ("session_max_age",)


@pytest.mark.parametrize("age", [300, 86400])
def test_session_max_age_bounds_accepted(age):
    s = Settings(database_url=URL, secret_key=KEY, session_max_age=age)
    assert s.session_max_age == age
