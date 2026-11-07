from medicare.common.passwords import hash_password, verify_password


def test_hash_is_argon2id_and_verifies():
    h = hash_password("Passw0rd!")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "Passw0rd!") is True


def test_wrong_password_false():
    assert verify_password(hash_password("Passw0rd!"), "nope") is False


def test_invalid_hash_false_not_raise():
    assert verify_password("not-a-hash", "x") is False
    assert verify_password("", "x") is False
