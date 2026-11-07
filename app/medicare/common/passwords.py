from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()  # argon2id with the library's recommended parameters


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(hash: str, plain: str) -> bool:
    """Return True only for a matching password; never raises on mismatch or a bad hash."""
    try:
        return _hasher.verify(hash, plain)
    except (VerificationError, InvalidHashError):
        return False
