"""Password hashing — argon2 (F2).

passlib CryptContext with argon2. Hashes start with the "$argon2" identifier;
verify is constant-time against the stored hash. No plaintext is ever stored.
"""
from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(plaintext: str) -> str:
    return _pwd_context.hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    return _pwd_context.verify(plaintext, password_hash)
