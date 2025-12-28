import base64
import hashlib
import os
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet

from .config import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_exp_minutes)
    payload = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(payload, settings.dockback_secret_key, algorithm="HS256")


def create_refresh_token(subject: str) -> str:
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_exp_days)
    payload = {"sub": subject, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.dockback_secret_key, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.dockback_secret_key, algorithms=["HS256"])


def _load_encryption_key() -> bytes:
    path = settings.dockback_encryption_key_file
    if not os.path.exists(path):
        raise RuntimeError("Encryption key file missing")
    with open(path, "rb") as handle:
        raw = handle.read().strip()
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    return Fernet(_load_encryption_key())


def encrypt_value(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_value(value: str) -> str:
    return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def generate_recovery_codes() -> list[str]:
    return [base64.urlsafe_b64encode(os.urandom(9)).decode("utf-8") for _ in range(5)]
