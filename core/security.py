from datetime import datetime, timedelta, timezone
from core.config import settings
import jwt
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return password_hash.verify(password, hashed)

def _create_token(sub: str, expires: timedelta, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "type": token_type,
        "iat": now,
        "exp": now + expires
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

def create_access_token(sub: str) -> str:
    return _create_token(sub, timedelta(minutes=settings.access_token_expire_minutes), "access")

def create_refresh_token(sub: str) -> str:
    return _create_token(sub, timedelta(minutes=settings.access_token_expire_minutes), "refresh")

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
