import secrets, hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import settings
from models.token import RefreshToken 

def build_refresh_token(user_id: int) -> tuple[str, RefreshToken]:
    """
    Generate a new refresh token.

    Returns (raw, row):
      - raw: the plaintext token to send to the client. Never stored.
      - row: the RefreshToken ORM object to persist. Stores only the hash.

    Hashing the token before storage means a database leak does not
    expose usable tokens. The token is high-entropy (256 bits) so a
    plain SHA-256 is sufficient — no salt or slow KDF needed, unlike
    passwords which are low-entropy and guessable.
    """
     
    raw = secrets.token_urlsafe(32)    
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

    row = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    
    return raw, row

def get_refresh_token(db: Session, raw: str) -> RefreshToken | None:
  """Look up a refresh token row by its raw value. Returns None if unknown."""
  raw_hash = hashlib.sha256(raw.encode()).hexdigest()
  return db.scalar(select(RefreshToken).where(RefreshToken.token_hash == raw_hash))


def validate_refresh_token(row: RefreshToken) -> None:
   """
    Raise ValueError if the token is revoked or expired.

    SQLite returns naive datetimes even for DateTime(timezone=True),
    so we normalize before comparing against an aware now.
    """
   now = datetime.now(timezone.utc)

   if row.revoked_at is not None:
      raise ValueError("Revoked refresh token")

   expires_at = row.expires_at
   if expires_at.tzinfo is None:
      expires_at = expires_at.replace(tzinfo=timezone.utc)
   
   if expires_at <= now:
      raise ValueError("Expired refresh token")