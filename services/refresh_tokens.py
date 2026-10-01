import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.config import settings
from models.token import RefreshToken


class RefreshTokenError(ValueError):
    """Base for refresh token validation failures."""


class RefreshTokenExpired(RefreshTokenError): ...


class RefreshTokenRevoked(RefreshTokenError): ...


class RefreshTokenReused(RefreshTokenError): ...


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
    expires_at = datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)

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
    Raise a RefreshTokenError subclass if the token is not usable.

    Order matters:
      - Reuse (revoked AND replaced_by_id set) is checked first because
        it is the strongest signal — a replayed token means we should
        kill the whole chain, not just reject this one.
      - Plain revocation (logout / logout-all) is next.
      - Expiry last.

    SQLite returns naive datetimes even for DateTime(timezone=True), so
    we normalize before comparing against an aware now.
    """
    now = datetime.now(UTC)

    if row.revoked_at is not None and row.replaced_by_id is not None:
        raise RefreshTokenReused()

    if row.revoked_at is not None:
        raise RefreshTokenRevoked()

    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at <= now:
        raise RefreshTokenExpired()


def revoke_refresh_token(row: RefreshToken, replaced_by_id: int | None = None) -> None:
    row.revoked_at = datetime.now(UTC)
    if replaced_by_id is not None:
        row.replaced_by_id = replaced_by_id


def revoke_all_refresh_token(db: Session, user_id: int):
    """
    Revoke every non-revoked refresh token for a user.

    Iterates rows so SQLAlchemy's onupdate fires on updated_at; a bulk
    UPDATE would bypass it. Returns the number of rows revoked.
    """
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
