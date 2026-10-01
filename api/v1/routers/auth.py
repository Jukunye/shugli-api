from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.db.base import get_db
from core.dependencies import get_current_user
from core.security import create_access_token, hash_password, verify_password
from models.user import User
from schemas.auth import RefreshRequest, TokenResponse
from schemas.user import UserCreate, UserLogin, UserResponse
from services.refresh_tokens import (
    build_refresh_token,
    get_refresh_token,
    revoke_refresh_token,
    validate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
def register(payload: UserCreate, db: Session = Depends(get_db)):

    # Check for existing email
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        )

    # Check for existing username, if provided
    if payload.username:
        existing_username = db.scalar(
            select(User).where(User.username == payload.username)
        )
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Username already taken"
            )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        username=payload.username,
        phone=payload.phone,
    )

    try:
        db.add(user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already registered",
        )

    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):

    user = db.scalar(select(User).where(User.email == payload.email))

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account inactive"
        )

    access_token = create_access_token(str(user.id))

    raw, row = build_refresh_token(user.id)
    db.add(row)
    db.commit()
    db.refresh(row)

    return {"access_token": access_token, "refresh_token": raw, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/refresh", response_model=TokenResponse)
def refresh(refresh_request: RefreshRequest, db: Session = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access + refresh pair.

    Rotation is atomic: the new token is flushed to obtain its id, the
    old token is marked revoked and linked via replaced_by_id, then a
    single commit persists both changes. Replaying a rotated token
    therefore fails, and no window exists where two tokens are live.

    Returns 401 for unknown, revoked, expired, or inactive-user tokens
    with a generic message so clients cannot distinguish the cause.
    """
    invalid_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
    )
    row = get_refresh_token(db, refresh_request.refresh_token)

    if row is None:
        raise invalid_error

    try:
        validate_refresh_token(row)
    except ValueError:
        raise invalid_error

    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise invalid_error

    raw_new, row_new = build_refresh_token(user.id)
    db.add(row_new)
    db.flush()

    row.revoked_at = datetime.now(UTC)
    row.replaced_by_id = row_new.id

    db.commit()
    db.refresh(row_new)

    access_token = create_access_token(str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": raw_new,
        "token_type": "bearer",
    }


@router.post("'logout")
def logout(refresh_request: RefreshRequest, db: Session = Depends(get_db)):
    """
    Revoke the presented refresh token.

    Idempotent: returns 204 whether or not the token exists or was
    already revoked. The client's goal — this session no longer
    refreshes — is achieved either way.
    """
    row = get_refresh_token(db=db, raw=refresh_request.refresh_token)
    if row is not None and row.revoked_at is None:
        revoke_refresh_token(row)
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
