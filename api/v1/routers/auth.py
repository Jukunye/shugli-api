from fastapi import APIRouter, Depends, HTTPException, status
from core.db.base import get_db
from core.security import hash_password
from models.user import User
from schemas.user import UserCreate, UserResponse
from sqlalchemy import select
from sqlalchemy.orm import Session


router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):

    # Check for existing email
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    # Check for existing username, if provided
    if payload.username:
        existing_username = db.scalar(select(User).where(User.username == payload.username))
        if existing_username:
            raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        username=payload.username,
        phone=payload.phone
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user