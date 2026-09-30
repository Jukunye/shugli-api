from fastapi import APIRouter, Depends, HTTPException, status
from core.db.base import get_db
from core.dependencies import get_current_user
from core.security import hash_password, verify_password, create_access_token, create_refresh_token
from models.user import User
from schemas.user import UserCreate, UserResponse, UserLogin
from schemas.auth import TokenResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from services.refresh_tokens import build_refresh_token


router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):

    # Check for existing email
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # Check for existing username, if provided
    if payload.username:
        existing_username = db.scalar(select(User).where(User.username == payload.username))
        if existing_username:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        username=payload.username,
        phone=payload.phone
    )

    try:
        db.add(user)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email or username already registered")
    
    db.refresh(user)
    return user

@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):

    user = db.scalar(select(User).where(User.email == payload.email))

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account inactive")


    access_token = create_access_token(str(user.id))
    
    raw, row = build_refresh_token(user.id)
    db.add(row)
    db.commit()
    db.refresh(row)


    return {"access_token": access_token, "refresh_token": raw, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    return current_user