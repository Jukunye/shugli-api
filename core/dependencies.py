import jwt
from fastapi import Depends, HTTPException, status, Path
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from core.db.base import get_db
from core.security import decode_token
from models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    creds_exp = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})

    try:
        payload = decode_token(token)
    except jwt.InvalidTokenError:
        raise creds_exp

    if payload.get("type") != "access":
        raise creds_exp

    sub = payload.get("sub")
    if not sub:
        raise creds_exp

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise creds_exp

    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise creds_exp
    return user

def require_self(user_id: int = Path(...), current_user: User = Depends(get_current_user)) -> User:
    if current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    return current_user