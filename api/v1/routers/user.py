from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.dependencies import require_self
from core.db.base import get_db
from models.user import User
from schemas.user import UserUpdate, UserResponse

router = APIRouter(prefix="/users", tags=["users"])

@router.patch("/{user_id}", response_model=UserResponse)
def update(payload: UserUpdate, current_user: User = Depends(require_self), db: Session = Depends(get_db)):

    update_data = payload.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")
    
    if "username" in update_data and update_data["username"] != current_user.username:
        if db.scalar(select(User).where(User.username == update_data["username"])):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")
    
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    db.commit()
    db.refresh(current_user)

    return current_user

@router.delete("/{user_id}", response_model=UserResponse)
def delete(current_user: User = Depends(require_self), db: Session = Depends(get_db)):
    
    current_user.is_active = False
    db.commit()
    db.refresh(current_user)

    return current_user
