from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.base import get_db
from core.dependencies import require_self
from models.user import User
from schemas.user import UserResponse, UserUpdate
from services.refresh_tokens import revoke_all_refresh_token

router = APIRouter(prefix="/users", tags=["users"])


@router.patch("/{user_id}", response_model=UserResponse)
def update(
    payload: UserUpdate,
    current_user: User = Depends(require_self),
    db: Session = Depends(get_db),
):

    update_data = payload.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update"
        )

    if "username" in update_data and update_data["username"] != current_user.username:
        if db.scalar(select(User).where(User.username == update_data["username"])):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Username already taken"
            )

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


@router.post("/{user_id}/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(
    current_user: User = Depends(require_self), db: Session = Depends(get_db)
):
    """
    Revoke every refresh token for the authenticated user.

    Requires a valid access token. The token used to call this endpoint
    is also revoked — 'log out all' means all devices, including this
    one. Idempotent.
    """
    revoke_all_refresh_token(db=db, user_id=current_user.id)
    db.commit()
