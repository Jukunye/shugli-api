from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional
from datetime import datetime

# --- Shared base ---
class UserBase(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: EmailStr

# --- Create ---
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    phone: Optional[str] = Field(None, max_length=20)

# --- Update (PATCH semantics: everything is optional) ---
class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(None, max_length=20)
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None

# --- Internal (DB representation) ---
class UserInDB(UserBase):
    id: int
    hashed_password: str
    phone: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

# --- Public response ---
class UserResponse(UserBase):
    id: int
    phone: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
