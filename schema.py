from pydantic import BaseModel, EmailStr, Field
from typing import List


# PYDANTIC MODELS WITH EMAILSTR VALIDATION

class UserCreate(BaseModel):
    email: EmailStr = Field(..., description="validated email using EmailStr") 
    full_name: str
    password: str
    roles: List[str] = ["user"]

class User(BaseModel):
    email: EmailStr
    full_name: str
    roles: List[str]
    disabled: bool = False

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None



