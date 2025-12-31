from fastapi import APIRouter, Depends, HTTPException, status
from schema import User, UserCreate, Token, UserInDB, TokenData
from Utilities import (user_db, get_user, verify_password, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_active_user,
        require_roles, get_password_hash, pwd_context)
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

router = APIRouter()


@router.post("/generate-hash/")
def generate_hash(password: str):
    return {"hash": pwd_context.hash(password)}



@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = get_user(user_db, form_data.username)

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)

    return Token(access_token=access_token, token_type="bearer")



@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[UserInDB, Depends(get_current_active_user)]):
    return current_user



@router.get("/admin/users/")
async def get_all_users(current_user: UserInDB = Depends(require_roles(["admin"]))):
    users = []
    for user_data in user_db.values():
        users.append(User(**user_data))
    return users



@router.post("/admin/create_user/")
async def create_user(user: UserCreate, current_user: UserInDB = Depends(require_roles(["admin"]))):
    hashed_password = get_password_hash(user.password)
    user_db[user.email] = {
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "disabled": False,
        "roles": user.roles
    }

    return {"message": f"User {user.email} created successfully", "user": user}

    

@router.get("/users/items/")
async def read_user_items(current_user: Annotated[UserInDB, Depends(get_current_active_user)]):
    return [{"item_id": "1", "owner": current_user.email, "item": "User Item"}]
