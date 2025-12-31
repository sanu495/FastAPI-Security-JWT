from datetime import datetime, timedelta, timezone
from typing import Annotated, List
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from schema import UserInDB, TokenData

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


PRE_HASHED_ADMIN = "$pbkdf2-sha256$29000$oHTufQ9B6B0DQAhBiJGy1g$S/MbXCMKEwTDeX6tS5m0d7vi7VZbzLdukAmh9wY5q2Q"  # admin123
PRE_HASHED_USER = "$2b$12$qwrtyuiopasdfghjklzxcvbnmQWERTYUIOP123456"  # user123

user_db = {
    "admin@example.com": {
        "email": "admin@example.com",
        "full_name": "Admin User",
        "hashed_password": PRE_HASHED_ADMIN,
        "disabled": False,
        "roles": ["admin", "user"]
    },
    "user@example.com": {
        "email": "user@example.com",
        "full_name": "Regular user",
        "hashed_password": PRE_HASHED_USER,
        "disabled": False,
        "roles": ["user"]
    }
}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_user(db: dict, email: str):
    if email in db:
        user_dict = db[email]
        return UserInDB(**user_dict)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(user_db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[UserInDB, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_roles(required_roles: List[str]):
    def role_checker(current_user: UserInDB = Depends(get_current_active_user)):
        user_roles = set(current_user.roles)
        required_set = set(required_roles)
        if not required_set.issubset(user_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Required roles: {required_roles}")
        return current_user
    return role_checker
