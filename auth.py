from passlib.context import CryptContext
import jwt
from fastapi import HTTPException
from datetime import datetime, UTC, timedelta

from config import get_settings

settings = get_settings()


SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

pwd_context = CryptContext(schemes=["argon2"], deprecated = "auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, password_hashed: str):
    return pwd_context.verify(password, password_hashed)

def create_token(data: dict):

    # Including all the user credentials inside payload
    payload = data.copy()

    payload["exp"] = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    return jwt.encode(payload, SECRET_KEY, ALGORITHM)

def create_reset_token(email:str):
    data = {"sub": email, "purpose": "Password_Reset"}

    return jwt.encode(data, SECRET_KEY, ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code = 401, detail = "Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code = 401, detail = "Invalid Token")
