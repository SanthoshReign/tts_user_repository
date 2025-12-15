from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
import os
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    DATABASE_URL: str
    FRONTEND_URL: str


    model_config = SettingsConfigDict(
        env_file="/.env",
        env_file_encoding="utf-8"
    )

@lru_cache
def get_settings():
    return Settings()





