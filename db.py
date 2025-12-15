from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base # ORM - Object-Relational Mappings
from config import get_settings

settings = get_settings()

DATABASE_URL = settings.DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    echo = True,
    future = True
)

SessionLocal = sessionmaker(bind = engine, autoflush = False)

Base = declarative_base()