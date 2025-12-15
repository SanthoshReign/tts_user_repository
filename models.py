from sqlalchemy import Column, String, Integer, Boolean, DateTime
from db import Base
from datetime import datetime, UTC

class User(Base):
    __tablename__ = "users_table"

    id = Column(Integer, primary_key = True, index = True)
    username = Column(String, unique = True, index = True)
    email = Column(String, unique = True, index = True)
    password_hashed = Column(String)
    branch = Column(String)
    team = Column(String)
    role = Column(String)

    is_active = Column(Boolean, default = True)  # soft_delete


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key = True, index = True)
    action = Column(String)
    performed_by = Column(String)
    target_user = Column(String)
    timestamp = Column(DateTime, default = datetime.now(UTC))