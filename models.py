from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
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

    teams = relationship("Team", back_populates = "creator")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key = True, index = True)
    action = Column(String)
    performed_by = Column(String)
    target_user = Column(String)
    timestamp = Column(DateTime, default = datetime.now(UTC))

#---------------------------------------------------------------------------------------------

# adding team
class Team(Base):
    __tablename__ = "team_table"

    id = Column(Integer, primary_key = True, index = True)
    team_name = Column(String, unique = True, index = True)
    description = Column(String)
    created_by = Column(Integer, ForeignKey("users_table.id"))
    branch = Column(String)
    status = Column(Boolean, default = True)

    creator = relationship("User", back_populates = "teams")