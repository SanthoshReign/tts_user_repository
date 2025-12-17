from typing import Optional
from pydantic import BaseModel, Field, EmailStr

from enums import Branches


# ----------------------- Input response Format ----------------
# ----------- SignUp ---------------------
class CreateUser(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(min_length = 8, max_length = 15)
    branch: str
    team: str
    role: str

# ------------ Login ---------------------
class LoginUser(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(min_length = 8, max_length = 15)

# ------- Update User Details -------
class UpdateUser(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None

# ----------- Adding Team -----------------

class AddTeam(BaseModel):
    team_name: str
    description: str
    branch: Branches
    status: bool

# ----------- Update Team ------------------

class UpdateTeam(BaseModel):
    team_name: Optional[str] = None
    description: Optional[str] = None
    branch: Optional[Branches] = None
    status: Optional[str] = None

# ------------ Team Response ------------------

class TeamResponse(BaseModel):
    id: int
    team_name: str
    description: Optional[str]
    created_by: int
    branch: Branches
    status: bool

    class config:
        from_attributes = True

# --------------------- Output Response --------------------------
class UserOut(BaseModel):
    message: str
    access_token: str
    token_type: str
    id: int
    username: str
    email: EmailStr

    class config:
        # This allows Pydantic to read ORM objects directly
        orm_mode = True

class SuccessMessage(BaseModel):
    message: str
    username: str
    email: EmailStr

class GetUser(BaseModel):
    id: int
    username: str
    email: EmailStr
    branch: str
    team: str
    role: str
    is_active: bool

    class config:
        # This allows Pydantic to read ORM objects directly
        orm_mode = True