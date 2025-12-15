from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials

from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from config import get_settings
from db import Base, engine, SessionLocal
from models import User, AuditLog
from schemas import CreateUser, LoginUser, UserOut, SuccessMessage, GetUser, UpdateUser
from auth import hash_password, verify_password, create_token, create_reset_token, SECRET_KEY, ALGORITHM, decode_token

from jose import jwt, JWTError

from datetime import datetime, UTC, timedelta

app = FastAPI()

settings = get_settings()

# origins = [
#     "http://localhost:5173"
# ]

app.add_middleware(
    CORSMiddleware,
    allow_origins= [settings.FRONTEND_URL],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)

# OAuth2_scheme = OAuth2PasswordBearer(tokenUrl = "login")
token_auth_scheme = HTTPBearer()

# create table
Base.metadata.create_all(bind = engine )

def getDb():
    db = SessionLocal()
    try:
        yield db

    finally:
        db.close()

@app.get("/")
def root():
    return {"status": "FastAPI running"}

# --------------------------------
# SIGN UP
# --------------------------------
@app.post('/signup', response_model = SuccessMessage)
def signup(user: CreateUser, db: Session = Depends(getDb)):
    # check existing 'user'
    # 'User' - database, user - incoming user credentials from front-end
    existing = db.query(User).filter((User.email == user.email) or (User.username == user.username)).first()

    if existing:
        raise HTTPException(status_code = 400, detail = "Username or Email already exist")

    hashed_password = hash_password(user.password)

    new_user = User(username = user.username, email = user.email, password_hashed = hashed_password,
                    branch = user.branch, team = user.team, role = user.role.capitalize())

    db.add(new_user)
    db.commit()        # update changes on the database
    db.refresh(new_user)

    return {"message": "User Registered Successfully", "username" : new_user.username, "email": new_user.email}

# ---------------------------------------
# LOGIN
# ---------------------------------------

@app.post('/login')
def login(user: LoginUser, db: Session = Depends(getDb)):
    # check user email in the database first
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user.is_active:
        raise HTTPException(status_code = 400, detail = "User has been deleted")

    if not db_user:
        raise HTTPException(status_code = 400, detail = "Invalid Email")

    if not verify_password(user.password, db_user.password_hashed):
        raise HTTPException(status_code = 400, detail = "Invalid Password")

    token = create_token({'sub': db_user.email, 'role': db_user.role})

    return {
        "message" : "Login Successfully!",
        "access_token": token,
        "token_type": "bearer",
        "id": db_user.id,
        "username": db_user.username,
        "email": db_user.email,
        "branch": db_user.branch,
        "team": db_user.team,
        "role": db_user.role
    }

# ------------------------------------------------
# FORGOT PASSWORD
# ------------------------------------------------

@app.post('/forgot-password')
def forgot_password(email: str, db: Session = Depends(getDb)):
    # User is the database class
    password_reset_user = db.query(User).filter(User.email == email).first()

    if not password_reset_user:
        raise HTTPException(status_code = 401, detail = "User not found")

    # Generate reset token
    reset_token = create_reset_token(password_reset_user.email)

    # now, we need to send reset link to email, but for simplicity we are just printing and returning it
    reset_link = f"http://localhost:8000/reset-token?token={reset_token}" # now, we need to create the endpoint /reset-token

    print("Password Reset link: ", reset_link)

    return {
        "message" : "Password reset link is sent to you email",
        "Reset Link": reset_link
    }


# ------------------------------------------------------
# RESET PASSWORD
# ------------------------------------------------------

@app.post("/reset-password")                                    # Depends - dependency injection
def reset_password(token: str, new_password: str, db: Session = Depends(getDb)):
    try:
        # payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        payload = decode_token(token)

        if payload.get("purpose") != "Password_Reset":
            raise HTTPException(status_code = 400, detail = "Invalid Token")

        email = payload.get('sub')

    except JWTError:
        raise HTTPException(status_code= 401, detail = "Invalid or expired token")

    # find the user in the database
    password_reset_user = db.query(User).filter(User.email == email).first()

    if not password_reset_user:
        raise HTTPException(status_code = 404, detail = "User not found")

    # Update and commit new password
    password_reset_user.password_hashed = hash_password(new_password)
    db.add(password_reset_user) # sometimes this line is necessary
    db.commit()
    db.refresh(password_reset_user)

    return {"message": "Password has been reset successfully!!!"}

# ------------------------------------------------------------
# GET ALL USERS
# ------------------------------------------------------------

@app.get('/get-all-users')
def get_all_users_details(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme) , db: Session = Depends(getDb)):
    token = credentials.credentials

    try:
        # payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        payload = decode_token(token)

        #check expiry
        if payload.get('exp') and datetime.now(UTC).timestamp() > payload['exp']:
            raise HTTPException(status_code = 401, detail = "Token Expired")


        if payload.get('role').lower() != "admin" or 'superadmin':
            raise HTTPException(status_code=403, detail="Unauthorised User")

        users = db.query(User).all()

        return {
            "Total Users": len(users),
            "Data" : users
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Token Expired")


# ------------------------------------------------------------
# GET USER DETAILS
# ------------------------------------------------------------
# SHOW USER DETAILS USING TOKEN

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme), db: Session = Depends(getDb)):
    # extract token only without "Bearer "
    token = credentials.credentials
    try:
        # payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        payload = decode_token(token)
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code = 401, detail= "Invalid Token")

    except JWTError:
        raise HTTPException(status_code = 401, detail= "Unauthorised Token")

    # find user on the database using email
    user_details = db.query(User).filter(User.email == email).first()

    if not user_details:
        raise HTTPException(status_code = 404, detail = "User not found")

    return user_details

@app.get("/get-user", response_model = GetUser)
def get_user_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "branch": current_user.branch,
        "team": current_user.team,
        "role": current_user.role,
        "is_active": current_user.is_active
    }

# ------------------------------------------------------------
# UPDATE USER (EMPLOYEE IS ALLOWED TO UPDATE ONLY USERNAME, PASSWORD, AND EMAIL ( PASSWORD IS HANDLED SEPARATELY)
# ------------------------------------------------------------
# Why ONE API is Better
# Multiple APIs (BAD at scale)
# POST /user/update-email
# POST /user/update-password
# POST /user/update-role
# POST /user/update-status
#
# Problems:
# API explosion
# Hard to maintain
# Hard to version
# More frontend complexity
# More permissions logic duplicated

# Use ONE update API per resource (user), not separate APIs for each field.
# Use PATCH (partial update), not PUT.
# Benefits:
# Clean REST design
# Scales well
# Easy frontend integration
# Easier RBAC
# Easier auditing

@app.patch('/update-user/me')
def update_user_profile(new_data: UpdateUser = Body(...),db: Session = Depends(getDb), current_user: User = Depends(get_current_user)):
    updates = new_data.model_dump(exclude_unset = True)

    if not updates:
        return {"Message": "No updates"}

    # change/update only needed fields
    for field, value in updates.items():
        setattr(current_user, field, value)

    # allow only admins to change team, branch, role, active status of an employee

    db.commit()
    db.refresh(current_user)

    return {
        "message": "Update Successfully",
        "Updated fields": list(updates.keys())
    }

# ------------------------------------------------------------
# UPDATE USER (ADMIN IS ALLOWED TO UPDATE ONLY TEAM, BRANCH, AND ROLE)
# ------------------------------------------------------------
# @app.patch('/admin/edit-user')
# def edit_user_profile_admin(employee_id: int, credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme) ,db: Session = Depends(getDb)):



# ------------------------------------------------------------
# DELETE USER AFTER LOGIN BY ONLY ADMIN
# ------------------------------------------------------------

@app.delete("/delete-user/{employee_id}")
def delete_user(employee_id: int, credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme) ,db: Session = Depends(getDb)):
    # Delete the user by id and commit
    token = credentials.credentials


    # payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
    # checking token of logged user - i.e. admin
    payload = decode_token(token)

    role = payload.get('role').lower()

    if role != 'admin' or 'superadmin':
        raise HTTPException(status_code = 403, detail = 'Unauthorised User - Only admin or superadmin have access')

    admin_id = payload.get('id')


    if payload.get('exp') and datetime.now(UTC).timestamp() > payload['exp']:
        raise HTTPException(status_code = 401, detail = "Token Expired")

    # Avoid admin deleting himself/herself
    if admin_id == employee_id:
        raise HTTPException(status_code = 400, detail = "Admin cannot delete himself")

    # fetch deleting user from database
    deleting_user = db.query(User).filter(User.id == employee_id).first()

    if not deleting_user:
        raise HTTPException(status_code = 404, detail = "User not found")

    # if user is already deleted
    if not deleting_user.is_active:
        raise HTTPException(status_code = 404, detail = "User is already deleted")

    # One admin cannot delete another admin - Only a superadmin delete admin
    if deleting_user.role.lower() == 'admin':
        raise HTTPException(status_code = 404, detail = "One admin cannot delete another admin")

    # No one can delete superadmin
    if deleting_user.role.lower() == "superadmin":
        raise HTTPException(status_code = 403, detail = "Unauthorised to delete superadmin")

    # safe delete - deactivating employee
    deleting_user.is_active = False

    # Audit log
    log = AuditLog(
        action = "Delete_user",
        performed_by = db.query(User.username).filter(User.id == admin_id).first(),
        target_user = deleting_user.username
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    db.refresh(deleting_user)

    return {"message": "User Deleted Successfully"}


# ------------------------------------------------------------
# RESTORE USER AFTER DELETED BY ONLY ADMIN AND SUPERADMIN
# ------------------------------------------------------------

@app.put('/restore-user/{employee_id}')
def restore_user(employee_id: int, credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme), db: Session = Depends(getDb)):
    token = credentials.credentials

    payload = decode_token(token)

    if payload.get('role').lower() != 'admin':
        raise HTTPException(status_code = 401, detail = "Not authorised to do this action")

    restoring_user = db.query(User).filter(User.id == employee_id).first()

    # admin cannot restore himself/herself
    if payload.get('id') == restoring_user.id:
        raise HTTPException(status_code = 401, detail = 'Superadmin or other admin have access to restore another admin' )

    if restoring_user.is_active:
        raise HTTPException(status_code = 401, detail="User is active")

    if not restoring_user:
        raise HTTPException(status_code = 404, detail="User not found")

    restoring_user.is_active = True

    db.add(restoring_user)
    db.commit()
    db.refresh(restoring_user)

    return {"message": "User restored successfully"}


