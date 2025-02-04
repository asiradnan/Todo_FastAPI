from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager
from db import create_db_and_tables, get_session
from typing import Annotated
from sqlmodel import Session, select
from models import Task, TaskCreate, TaskUpdate, TaskPublic
from models import User, UserCreate, UserUpdate, UserPublic, Token, Passwords
from auth import create_refresh_token, verify_password, authenticate_user, create_access_token, get_password_hash, UserDep, get_user, get_current_user_by_refresh_token
import os
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from dotenv import load_dotenv
import jwt
from jwt.exceptions import InvalidTokenError
from pydantic import EmailStr
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("PRODUCTION") != "true" else None,
    redoc_url="/redoc" if os.getenv("PRODUCTION") != "true" else None
)
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)
SessionDep = Annotated[Session, Depends(get_session)]
ACCESS_TOKEN_EXPIRE_MINUTES = 30
conf = ConnectionConfig(
    MAIL_USERNAME = os.getenv("EMAIL"),
    MAIL_FROM = os.getenv("EMAIL"),
    MAIL_PASSWORD =os.getenv("EMAIL_PASSWORD"),
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False
)


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post("/create_account", status_code=201)
async def create_account(user: UserCreate, session: SessionDep) -> UserPublic:
    lookup_user_by_username = select(User).where(User.username == user.username)
    existing_user = session.exec(lookup_user_by_username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username is already taken")
    lookup_user_by_email = select(User).where(User.email == user.email)
    existing_user = session.exec(lookup_user_by_email).first()
    if user.email and existing_user:
        raise HTTPException(status_code=400, detail="Email is already taken")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password, email=user.email)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user


@app.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDep) -> Token:
    user = authenticate_user(form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)}, expires_delta=timedelta(days=7)
    )
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")

@app.post("/refresh_token")
async def refresh_token(refresh_token: dict, session: SessionDep) -> Token:
    user = await get_current_user_by_refresh_token(refresh_token["refresh_token"], session=session)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    refresh_token_expires = timedelta(days=7)
    refresh_token = create_refresh_token(
        data={"sub": str(user.id)}, expires_delta=refresh_token_expires
    )
    return Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@app.get("/me", response_model=UserPublic)
async def me(current_user: UserDep):
    return current_user


@app.post("/update_user", status_code=201)
async def update_user(current_user: UserDep, user_infos: UserUpdate, session: SessionDep) -> dict:
    if user_infos.username:
        lookup_user_by_username = select(User).where(User.username == user_infos.username)
        existing_user = session.exec(lookup_user_by_username).first()
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Username is already taken")
    if user_infos.email:
        lookup_user_by_email = select(User).where(User.email == user_infos.email)
        existing_user = session.exec(lookup_user_by_email).first()
        if user_infos.email and existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=400, detail="Email is already taken")
    username_changed = False
    if user_infos.username:
        current_user.username = user_infos.username
        username_changed = True
    if user_infos.email:
        if current_user.email != user_infos.email:
            current_user.verified = False
        current_user.email = user_infos.email
    user = UserPublic.model_validate(current_user)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    if username_changed:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(current_user.id)}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer", "user": user }
    return {"user": user}


@app.post("/change_password", status_code=201, response_model=UserPublic)
async def change_password(current_user: UserDep, passwords: Passwords, session: SessionDep):
    if not verify_password(passwords.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    hashed_password = get_password_hash(passwords.new_password)
    current_user.hashed_password = hashed_password
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user




@app.get("/remove_email", status_code=200)
async def remove_email(current_user: UserDep, session: SessionDep) -> dict:
    current_user.email = None
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return {"message": "Email removed successfully"}


@app.post("/get_verify_token")
async def get_verify_token(current_user: UserDep) ->  dict:
    if not current_user.email:
        raise HTTPException(status_code=400, detail="Email is not provided")
    verify_token_expires = timedelta(hours=1)
    verify_token = create_access_token(
        data={"sub": current_user.username}, expires_delta=verify_token_expires
    )
    template = f"""
        <html>
        <body>
        <h1>Email Verification</h1>
        <p> Please add the following token to your application to verify your email address</p>
        <p> {verify_token} </p>
        """
    message = MessageSchema(
        subject="Confirm Email",
        recipients=[current_user.email],
        body=template,
        subtype="html"
        )
    fm = FastMail(conf)
    await fm.send_message(message)
    return {"message": "email has been sent"}


@app.post("/verify_email")
async def verify_email(verify_token: str, session: SessionDep):
    try:
        payload = jwt.decode(verify_token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        username: str = payload.get("sub")
        user = get_user(username, session)
        user.verified = True
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"message": "email verified"}
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")
    

@app.get("/get_password_reset_token")
async def get_password_reset_token(email: EmailStr, session:  SessionDep) -> dict:
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    password_reset_token_expires = timedelta(hours=1)
    password_reset_token = create_access_token(
        data={"sub": user.username}, expires_delta=password_reset_token_expires
    )
    template = f"""
    <html>
    <body>
    <h1>Password Reset</h1>
    <p> Please add the following token to your application to reset your password</p>
    <p> {password_reset_token} </p>
    """
    message = MessageSchema(
        subject="Reset Password",
        recipients=[user.email],
        body=template,
        subtype="html"
        )
    fm = FastMail(conf)
    await fm.send_message(message)
    return {"message": "email has been sent"}


@app.post("/reset_password")
async def reset_password(password_reset_token: str, new_password: str, session: SessionDep):
    try:
        payload = jwt.decode(password_reset_token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")])
        username: str = payload.get("sub")
        user = get_user(username, session)
        hashed_password = get_password_hash(new_password)
        user.hashed_password = hashed_password
        session.add(user)
        session.commit()
        session.refresh(user)
        return {"message": "password reset"}
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token")


@app.post("/add_task", status_code=201)
def create_task(task_received: TaskCreate, session: SessionDep, current_user : UserDep) -> TaskPublic:
    new_task = Task(description=task_received.description, due_date = task_received.due_date, due_time=task_received.due_time, user_id=current_user.id)
    session.add(new_task)
    session.commit()
    session.refresh(new_task)
    return new_task


@app.get("/get_tasks", status_code=200)
def get_tasks(session: SessionDep, current_user: UserDep) -> list[TaskPublic]:
    tasks = session.exec(select(Task).where(Task.user_id == current_user.id)).all()
    return tasks


@app.put("/edit_task/{task_id}", status_code=200)
def edit_task(task_id: int, task: TaskUpdate, session: SessionDep, current_user: UserDep) -> TaskPublic:
    current_task = session.get(Task, task_id)
    if not current_task:
        return HTTPException(status_code=404, detail = "Task not found!")
    if current_task.user_id != current_user.id:
        raise HTTPException(status_code=403, detail = "User not authorized to edit this task!")
    task_data = task.model_dump(exclude_unset=True)
    current_task.sqlmodel_update(task_data)
    if task.delete_date:
        current_task.due_date = None
    if task.delete_time:
        current_task.due_time = None
    session.add(current_task)
    session.commit()
    session.refresh(current_task)
    return current_task


@app.delete("/delete/{task_id}", status_code=200)
def delete_task(task_id: int, session: SessionDep, current_user: UserDep) -> dict:
    task = session.get(Task, task_id)
    if not task:
        return HTTPException(status_code=404, detail = "Task not found!")
    if task.user_id != current_user.id:
        raise HTTPException(status_code=403, detail = "User not authorized to delete this task!")
    session.delete(task)
    session.commit()
    return {"deleted" : True}


@app.delete("/delete_all_completed", status_code=200)
def delete_task(session: SessionDep, current_user: UserDep) -> dict:
    statement = select(Task).where(Task.completed == True, Task.user_id == current_user.id)
    tasks = session.exec(statement).all()
    for task in tasks:
        session.delete(task)
    session.commit()
    return {"all completed tasks deleted" : True}