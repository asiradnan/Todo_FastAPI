from sqlmodel import Field, SQLModel
from datetime import date, time
from pydantic import EmailStr

class TaskBase(SQLModel):
    description: str
    due_date: date | None = None
    due_time: time | None = None
    priority: int | None = 0

class Task(TaskBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    completed: bool | None = False

class TaskCreate(TaskBase):
    pass

class TaskUpdate(SQLModel):
    description: str | None = None
    completed: bool | None = None
    due_date: date | None = None
    due_time: time | None = None
    priority: int | None = None

class TaskPublic(TaskBase):
    id: int
    completed: bool

class UserBase(SQLModel):
    username: str = Field(unique=True, index=True)
    email: EmailStr | None = Field(default=None, unique=True)
    
class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    hashed_password: str
    verified: bool = False

class UserCreate(UserBase):
    password: str

class UserUpdate(SQLModel):
    username: str | None = None
    email: EmailStr | None = None 

class UserPublic(UserBase):
    id: int
    verified: bool

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    id: str | None = None