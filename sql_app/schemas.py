from typing import List, Optional
from datetime import date
from pydantic import BaseModel
from sqlalchemy.sql.sqltypes import Boolean
from uuid import UUID
from datetime import datetime


class SubmitIndicator(BaseModel):
    indicator: str


class AuthBase(BaseModel):
    username: str


class AuthCreate(AuthBase):
    password: str
    account_active: bool


class AuthUpdateStatus(AuthBase):
    account_active: bool

    class Config:
        orm_mode = True


class AuthUpdatePassword(AuthBase):
    password: str

    class Config:
        orm_mode = True


class Auth(AuthBase):
    class Config:
        orm_mode = True


class LoggingBase(BaseModel):
    username: str


class LoggingCreate(LoggingBase):
    page: str
    data_size: int
    endpoint: str
    parameters: str
    user_agent: str
    ip_address: str


class Logging(LoggingBase):
    id: UUID

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []
    expires: Optional[datetime]
