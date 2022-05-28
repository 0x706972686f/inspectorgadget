from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from sqlalchemy import and_
from . import models, schemas
from jose import JWTError, jwt
from datetime import datetime, timedelta, date
import uuid


def get_username(db: Session, username: str):
    return db.query(models.Auth).filter(models.Auth.username == username).first()


def get_user_details_by_name(db: Session, username: str):
    return (
        db.query(
            models.Auth.username,
            models.Auth.account_active,
            models.Auth.account_admin,
            models.Auth.created_date,
            models.Auth.id,
        )
        .filter(models.Auth.username == username)
        .one()
    )


# Not implemented yet
def get_user_details_by_id(db: Session, user_id: uuid):
    return (
        db.query(
            models.Auth.username,
            models.Auth.account_active,
            models.Auth.account_admin,
            models.Auth.created_date,
            models.Auth.id,
        )
        .filter(models.Auth.id == user_id)
        .one()
    )


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return (
        db.query(
            models.Auth.id,
            models.Auth.username,
            models.Auth.created_date,
            models.Auth.account_active,
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_all_logs(db: Session, skip: int = 0, limit: int = 100):
    return (
        db.query(
            models.Logging.username,
            models.Logging.endpoint,
            models.Logging.parameters,
            models.Logging.user_agent,
            models.Logging.ip_address,
            models.Logging.query_date,
            models.Logging.data_size,
            models.Logging.page,
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_user_logs(db: Session, username: str, skip: int = 0, limit: int = 100):
    return (
        db.query(
            models.Logging.endpoint,
            models.Logging.parameters,
            models.Logging.user_agent,
            models.Logging.ip_address,
            models.Logging.query_date,
            models.Logging.data_size,
            models.Logging.page,
        )
        .filter(models.Logging.username == username)
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_all_users_report(
    db: Session,
    start_date: date = date.today() - timedelta(weeks=4),
    end_date: date = date.today(),
    skip: int = 0,
    limit: int = 100,
):
    return (
        db.query(
            models.Logging.username,
            models.Logging.page,
            func.count(models.Logging.data_size).label("api_calls"),
            func.sum(models.Logging.data_size).label("data_total"),
        )
        .filter(
            and_(
                models.Logging.query_date >= start_date,
                models.Logging.query_date <= end_date,
            )
        )
        .group_by(models.Logging.username, models.Logging.page)
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_user_report(
    db: Session,
    username: str,
    start_date: date = date.today() - timedelta(weeks=4),
    end_date: date = date.today(),
    skip: int = 0,
    limit: int = 100,
):
    return (
        db.query(
            models.Logging.username,
            models.Logging.page,
            func.count(models.Logging.data_size).label("api_calls"),
            func.sum(models.Logging.data_size).label("data_total"),
        )
        .filter(
            and_(
                models.Logging.username == username,
                models.Logging.query_date >= start_date,
                models.Logging.query_date <= end_date,
            )
        )
        .group_by(models.Logging.username, models.Logging.page)
        .offset(skip)
        .limit(limit)
        .all()
    )


def add_log(db: Session, log: schemas.LoggingCreate):
    db_user = models.Logging(
        username=log.username,
        endpoint=log.endpoint,
        page=log.page,
        data_size=log.data_size,
        parameters=log.parameters,
        user_agent=log.user_agent,
        ip_address=log.ip_address,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_user(db: Session, user: schemas.AuthCreate):
    db_user = models.Auth(
        username=user.username,
        password=user.password,
        account_active=user.account_active,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_status(db: Session, user: schemas.AuthUpdateStatus):
    db_user = (
        db.query(models.Auth).filter(models.Auth.username == user.username).first()
    )
    if not db_user:
        return None

    setattr(db_user, "account_active", user.account_active)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_password(db: Session, user: schemas.AuthUpdatePassword):
    db_user = (
        db.query(models.Auth).filter(models.Auth.username == user.username).first()
    )
    if not db_user:
        return None

    setattr(db_user, "password", user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
