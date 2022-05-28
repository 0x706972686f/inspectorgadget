from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from typing import List
from datetime import datetime, timedelta, date
from pydantic import ValidationError
from sqlalchemy.orm import Session
from fastapi import Depends, FastAPI, HTTPException, Security, status, Request
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from fastapi.responses import ORJSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from sql_app import crud, models, schemas
from sql_app.database import SessionLocal, engine
from typing import Optional
from passlib.context import CryptContext
from starlette.routing import Match
from starlette.status import HTTP_504_GATEWAY_TIMEOUT
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from utils import secrets
from worker import get_ipv4_ioc, get_sha256_ioc, get_url_ioc
from celery.result import AsyncResult
import json
import sys
import pytz
import time
import asyncio

##############################################################################

REQUEST_TIMEOUT_ERROR = 1
SERVER_STARTUP_TIME = datetime.utcnow().replace(tzinfo=pytz.utc)

models.Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/authenticate", scopes=secrets.OAUTH2_SCOPES
)

limiter = Limiter(key_func=get_remote_address)
# Can turn off OpenAPI docs and similar by changing the parameters
# app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, include_in_schema=False)
app = FastAPI(default_response_class=ORJSONResponse)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

##############################################################################


@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    try:
        start_time = time.time()
        return await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT_ERROR)

    except asyncio.TimeoutError:
        process_time = time.time() - start_time
        return ORJSONResponse(
            {
                "detail": "Request processing time excedeed limit",
                "processing_time": process_time,
            },
            status_code=HTTP_504_GATEWAY_TIMEOUT,
        )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(input_password, db_password):
    return pwd_context.verify(input_password, db_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(
    db: Session,
    username: str,
    password: str,
):
    user = crud.get_username(db, username=username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secrets.SECRET_KEY, algorithm=secrets.ALGORITHM)
    return encoded_jwt


async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = f"Bearer"
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": {authenticate_value}},
        )
    try:
        payload = jwt.decode(token, secrets.SECRET_KEY, algorithms=[secrets.ALGORITHM])
        username: str = payload.get("sub")
        expires = payload.get("exp")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = schemas.TokenData(
            scopes=token_scopes, username=username, expires=expires
        )
    except (JWTError, ValidationError):
        raise credentials_exception
    user = crud.get_username(db, username=token_data.username)
    if expires is None:
        raise credentials_exception
    if datetime.utcnow().replace(tzinfo=pytz.utc) > token_data.expires:
        raise credentials_exception
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: schemas.Auth = Security(get_current_user, scopes=["users"])
):
    if not current_user.account_active:
        raise HTTPException(status_code=400, detail="Invalid user")
    return current_user


async def get_current_active_admin_user(
    current_user: schemas.Auth = Security(get_current_user, scopes=["users"])
):
    if not current_user.account_admin and current_user.account_active:
        raise HTTPException(status_code=400, detail="Invalid user")
    return current_user


def log_request(
    request: Request,
    db: Session,
    user: schemas.Auth,
    page: str,
    data_size: int,
    form_data: OAuth2PasswordRequestForm,
):
    new_log = schemas.LoggingCreate(
        username=user.username,
        page=page,
        data_size=data_size,
        endpoint=str(request.method) + " " + str(request.url),
        parameters="None",
        user_agent=request.headers.get("user-agent")
        + " "
        + request.headers.get("accept-language"),
        ip_address=request.headers.get("host"),
    )
    if form_data:
        new_log.parameters = str(form_data)
    crud.add_log(db=db, log=new_log)


@app.post("/api/authenticate", response_model=schemas.Token)
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    input_data = {"username": form_data.username, "status": "success"}
    access_token_expires = timedelta(minutes=secrets.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scopes": form_data.scopes},
        expires_delta=access_token_expires,
    )
    results = {"access_token": access_token, "token_type": "bearer"}
    log_request(
        request, db, user, "authenticate", sys.getsizeof(results), str(input_data)
    )
    return results


@app.get("/api/uptime")
@limiter.limit("5/minute")
async def server_uptime(request: Request):
    results = {
        "start_time": SERVER_STARTUP_TIME.strftime("%H:%M:%S %Z %Y-%m-%d"),
        "uptime": (
            datetime.utcnow().replace(tzinfo=pytz.utc) - SERVER_STARTUP_TIME
        ).total_seconds(),
        "status": "functional",
    }
    return results


@app.get("/api/verify", response_model=schemas.Auth)
@limiter.limit("5/minute")
async def verify_login(
    request: Request, current_user: schemas.Auth = Depends(get_current_active_user)
):
    results = {
        "username": current_user.username,
        "logged_in": True,
        "start_time": SERVER_STARTUP_TIME.strftime("%H:%M:%S %Z %Y-%m-%d"),
        "uptime": (
            datetime.utcnow().replace(tzinfo=pytz.utc) - SERVER_STARTUP_TIME
        ).total_seconds(),
        "status": "functional",
    }
    return results


@app.get("/api/admin/users")
async def get_users(
    request: Request,
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_users(db, offset)
    log_request(
        request,
        db,
        current_user,
        "admin/users",
        sys.getsizeof(db_query_results),
        "None",
    )
    return db_query_results


@app.post("/api/admin/user", response_model=schemas.Auth)
async def create_user(
    user: schemas.AuthCreate,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_user = crud.get_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user.password = get_password_hash(user.password)
    return crud.create_user(db=db, user=user)


@app.get("/api/admin/user/{username}")
async def get_user_details(
    request: Request,
    username,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_user_details_by_name(db, username)
    log_request(
        request,
        db,
        current_user,
        f"admin/user/{username}",
        sys.getsizeof(db_query_results),
        "None",
    )
    return db_query_results


@app.patch("/api/admin/user/status", response_model=schemas.AuthUpdateStatus)
async def update_user_status(
    request: Request,
    user: schemas.AuthUpdateStatus,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_user = crud.update_user_status(db, user)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid User Account")
    return db_user


@app.patch("/api/admin/user/password")
async def update_user_password(
    request: Request,
    user: schemas.AuthUpdatePassword,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    user.password = get_password_hash(user.password)
    db_user = crud.update_user_password(db, user)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid User Account")

    password_updated = {"username": db_user.username, "status": "success"}
    return password_updated


@app.get("/api/admin/logs")
async def get_all_user_logs(
    request: Request,
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_all_logs(db, offset)
    log_request(
        request, db, current_user, "admin/logs", sys.getsizeof(db_query_results), "None"
    )
    return db_query_results


@app.get("/api/admin/log/{username}")
async def get_user_logs(
    request: Request,
    username: str,
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_user_logs(db, username, offset)
    log_request(
        request,
        db,
        current_user,
        f"admin/log/{username}",
        sys.getsizeof(db_query_results),
        "None",
    )
    return db_query_results


@app.get("/api/admin/reports")
async def get_users_reports(
    request: Request,
    start_date: Optional[date] = date.today() - timedelta(weeks=4),
    end_date: Optional[date] = date.today(),
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_all_users_report(db, start_date, end_date, offset)
    log_request(
        request,
        db,
        current_user,
        "admin/reports",
        sys.getsizeof(db_query_results),
        "None",
    )
    return db_query_results


@app.get("/api/admin/report/{username}")
async def get_user_report(
    request: Request,
    username: str,
    start_date: Optional[date] = date.today() - timedelta(weeks=4),
    end_date: Optional[date] = date.today(),
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(
        get_current_active_admin_user, scopes=["mon"]
    ),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_user_report(db, username, start_date, end_date, offset)
    log_request(
        request,
        db,
        current_user,
        f"admin/reports/{username}",
        sys.getsizeof(db_query_results),
        "None",
    )
    return db_query_results


@app.get("/api/me")
async def get_my_status(
    request: Request,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["users"]),
    db: Session = Depends(get_db),
):
    results = {
        "username": current_user.username,
        "start_time": SERVER_STARTUP_TIME.strftime("%H:%M:%S %Z %Y-%m-%d"),
        "uptime": (
            datetime.utcnow().replace(tzinfo=pytz.utc) - SERVER_STARTUP_TIME
        ).total_seconds(),
        "status": "functional",
    }
    return results


@app.get("/api/me/usage")
async def get_my_report(
    request: Request,
    start_date: Optional[date] = date.today() - timedelta(weeks=4),
    end_date: Optional[date] = date.today(),
    offset: Optional[int] = 0,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["users"]),
    db: Session = Depends(get_db),
):
    db_query_results = crud.get_user_report(
        db, current_user.username, start_date, end_date, offset
    )
    log_request(
        request, db, current_user, f"me/report", sys.getsizeof(db_query_results), "None"
    )
    return db_query_results


@app.patch("/api/me/password")
async def update_my_password(
    request: Request,
    password: str,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["users"]),
    db: Session = Depends(get_db),
):
    user = crud.get_username(db, username=current_user.username)
    user.password = get_password_hash(password)
    db_user = crud.update_user_password(db, user)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid User Account")

    password_updated = {"username": db_user.username, "status": "success"}
    return password_updated


@app.post("/api/indicator/ipv4")
async def create_ipv4_task(
    request: Request,
    indicator: schemas.SubmitIndicator,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    # print(indicator)
    task = get_ipv4_ioc.delay(indicator.indicator)
    log_request(
        request,
        db,
        current_user,
        "api/indicator/ipv4",
        sys.getsizeof(task.id),
        {"indicator": indicator.indicator},
    )
    return ORJSONResponse({"task_id": task.id})


@app.get("/api/indicator/ipv4/{task_id}")
async def get_ipv4_task(
    request: Request,
    task_id,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    task_result = AsyncResult(task_id)

    if task_result.status == "SUCCESS":
        task_result.result["status"] = task_result.status
        task_result.result["task_id"] = task_id
        log_request(
            request,
            db,
            current_user,
            "api/indicator/ipv4",
            sys.getsizeof(task_result.result),
            {"task_id": task_id},
        )
        return Response(json.dumps(task_result.result))
    else:
        result = {
            "task_id": task_id,
            "task_status": task_result.status,
            "task_result": task_result.result,
        }
        log_request(
            request,
            db,
            current_user,
            "api/indicator/ipv4",
            sys.getsizeof(result),
            {"task_id": task_id},
        )
        return result


@app.post("/api/indicator/url")
async def create_url_task(
    request: Request,
    indicator: schemas.SubmitIndicator,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    task = get_url_ioc.delay(indicator.indicator)
    log_request(
        request,
        db,
        current_user,
        "api/indicator/url",
        sys.getsizeof(task.id),
        {"indicator": indicator.indicator},
    )
    return ORJSONResponse({"task_id": task.id})


@app.get("/api/indicator/url/{task_id}")
async def get_url_task(
    request: Request,
    task_id,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    task_result = AsyncResult(task_id)

    if task_result.status == "SUCCESS":
        task_result.result["status"] = task_result.status
        task_result.result["task_id"] = task_id
        log_request(
            request,
            db,
            current_user,
            "api/indicator/url",
            sys.getsizeof(task_result.result),
            {"task_id": task_id},
        )
        return Response(json.dumps(task_result.result))
    else:
        result = {
            "task_id": task_id,
            "task_status": task_result.status,
            "task_result": task_result.result,
        }
        log_request(
            request,
            db,
            current_user,
            "api/indicator/url",
            sys.getsizeof(result),
            {"task_id": task_id},
        )
        return result


@app.post("/api/indicator/sha256")
async def create_sha256_task(
    request: Request,
    indicator: schemas.SubmitIndicator,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    # print(indicator)
    task = get_sha256_ioc.delay(indicator.indicator)
    log_request(
        request,
        db,
        current_user,
        "api/indicator/sha256",
        sys.getsizeof(task.id),
        {"indicator": indicator.indicator},
    )
    return ORJSONResponse({"task_id": task.id})


@app.get("/api/indicator/sha256/{task_id}")
async def get_sha256_task(
    request: Request,
    task_id,
    current_user: schemas.Auth = Security(get_current_active_user, scopes=["tasks"]),
    db: Session = Depends(get_db),
):
    task_result = AsyncResult(task_id)

    if task_result.status == "SUCCESS":
        task_result.result["status"] = task_result.status
        task_result.result["task_id"] = task_id
        log_request(
            request,
            db,
            current_user,
            "api/indicator/sha256",
            sys.getsizeof(task_result.result),
            {"task_id": task_id},
        )
        return Response(json.dumps(task_result.result))
    else:
        result = {
            "task_id": task_id,
            "task_status": task_result.status,
            "task_result": task_result.result,
        }
        log_request(
            request,
            db,
            current_user,
            "api/indicator/sha256",
            sys.getsizeof(result),
            {"task_id": task_id},
        )
        return result


@app.get("/index", response_class=HTMLResponse)
async def read_item(request: Request):
    return templates.TemplateResponse("item.html", {"request": request})
