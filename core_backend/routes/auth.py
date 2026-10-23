from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import hashlib
import logging
import re
import uuid

import jwt

from ..models import User, Session as SessionModel
from ..schemas import RefreshTokenRequest, TokenRequest, TokenResponse, UserResponse
from ..database import get_db
from ..security import (
    DUMMY_HASH, failed_logins_per_account, get_secret_key, hash_password, login_attempts_per_ip,
    needs_rehash, registrations_per_ip, verify_password,
)

logger = logging.getLogger(__name__)


class HTTPAuthCredentials(BaseModel):
    scheme: str
    credentials: str


router = APIRouter(prefix="/api/auth", tags=["authentication"])
security = HTTPBearer()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_PASSWORD_LENGTH = 256


def _encode(payload: dict) -> str:
    return jwt.encode(payload, get_secret_key(), algorithm=ALGORITHM)


def _decode(token: str) -> dict:
    return jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM], options={"require": ["exp", "sub", "type"]})


def create_access_token(user_id: str, expires_delta: timedelta = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return _encode({"sub": user_id, "type": "access", "exp": expire, "jti": uuid.uuid4().hex})


def create_refresh_token(user_id: str):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return _encode({"sub": user_id, "type": "refresh", "exp": expire, "jti": uuid.uuid4().hex})


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _too_many(retry_after: int):
    raise HTTPException(
        status_code=429,
        detail=f"Too many attempts. Try again in {max(1, retry_after // 60)} minute(s).",
        headers={"Retry-After": str(retry_after)},
    )


def _issue_tokens(user: User, db: Session, user_agent: str = None) -> TokenResponse:
    refresh_token = create_refresh_token(str(user.id))
    db.add(SessionModel(
        user_id=user.id,
        token_hash=_token_hash(refresh_token),
        user_agent=(user_agent or "")[:500] or None,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    db.commit()
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


def verify_token(credentials: HTTPAuthCredentials, db: Session):
    """Validate an access token and return the user id. Refresh tokens and inactive users are rejected."""
    try:
        payload = _decode(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user_id = payload.get("sub")
    try:
        uuid.UUID(str(user_id))
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User.status).filter(User.id == user_id).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=401, detail="Account not found or inactive")
    return user_id


def _username_for(email: str) -> str:
    local = re.sub(r"[^a-zA-Z0-9._-]", "", email.split("@")[0])[:80] or "user"
    return f"{local}-{uuid.uuid4().hex[:8]}"


@router.post("/register", response_model=UserResponse)
async def register(user_data: TokenRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    wait = registrations_per_ip.retry_after(ip)
    if wait:
        _too_many(wait)
    registrations_per_ip.hit(ip)

    if len(user_data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if len(user_data.password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    email = user_data.email.lower()
    if db.query(User).filter(func.lower(User.email) == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(email=email, username=_username_for(email), password_hash=hash_password(user_data.password), status="active")
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")
    except Exception:
        db.rollback()
        logger.exception("Registration failed")
        raise HTTPException(status_code=500, detail="Registration failed. Please try again.")
    db.refresh(new_user)
    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(credentials: TokenRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    email = credentials.email.lower()
    account_key = (email, ip)
    wait = max(login_attempts_per_ip.retry_after(ip), failed_logins_per_account.retry_after(account_key))
    if wait:
        _too_many(wait)
    login_attempts_per_ip.hit(ip)

    user = db.query(User).filter(func.lower(User.email) == email).first()
    password = credentials.password[:MAX_PASSWORD_LENGTH]
    valid = verify_password(password, user.password_hash if user else DUMMY_HASH) and user is not None
    if not valid:
        failed_logins_per_account.hit(account_key)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="User account is inactive")

    failed_logins_per_account.reset(account_key)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.utcnow()
    return _issue_tokens(user, db, request.headers.get("user-agent"))


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(request_data: RefreshTokenRequest, request: Request, db: Session = Depends(get_db)):
    refresh_token = request_data.refresh_token
    try:
        payload = _decode(refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    session = db.query(SessionModel).filter(SessionModel.token_hash == _token_hash(refresh_token)).first()
    if session and session.invalidated_at is not None:
        # A rotated token was presented again: treat it as stolen and end every session of this user.
        db.query(SessionModel).filter(SessionModel.user_id == session.user_id, SessionModel.invalidated_at.is_(None)) \
            .update({SessionModel.invalidated_at: datetime.utcnow()}, synchronize_session=False)
        db.commit()
        logger.warning(f"Refresh token reuse detected for user {session.user_id}; all sessions revoked")
        raise HTTPException(status_code=401, detail="Session revoked")
    if not session or session.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=401, detail="Session revoked or expired")

    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or user.status != "active":
        raise HTTPException(status_code=401, detail="User not found or inactive")

    session.invalidated_at = datetime.utcnow()
    return _issue_tokens(user, db, request.headers.get("user-agent"))


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    return db.query(User).filter(User.id == user_id).first()


@router.post("/logout")
async def logout(
    request_data: RefreshTokenRequest,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    revoked = db.query(SessionModel).filter(
        SessionModel.user_id == user_id,
        SessionModel.token_hash == _token_hash(request_data.refresh_token),
        SessionModel.invalidated_at.is_(None)
    ).update({SessionModel.invalidated_at: datetime.utcnow()}, synchronize_session=False)
    db.commit()

    return {"message": "Logged out successfully", "sessions_revoked": revoked}
