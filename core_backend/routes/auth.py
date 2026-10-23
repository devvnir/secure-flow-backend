from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import hashlib
import uuid
from ..models import User, Session as SessionModel
from ..schemas import RefreshTokenRequest, TokenRequest, TokenResponse, UserResponse
from ..database import get_db
import os

class HTTPAuthCredentials(BaseModel):
    scheme: str
    credentials: str

router = APIRouter(prefix="/api/auth", tags=["authentication"])
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

def create_access_token(user_id: str, expires_delta: timedelta = None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {"sub": user_id, "exp": expire}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(user_id: str):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": user_id, "type": "refresh", "exp": expire, "jti": uuid.uuid4().hex}
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def _issue_tokens(user: User, db: Session, user_agent: str = None) -> TokenResponse:
    refresh_token = create_refresh_token(str(user.id))
    db.add(SessionModel(
        user_id=user.id,
        token_hash=_token_hash(refresh_token),
        user_agent=user_agent,
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    db.commit()
    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

def verify_token(credentials: HTTPAuthCredentials, db: Session):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

@router.post("/register", response_model=UserResponse)
async def register(user_data: TokenRequest, db: Session = Depends(get_db)):
    if len(user_data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    try:
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")

        new_user = User(
            email=user_data.email,
            username=user_data.email.split("@")[0],
            password_hash=hash_password(user_data.password),
            status="active"
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")
    return new_user

@router.post("/login", response_model=TokenResponse)
async def login(credentials: TokenRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or user.password_hash != hash_password(credentials.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.status != "active":
        raise HTTPException(status_code=403, detail="User account is inactive")

    user.last_login_at = datetime.utcnow()
    return _issue_tokens(user, db, request.headers.get("user-agent"))

@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(request_data: RefreshTokenRequest, request: Request, db: Session = Depends(get_db)):
    refresh_token = request_data.refresh_token
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    session = db.query(SessionModel).filter(
        SessionModel.token_hash == _token_hash(refresh_token),
        SessionModel.invalidated_at.is_(None),
        SessionModel.expires_at > datetime.utcnow()
    ).first()
    if not session:
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
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

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
