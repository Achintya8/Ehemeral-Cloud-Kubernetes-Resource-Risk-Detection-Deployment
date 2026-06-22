from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from backend.database import get_user_by_username


# JWT signing secret. Read from JWT_SECRET_KEY env var; falls back to a dev
# default. NEVER rely on the default in production — set JWT_SECRET_KEY.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me-in-production-hackathon-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 12 * 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: Dict[str, Any], expires_delta_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_delta_minutes)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc


def authenticate_user(username: str, password: str):
    print(f"DEBUG auth.py: authenticate_user called for '{username}'")
    user = get_user_by_username(username)
    print(f"DEBUG auth.py: user found in DB: {user is not None}")
    if not user:
        return None
    try:
        pw_ok = verify_password(password, user["hashed_password"])
        print(f"DEBUG auth.py: password verification ok: {pw_ok}")
    except Exception as e:
        print(f"DEBUG auth.py: Exception during verify_password: {e}")
        raise e
    if not pw_ok:
        return None
    return user



def _extract_bearer_token(request: Request, credentials: HTTPAuthorizationCredentials | None):
    if credentials and credentials.credentials:
        return credentials.credentials
    header_value = request.headers.get("authorization", "")
    if header_value.lower().startswith("bearer "):
        return header_value.split(" ", 1)[1].strip()
    return None


def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
    token = _extract_bearer_token(request, credentials)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_admin(current_user=Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user
