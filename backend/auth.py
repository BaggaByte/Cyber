import jwt
from datetime import datetime, timedelta
import bcrypt
import os

# SECRET_KEY is REQUIRED — the API will refuse to start without it.
# Generate with: openssl rand -hex 32
# Never use a default or fallback value.
SECRET_KEY = os.environ["SECRET_KEY"]  # Raises KeyError at startup if not set — intentional
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # Tokens last for 2 hours

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Checks if the plaintext password matches the hashed database string."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Converts a plaintext password into a secure bcrypt hash."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict) -> str:
    """Packs user data (like org_id and role) into a secure, signed JWT token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

from fastapi import HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def get_current_user(request: Request):
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]

    if not token:
        token = request.cookies.get("token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
