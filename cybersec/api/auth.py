"""
Authentication utilities (hashing, JWT).
"""
import bcrypt

# Patch bcrypt.hashpw to bypass passlib's internal wrap-bug detection crash,
# which tests with a 255-byte secret breaking bcrypt >= 4.0.0 on python 3.13.
_original_hashpw = getattr(bcrypt, "hashpw")
def _mocked_hashpw(password: bytes, salt: bytes | None = None) -> bytes:
    if len(password) > 72:
        return _original_hashpw(password[:72], salt)
    return _original_hashpw(password, salt)
bcrypt.hashpw = _mocked_hashpw

from datetime import datetime, timedelta, timezone
from uuid import UUID

from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from cybersec.config import settings
from cybersec.api.schemas.user import TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.APP_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = TokenData(user_id=UUID(user_id_str))
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data
