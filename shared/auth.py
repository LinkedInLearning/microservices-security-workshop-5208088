from fastapi import HTTPException, Security, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import jwt as PyJWT
from datetime import datetime, timedelta
import os
from passlib.context import CryptContext
import time
from slowapi import Limiter
from slowapi.util import get_remote_address

# Security configurations
pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__type="id",  # Use Argon2id
    argon2__memory_cost=65536,  # 64MB
    argon2__time_cost=3,  # Number of iterations
    argon2__parallelism=4,  # Number of parallel threads
    deprecated="auto"
)
limiter = Limiter(key_func=get_remote_address)

# Get secrets from environment variables
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable must be set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: str = Field(..., pattern="^(admin|user)$")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class User(UserBase):
    disabled: bool = False

    class Config:
        orm_mode = True

# Hardcoded users for demo purposes - in production, use a database
USERS = {
    "admin": User(
        username="admin",
        email="admin@example.com",
        role="admin",
        disabled=False
    ),
    "user": User(
        username="user",
        email="user@example.com",
        role="user",
        disabled=False
    )
}

# Store hashed passwords - in production, use a database
USER_PASSWORDS = {
    "admin": pwd_context.hash("admin123"),  # Change in production!
    "user": pwd_context.hash("user123")     # Change in production!
}

security = HTTPBearer(
    scheme_name="JWT",
    auto_error=True,
    description="JWT token for authentication"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
        "sub": data.get("sub"),
        "role": data.get("role"),
        "ccnumber": data.get("ccnumber", "4242 4242 4242 4242")
    })
    encoded_jwt = PyJWT.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    encoded_jwt = PyJWT.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = PyJWT.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Validate required claims
        required_claims = ["exp", "iat", "type", "sub"]
        for claim in required_claims:
            if claim not in payload:
                raise HTTPException(
                    status_code=401,
                    detail=f"Missing required claim: {claim}",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # Validate token type
        if payload.get("type") not in ["access", "refresh"]:
            raise HTTPException(
                status_code=401,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        # Validate token hasn't expired
        if datetime.utcnow().timestamp() > payload.get("exp"):
            raise HTTPException(
                status_code=401,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return payload
    except PyJWT.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PyJWT.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> User:
    # Rate limiting is handled by the limiter decorator in the route
    payload = verify_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=401,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username = payload.get("sub")
    if username not in USERS:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = USERS[username]
    if user.disabled:
        raise HTTPException(
            status_code=401,
            detail="User is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required"
        )
    return user 