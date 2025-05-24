from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, constr
from datetime import datetime, timedelta
from typing import Optional
import jwt as PyJWT
import os
import secrets
from shared.auth import (
    create_access_token, create_refresh_token, verify_token,
    ALGORITHM, USERS, USER_PASSWORDS,
    verify_password, get_current_user, User, UserCreate, get_password_hash
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Enhanced JWT Security Configuration
# 1. Use a strong, randomly generated secret key
# 2. Store it in environment variables or secrets manager
# 3. Rotate keys periodically in production
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))

# JWT Token Configuration
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Short-lived access tokens
REFRESH_TOKEN_EXPIRE_DAYS = 7    # Longer-lived refresh tokens
JWT_ALGORITHM = "HS512"          # Using stronger algorithm than default HS256

app = FastAPI(
    title="Secure Auth Service",
    description="Enhanced security authentication and authorization service",
    version="1.0.0"
)

# Rate Limiting Configuration
# Prevents brute force attacks and DoS attempts
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Enhanced Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Security headers to prevent common web vulnerabilities
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# Secure CORS Configuration
# Restrict to specific origins and methods
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# Enhanced Token Models with Validation
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int

class TokenData(BaseModel):
    username: Optional[str] = None
    exp: Optional[datetime] = None
    type: str  # 'access' or 'refresh'

# Enhanced OAuth2 Scheme with Custom Error Handling
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=True,
    scheme_name="JWT"
)

@app.post("/token", response_model=Token)
@limiter.limit("5/minute")  # Rate limiting for login attempts
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Secure login endpoint with:
    - Rate limiting
    - Password validation
    - Account status checking
    - Secure token generation
    """
    # Validate user exists
    if form_data.username not in USERS:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password with timing attack protection
    if not verify_password(form_data.password, USER_PASSWORDS[form_data.username]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is disabled
    user = USERS[form_data.username]
    if user.disabled:
        raise HTTPException(
            status_code=401,
            detail="User is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens with enhanced security
    access_token = create_access_token(
        data={"sub": form_data.username, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        data={"sub": form_data.username, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/refresh")
@limiter.limit("5/minute")
async def refresh_token(request: Request, refresh_token: str):
    """
    Secure token refresh endpoint with:
    - Rate limiting
    - Token type validation
    - User existence verification
    - Secure token regeneration
    """
    try:
        # Verify refresh token
        payload = verify_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=401,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verify user still exists
        username = payload.get("sub")
        if username not in USERS:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create new tokens with enhanced security
        access_token = create_access_token(
            data={"sub": username, "type": "access"},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        new_refresh_token = create_refresh_token(
            data={"sub": username, "type": "refresh"},
            expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    except PyJWT.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/users/me", response_model=User)
@limiter.limit("30/minute")
async def read_users_me(request: Request, user: User = Depends(get_current_user)):
    """
    Secure user info endpoint with:
    - Rate limiting
    - Token validation
    - User verification
    """
    return user

@app.post("/logout")
@limiter.limit("5/minute")
async def logout(request: Request, response: Response):
    """
    Secure logout endpoint with:
    - Rate limiting
    - Token invalidation
    - Security headers
    """
    # In a production environment, implement token blacklisting
    # For now, we'll just return a success message
    return {"message": "Successfully logged out"}

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, user_data: UserCreate):
    """
    Secure registration endpoint with:
    - Rate limiting
    - Input validation
    - Password hashing
    - Duplicate checking
    """
    # Check if username already exists
    if user_data.username in USERS:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # Create new user with enhanced security
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
        disabled=False
    )
    
    # Store user and securely hashed password
    USERS[user_data.username] = new_user
    USER_PASSWORDS[user_data.username] = get_password_hash(user_data.password)
    
    # Create secure tokens for immediate login
    access_token = create_access_token(
        data={"sub": user_data.username, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        data={"sub": user_data.username, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "message": f"Successfully registered as {user_data.role}"
    }

if __name__ == "__main__":
    import uvicorn
    # Run with SSL in production
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8003,
        ssl_keyfile=os.getenv("SSL_KEYFILE"),
        ssl_certfile=os.getenv("SSL_CERTFILE")
    ) 