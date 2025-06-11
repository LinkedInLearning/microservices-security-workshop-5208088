from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import jwt as PyJWT
from shared.auth import (
    create_access_token, create_refresh_token, verify_token,
    SECRET_KEY, ALGORITHM, USERS, USER_PASSWORDS,
    verify_password, get_current_user, User, UserCreate, get_password_hash
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization service",
    version="1.0.0"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# CORS middleware with secure defaults
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token", response_model=Token)
@limiter.limit("5/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    # Validate user exists
    if form_data.username not in USERS:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
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
    
    # Create tokens
    access_token = create_access_token(data={
    "sub": form_data.username,
    "role": user.role,
    "ccnumber": "4242 4242 4242 4242"
    })
    new_refresh_token = create_refresh_token(data={
        "sub": form_data.username
    })

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh")
@limiter.limit("5/minute")
async def refresh_token(request: Request, refresh_token: str):
    try:
        payload = verify_token(refresh_token)
        if payload.get("type") != "refresh":
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
        
        # Create new tokens
        access_token = create_access_token(data={
        "sub": username,
        "role": USERS[username].role,
        "ccnumber": "4242 4242 4242 4242"
        })
        new_refresh_token = create_refresh_token(data={
            "sub": username
        })
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
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
    return user

@app.post("/logout")
@limiter.limit("5/minute")
async def logout(request: Request, response: Response):
    # In a real application, you might want to blacklist the token
    # For now, we'll just return a success message
    return {"message": "Successfully logged out"}

@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, user_data: UserCreate):
    # Check if username already exists
    if user_data.username in USERS:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
        disabled=False
    )
    
    # Store user and hashed password
    USERS[user_data.username] = new_user
    USER_PASSWORDS[user_data.username] = get_password_hash(user_data.password)
    
    # Create tokens for immediate login
    access_token = create_access_token(data={
    "sub": user_data.username,
    "role": user_data.role,
    "ccnumber": "4242 4242 4242 4242"
    })
    refresh_token = create_refresh_token(data={
        "sub": user_data.username
    })
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "message": f"Successfully registered as {user_data.role}"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003) 