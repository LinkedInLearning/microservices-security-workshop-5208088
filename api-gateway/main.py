from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
import httpx
from typing import Optional
import os
from shared.auth import get_current_user, User

# Get JWT secret key from environment variable
# In production, this would be retrieved from a secrets manager
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-that-should-be-in-secrets-manager")

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service URLs
PLANET_SERVICE_URL = "http://planet-service:8000"
CREATION_SERVICE_URL = "http://creation-service:8002"
SALVATION_SERVICE_URL = "http://salvation-service:8001"
AUTH_SERVICE_URL = "http://auth-service:8003"

# OAuth2 scheme for token validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_http_client():
    async with httpx.AsyncClient() as client:
        yield client

# Auth endpoints
@app.post("/token")
async def login(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.post(f"{AUTH_SERVICE_URL}/token", data=await request.form())
    return response.json()

@app.post("/refresh")
async def refresh_token(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.post(f"{AUTH_SERVICE_URL}/refresh", json=await request.json())
    return response.json()

@app.get("/users/me")
async def read_users_me(request: Request, client: httpx.AsyncClient = Depends(get_http_client), user: User = Depends(get_current_user)):
    response = await client.get(f"{AUTH_SERVICE_URL}/users/me", headers=request.headers)
    return response.json()

@app.post("/register")
async def register(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.post(f"{AUTH_SERVICE_URL}/register", json=await request.json())
    return response.json()

@app.post("/logout")
async def logout(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.post(f"{AUTH_SERVICE_URL}/logout", headers=request.headers)
    return response.json()

# Planet endpoints
@app.get("/planets")
async def get_planets(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.get(f"{PLANET_SERVICE_URL}/planets", headers=request.headers)
    return response.json()

@app.get("/planets/{planet_id}")
async def get_planet(planet_id: int, request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.get(f"{PLANET_SERVICE_URL}/planets/{planet_id}", headers=request.headers)
    return response.json()

@app.get("/search")
async def search_planets(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    query = request.query_params.get("query", "")
    response = await client.get(f"{PLANET_SERVICE_URL}/search?query={query}", headers=request.headers)
    return response.json()

@app.get("/death-toll")
async def get_death_toll(request: Request, client: httpx.AsyncClient = Depends(get_http_client)):
    response = await client.get(f"{PLANET_SERVICE_URL}/death-toll", headers=request.headers)
    return response.json()

# Creation endpoints
@app.post("/create")
async def create_planet(request: Request, client: httpx.AsyncClient = Depends(get_http_client), user: User = Depends(get_current_user)):
    response = await client.post(f"{CREATION_SERVICE_URL}/create", json=await request.json(), headers=request.headers)
    return response.json()

@app.post("/upload-image")
async def upload_planet_image(request: Request, client: httpx.AsyncClient = Depends(get_http_client), user: User = Depends(get_current_user)):
    response = await client.post(f"{CREATION_SERVICE_URL}/upload-image", files=await request.files(), headers=request.headers)
    return response.json()

# Salvation endpoints
@app.post("/destroy/{planet_id}")
async def destroy_planet(planet_id: int, request: Request, client: httpx.AsyncClient = Depends(get_http_client), user: User = Depends(get_current_user)):
    response = await client.post(f"{SALVATION_SERVICE_URL}/save/{planet_id}", headers=request.headers)
    return response.json()

@app.post("/reset-planets")
async def reset_planets(request: Request, client: httpx.AsyncClient = Depends(get_http_client), user: User = Depends(get_current_user)):
    response = await client.post(f"{SALVATION_SERVICE_URL}/reset-planets", headers=request.headers)
    return response.json()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004) 