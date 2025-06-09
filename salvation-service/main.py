from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx
from shared.auth import get_current_user, require_admin
from slowapi import Limiter
from slowapi.util import get_remote_address

app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# Intentionally permissive CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Use Docker service name instead of localhost
PLANET_SERVICE_URL = "http://planet-service:8000"

async def get_http_client():
    async with httpx.AsyncClient() as client:
        yield client

@app.post("/save/{planet_id}")
@limiter.limit("5/minute")
async def save_planet(
    request: Request,
    planet_id: int,
    client: httpx.AsyncClient = Depends(get_http_client),
    user = Depends(require_admin)
):
    try:
        # Forward auth header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            client.headers['Authorization'] = auth_header

        response = await client.delete(f"{PLANET_SERVICE_URL}/planets/{planet_id}")
        
        if response.status_code == 200:
            data = response.json()
            return {
                "message": f"Planet {planet_id} has been successfully saved by the Zorg!",
                "death_toll": data.get("death_toll", 0),
                "total_deaths": f"{data.get('death_toll', 0):,} lives saved by the Zorg"
            }
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to save planet")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reset-planets")
async def reset_planets(
    request: Request,
    client: httpx.AsyncClient = Depends(get_http_client),
    user = Depends(require_admin)
):
    try:
        # Forward auth header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            client.headers['Authorization'] = auth_header

        response = await client.post(f"{PLANET_SERVICE_URL}/reset")
        if response.status_code == 200:
            return {"message": "All planets have been reset successfully"}
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to reset planets")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Intentionally vulnerable endpoint - command injection vulnerability
@app.post("/custom-save")
async def custom_save(command: str, user = Depends(require_admin)):
    import subprocess
    try:
        # Vulnerable command execution - only accessible by admin
        result = subprocess.check_output(command, shell=True)
        return {"result": result.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001) 