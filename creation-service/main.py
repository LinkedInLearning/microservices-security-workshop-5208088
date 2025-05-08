from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from typing import List
from shared.auth import get_current_user

app = FastAPI()

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

class PlanetCreate(BaseModel):
    name: str
    size: int
    population: int

async def get_http_client():
    async with httpx.AsyncClient() as client:
        yield client

@app.post("/create")
async def create_planet(
    planet: PlanetCreate,
    request: Request,
    client: httpx.AsyncClient = Depends(get_http_client),
    user = Depends(get_current_user)
):
    try:
        # Forward auth header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            client.headers['Authorization'] = auth_header

        # Get current planets to generate new ID
        response = await client.get(f"{PLANET_SERVICE_URL}/planets")
        planets = response.json()
        new_id = max(p["id"] for p in planets) + 1 if planets else 1
        
        # Create new planet
        new_planet = {
            "id": new_id,
            "name": planet.name,
            "size": planet.size,
            "population": planet.population
        }
        
        # Add to planets list
        response = await client.post(
            f"{PLANET_SERVICE_URL}/planets",
            json=new_planet
        )
        
        if response.status_code == 200:
            return {"message": f"Planet {planet.name} created successfully!", "planet": new_planet}
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to create planet")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Intentionally vulnerable endpoint - file upload vulnerability
@app.post("/upload-image")
async def upload_planet_image(file: bytes):
    try:
        # No file type validation
        # No file size limits
        # No sanitization of file name
        with open(f"uploads/{file.filename}", "wb") as f:
            f.write(file.file.read())
        return {"message": "Image uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002) 