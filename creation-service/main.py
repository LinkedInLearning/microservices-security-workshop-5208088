from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import json

app = FastAPI()

# Intentionally permissive CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Hardcoded planet service URL (vulnerability: no environment variables)
PLANET_SERVICE_URL = "http://localhost:8000"

class PlanetCreate(BaseModel):
    name: str
    size: int
    population: int

@app.post("/create")
async def create_planet(planet: PlanetCreate):
    try:
        # No input validation or sanitization
        # No authentication or authorization
        # No rate limiting
        # No size/population validation
        
        # Get current planets to generate new ID
        response = requests.get(f"{PLANET_SERVICE_URL}/planets")
        planets = response.json()
        new_id = max(p["id"] for p in planets) + 1 if planets else 1
        
        # Create new planet
        new_planet = {
            "id": new_id,
            "name": planet.name,
            "size": planet.size,
            "population": planet.population
        }
        
        # Add to planets list (in a real app, this would be a database operation)
        response = requests.post(f"{PLANET_SERVICE_URL}/planets", json=new_planet)
        
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