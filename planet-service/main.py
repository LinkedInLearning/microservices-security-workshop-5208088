from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import sqlite3
import json
from shared.auth import get_current_user, require_admin

app = FastAPI()

# Intentionally permissive CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Allow both localhost and 127.0.0.1
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600
)

# Initial planets data
INITIAL_PLANETS = [
    {"id": 1, "name": "Earth", "size": 12742, "population": 12000000000},
    {"id": 2, "name": "Mars", "size": 6779, "population": 5000000},
    {"id": 3, "name": "Jupiter", "size": 139820, "population": 20000000},
    {"id": 4, "name": "Saturn", "size": 116460, "population": 20000000},
    {"id": 5, "name": "Venus", "size": 12104, "population": 20000000},
    {"id": 6, "name": "Mercury", "size": 4879, "population": 1000},
    {"id": 7, "name": "Uranus", "size": 50724, "population": 20000000},
    {"id": 8, "name": "Neptune", "size": 49244, "population": 20000000},
    {"id": 9, "name": "Pluto", "size": 2376, "population": 500},
    {"id": 10, "name": "Tatooine", "size": 10465, "population": 500000},
    {"id": 11, "name": "Coruscant", "size": 12742, "population": 20000000000},
    {"id": 12, "name": "Arrakis", "size": 12000, "population": 20000000},
    {"id": 13, "name": "Vulcan", "size": 15000, "population": 8000000000},
    {"id": 14, "name": "Krypton", "size": 18000, "population": 20000000},
    {"id": 15, "name": "Pandora", "size": 11447, "population": 20000000},
    {"id": 16, "name": "Gallifrey", "size": 25000, "population": 5000000000},
    {"id": 17, "name": "Ego", "size": 30000, "population": 1},
    {"id": 18, "name": "Xandar", "size": 14000, "population": 3000000000},
    {"id": 19, "name": "Knowhere", "size": 5000, "population": 5000000},
    {"id": 20, "name": "Sakaar", "size": 20000, "population": 1000000000},
    {"id": 21, "name": "Asgard", "size": 22000, "population": 20000000},
    {"id": 22, "name": "Naboo", "size": 12120, "population": 6000000000},
    {"id": 23, "name": "Endor", "size": 4900, "population": 10000000},
    {"id": 24, "name": "Hoth", "size": 7200, "population": 200000000},
    {"id": 25, "name": "Dagobah", "size": 8900, "population": 20000000}
]

# In-memory database (for simplicity)
planets = INITIAL_PLANETS.copy()
death_toll = 0

class Planet(BaseModel):
    id: int
    name: str
    size: int
    population: int

@app.get("/planets", response_model=List[Planet])
async def get_planets():
    return planets

@app.get("/planets/{planet_id}", response_model=Planet)
async def get_planet(planet_id: int):
    for planet in planets:
        if planet["id"] == planet_id:
            return planet
    raise HTTPException(status_code=404, detail="Planet not found")

@app.get("/death-toll")
async def get_death_toll():
    return {"death_toll": death_toll}

@app.delete("/planets/{planet_id}")
async def delete_planet(planet_id: int, user = Depends(get_current_user)):
    global planets, death_toll
    for i, planet in enumerate(planets):
        if planet["id"] == planet_id:
            death_toll += planet["population"]  # Add population to death toll
            planets.pop(i)
            return {"message": f"Planet {planet_id} destroyed successfully", "death_toll": death_toll}
    raise HTTPException(status_code=404, detail="Planet not found")

# Intentionally vulnerable endpoint - SQL injection vulnerability
@app.get("/search")
async def search_planets(query: str):
    try:
        # Fix SQL injection vulnerability by using parameterized query
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        
        # Create a temporary table with our planets data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS planets (
                id INTEGER,
                name TEXT,
                size INTEGER,
                population INTEGER
            )
        """)
        
        # Insert our planets data
        for planet in planets:
            cursor.execute(
                "INSERT INTO planets (id, name, size, population) VALUES (?, ?, ?, ?)",
                (planet["id"], planet["name"], planet["size"], planet["population"])
            )
        
        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT * FROM planets WHERE name LIKE ?", (f"%{query}%",))
        results = cursor.fetchall()
        
        # Convert results to list of dictionaries
        planets_list = []
        for row in results:
            planets_list.append({
                "id": row[0],
                "name": row[1],
                "size": row[2],
                "population": row[3]
            })
        
        return {"results": planets_list}
    except Exception as e:
        print(f"Error in search: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Intentionally vulnerable endpoint - no input validation
@app.post("/planets")
async def create_planet(planet: Planet):
    global planets
    # No validation of planet data
    # No duplicate name checking
    # No size/population validation
    planets.append(planet.dict())
    return {"message": "Planet created successfully", "planet": planet}

@app.post("/planets/reset")
async def reset_planets(user = Depends(require_admin)):
    global planets
    planets = INITIAL_PLANETS.copy()
    return {"message": "Planets reset to initial state"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 