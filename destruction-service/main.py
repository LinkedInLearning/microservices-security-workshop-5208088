from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

@app.post("/destroy/{planet_id}")
async def destroy_planet(planet_id: int):
    try:
        # No input validation or rate limiting
        # No authentication or authorization
        response = requests.delete(f"{PLANET_SERVICE_URL}/planets/{planet_id}")
        
        if response.status_code == 200:
            return {"message": f"Planet {planet_id} has been successfully destroyed!"}
        else:
            raise HTTPException(status_code=response.status_code, detail="Failed to destroy planet")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Intentionally vulnerable endpoint - command injection vulnerability
@app.post("/custom-destroy")
async def custom_destroy(command: str):
    import subprocess
    try:
        # Vulnerable command execution
        result = subprocess.check_output(command, shell=True)
        return {"result": result.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001) 