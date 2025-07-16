# Microservices Security Workshop: From Build to Production
This is the repository for the LinkedIn Learning course `Microservices Security Workshop: From Build to Production`. The full course is available from [LinkedIn Learning][lil-course-url].

![lil-thumbnail-url]

# Course Description

# Insecure Microservices Demo

A demonstration of various security vulnerabilities in a microservices architecture, featuring a planet management system.

## Services

- **Planet Service** (`planet-service/`): Manages planet data and search functionality
- **Destruction Service** (`destruction-service/`): Handles planet destruction
- **Creation Service** (`creation-service/`): Handles planet creation
- **Frontend** (`frontend/`): Web interface for interacting with the services

## Setup

### Option 1: Using Docker (Recommended)

1. Make sure you have Docker and Docker Compose installed on your system.

2. Build and start all services:
```bash
docker-compose up --build
```

3. Access the application:
   - Frontend: http://localhost:3000
   - Planet Service: http://localhost:8000
   - Destruction Service: http://localhost:8001
   - Creation Service: http://localhost:8002

### Option 2: Manual Setup

1. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies for each service:
```bash
# Planet Service
cd planet-service
pip install -r requirements.txt

# Destruction Service
cd ../destruction-service
pip install -r requirements.txt

# Creation Service
cd ../creation-service
pip install -r requirements.txt

# Frontend
cd ../frontend
pip install -r requirements.txt
```

## Running the Services

### Manual Setup Instructions

You'll need to start each service in a separate terminal window:

1. Start the Planet Service:
```bash
cd planet-service
python main.py
```
The service will run on http://localhost:8000

2. Start the Destruction Service:
```bash
cd destruction-service
python main.py
```
The service will run on http://localhost:8001

3. Start the Creation Service:
```bash
cd creation-service
python main.py
```
The service will run on http://localhost:8002

4. Start the Frontend Server:
```bash
cd frontend
python server.py
```
The frontend will be available at http://localhost:3000

## Accessing the Application

Once all services are running, open your browser and navigate to:
http://localhost:3000

## Features

- View list of planets
- Search planets
- Create new planets
- Destroy planets
- Reset planets to initial state

## Security Notes

This application is intentionally designed with security vulnerabilities for educational purposes. Do not use this in production without proper security measures.

## Troubleshooting

If you encounter CORS issues:
1. Ensure all services are running
2. Access the frontend through http://localhost:3000 (not file://)
3. Check that all services are running on their correct ports

If you encounter any other issues:
1. Check the console output of each service for error messages
2. Ensure all dependencies are installed correctly
3. Try restarting the services in the correct order

## Instructor
James Berthoty
Security Engineer Turned Analyst at Latio Tech

[0]: # (Replace these placeholder URLs with actual course URLs)

[lil-course-url]: https://www.linkedin.com/learning/microservices-security-workshop-from-build-to-production
[lil-thumbnail-url]: https://media.licdn.com/dms/image/v2/D4E0DAQGr36V_9QGHpg/learning-public-crop_675_1200/B4EZflAVtsGcAg-/0/1751893761164?e=1753304400&v=beta&t=LH5uDA6rd8usOnwQcMcQWi6d9klJDHD1W34hzws5R0U
