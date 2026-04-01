# Secure Social Web App

This project is a full-stack discussion board prototype with:
- React + TypeScript frontend
- FastAPI backend
- Signup/Login flow
- Protected post endpoints using Bearer token auth
- Firestore-backed storage for users, sessions, and posts

## Requirements

- Docker (recommended), or
- Python 3.11+ and Node.js 18+

## Project Structure

- `docker-compose.yml`: runs frontend and backend services
- `backend/Dockerfile`: backend container image
- `backend/requirements.txt`: backend dependencies
- `backend/run_web.py`: backend launcher
- `backend/src/web_api.py`: FastAPI routes
- `backend/src/file_store.py`: Firestore-backed persistence
- `firebase.json`: Firebase service account credentials (project root, for Docker)
- `frontend/`: React + TypeScript client

## Firebase Setup

1. For Docker, place `firebase.json` at the project root (same level as `docker-compose.yml`).
2. For local backend runs from `backend/`, place `firebase.json` at `backend/firebase.json`.

## Run With Docker Compose


```bash
docker compose up -d
```

Services:
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

Stop services:

```bash
docker compose down -v --rmi local
```

## Run Without Docker

### 1) Start backend

```bash
cd backend
pip install -r requirements.txt
python run_web.py
```

Backend runs on `http://127.0.0.1:8000`.

Note: local backend execution expects credentials at `backend/firebase.json`.

### 2) Start frontend

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:5173`.

## API Endpoints

- `GET /health`
- `POST /auth/signup`
- `POST /auth/login`
- `GET /posts` (Bearer token required)
- `POST /posts` (Bearer token required)

<!-- ## Quick Backend Check

1. Start the backend.
2. Send `GET http://127.0.0.1:8000/health`.
3. Expected response:

```json
{
  "status": "ok"
}
``` -->
