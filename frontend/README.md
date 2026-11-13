# CyberWatch

CyberWatch is a React dashboard backed by the FastAPI service in `backend/`.
The dashboard uses a WebSocket for packet events and HTTP for file analysis.

## Run locally

1. Install the backend requirements and start the API:

   ```powershell
   python -m pip install -r backend\requirements.txt
   Set-Location backend
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

2. In another terminal, install and start the frontend:

   ```powershell
   Set-Location frontend
   npm ci
   npm run dev
   ```

Vite proxies `/api` requests and `/ws` connections to the local backend. The
backend permits browser origins from `localhost:5173` and `127.0.0.1:5173`.
Packet capture may require Npcap and elevated privileges on Windows; the API
can still serve file-analysis requests if capture is unavailable.

## Deployment

Configure the reverse proxy to forward `/api/*` to FastAPI and pass
`/ws/packets` through as a WebSocket. The backend CORS and WebSocket origin
allowlists are intentionally local-development-only.

The file analyzer accepts PDF, DOC, DOCX, PPT, and PPTX files up to 50 MB. It
uses lightweight metadata and byte-pattern heuristics; it is not an antivirus
engine, and its rule scores are not calibrated probabilities.

The backend has no authentication. Keep it bound to a trusted local interface;
CORS restrictions do not prevent non-browser clients from reaching the API.
