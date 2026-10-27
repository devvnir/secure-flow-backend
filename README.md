# Secure Flow

Secure real-estate data platform: RESO data ingestion, an isolated processing enclave, a
zero-knowledge vault, canvas signatures and Stripe subscription billing, with a JSON-driven
overlay engine for broker pages.

- **Backend:** this repository (FastAPI + PostgreSQL)
- **Frontend and overlay engine:** `secure-flow-frontend` (Next.js 14)

## Documentation

- [Architecture](docs/ARCHITECTURE.md): components, tech stack, data model, API, security design
- [Deployment](docs/DEPLOYMENT.md): Render cloud deployment, configuration, local / Windows 11 ARM64

## Quick start

```
pip install -r core_backend/requirements.txt
cp .env.example core_backend/.env      # set DATABASE_URL and SECRET_KEY
uvicorn core_backend.main:app --port 8000 --no-proxy-headers
```

API docs: http://localhost:8000/docs. Cloud deployment: `render.yaml` (see the deployment guide).
