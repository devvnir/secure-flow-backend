# Secure Flow – Technical Architecture

## 1. Overview

Secure Flow ingests real-estate data (RESO Web API), processes sensitive payloads inside an isolated
enclave process, stores encrypted files in a zero-knowledge vault, captures single-party canvas
signatures and bills subscriptions through Stripe. A JSON-driven overlay engine renders broker UI on
third-party pages.

```
 Browser ──────────────► Next.js 14 frontend (secure-flow-frontend)
   │                        pages: dashboard, data flows, vault, sign, billing, overlay demo
   │  HTTPS / JSON + JWT    public/overlay/secure-flow-overlay.js (embeddable engine)
   ▼
 FastAPI backend (this repository, core_backend/)
   ├── auth            JWT access + refresh tokens, bcrypt, rate limits
   ├── data flows      CRUD, runs, ingested data
   ├── ingestion       RESO OData client, schema translation, batch ingest
   ├── enclave         sanitisation in a separate, resource-limited worker process
   ├── vault           ciphertext-only file store (browser-side encryption)
   ├── signatures      canvas vectors + UTC timestamp + client IP
   └── billing         Stripe Checkout, tiers, ACH / card fee, webhooks
   │
   ├──► PostgreSQL (all state; schema in database-enclave/schema.sql)
   └──► Stripe API (test mode) ◄── Stripe webhooks (POST /api/stripe/webhook)
```

## 2. Tech stack

| Layer | Technology |
|---|---|
| API | Python 3.11, FastAPI 0.104, Uvicorn 0.24, Pydantic 2 |
| Database | PostgreSQL 14+ via SQLAlchemy 2.0; psycopg2, or pure-Python pg8000 where no native wheel exists (Windows 11 ARM64) |
| Crypto | `cryptography` 46 (RSA-OAEP-256 3072-bit, AES-256-GCM), bcrypt 5, PyJWT |
| Payments | Stripe API (stripe-python 15.6), Checkout, Billing Portal, webhooks |
| Frontend | Next.js 14, React 18, Tailwind CSS, TypeScript |
| Overlay engine | Dependency-free TypeScript compiled to a single script, Shadow DOM |
| Hosting | Render Blueprint (`render.yaml`): managed PostgreSQL + two web services |

## 3. Backend modules

| Path | Responsibility |
|---|---|
| `core_backend/main.py` | App setup: CORS allowlist, Host-header allowlist, routers, startup migrations |
| `core_backend/security.py` | Signing-key policy (refuses weak keys), password hashing, rate limiting, trusted-proxy client IP |
| `core_backend/database.py` | Engine, driver selection, idempotent startup migrations |
| `core_backend/models.py` | SQLAlchemy models (18 tables) |
| `core_backend/ingestion.py` | RESO OData client and schema translation |
| `core_backend/enclave/` | Key ring, sandbox launcher, worker, sanitisers, hash-chained audit log |
| `core_backend/signatures.py` | Stroke normalisation, hashing, SVG rendering |
| `core_backend/billing.py` | Stripe catalog sync, tiers, fee calculation, checkout, webhook handlers |
| `core_backend/routes/` | HTTP endpoints (see section 5) |
| `database-enclave/schema.sql` | Full PostgreSQL schema; re-runnable and upgrades older databases |
| `tools/stripe_setup.py` | Creates the subscription tiers in a Stripe test account from `tools/stripe_tiers.json` |
| `tools/verify_forensic_export.py` | Offline verification of an exported enclave audit chain |

## 4. Data model (PostgreSQL)

| Area | Tables |
|---|---|
| Identity | `users`, `sessions`, `roles`, `user_roles`, `api_keys`, `audit_logs` |
| Data flows | `data_flows`, `data_flow_runs`, `ingested_records` |
| Enclave and vault | `enclave_records`, `encryption_keys`, `vault_configs`, `vault_items` |
| Signatures | `signatures`: raw stroke vectors (JSONB), canvas size, `signed_at_utc`, `ip_address` (INET), user agent, session id, SHA-256 hash; one signature per user and document |
| Billing | `billing_customers`, `billing_prices` (mirror of the Stripe catalog), `subscriptions`, `stripe_events` (ledger and idempotency) |

The tables are created on startup (`create_all`) and existing databases are upgraded by the
migrations in `database.py`. `schema.sql` is the same schema for DBAs and can be applied by hand.

## 5. API surface

Interactive documentation: `GET /docs` (Swagger UI) and `GET /openapi.json` on the running API.

| Prefix | Endpoints |
|---|---|
| `/health` | Liveness |
| `/api/auth` | `register`, `login`, `refresh`, `me`, `logout` |
| `/api/data-flows` | CRUD, `/{id}/runs`, `/{id}/runs/{run_id}`, `/{id}/data` |
| `/api/ingestion` | `reso/ingest`, `batch-ingest`, `validate-payload`, `translate-schema`, `schemas`, `schema-mappings` |
| `/api/enclave` | `public-key`, `sanitize`, `records`, `records/{id}`, `verify`, `export` |
| `/api/vault` | vault config (`GET`/`POST`/`DELETE`), `items` (list, upload, get, delete) |
| `/api/signatures` | create, list, get, `/{id}/svg`, `/{id}/verify` |
| `/api/billing` | `plans`, `payment-options`, `quote`, `checkout-session`, `change-tier`, `payment-method-session`, `portal-session`, `subscription`, `ledger` |
| `/api/stripe/webhook` | Stripe events (signature-verified) |
| `/api/mock-reso/odata` | Bundled mock RESO source (demo/test only, `ENABLE_MOCK_SOURCES`) |

## 6. Security design

- **Authentication:** short-lived JWT access tokens plus rotating refresh tokens tracked in
  `sessions`. Passwords use bcrypt. Login and registration are rate-limited per IP and account.
  The server refuses to start with a missing, short or placeholder `SECRET_KEY`.
- **Network boundary:** CORS accepts only the configured frontend origin (`CORS_ORIGIN_REGEX`).
  The Host header must match `ALLOWED_HOSTS`. `X-Forwarded-For` is honoured only from
  `TRUSTED_PROXY_IPS` (IPs or CIDR ranges), so a client cannot spoof the IP recorded on signatures,
  audit records or rate limits.
- **Enclave:** payloads are encrypted in the browser to the enclave's RSA-OAEP-256 public key, which
  exists only in memory and is regenerated on every start. Decryption and sanitisation run in a
  fresh worker process for each request. The worker runs in Python isolated mode with a scrubbed
  environment, a 30 s timeout and a 512 MB memory cap (Job Object on Windows, rlimits on Linux).
  Every result is appended to a SHA-256 hash-chained audit log that `/verify` and
  `tools/verify_forensic_export.py` can check.
- **Vault:** files are encrypted in the browser with AES-GCM under a key derived with
  PBKDF2-SHA256 (≥ 310,000 iterations). The server stores only ciphertext and parameters, never keys.
- **Signatures:** a single party signs on an HTML5 canvas. The raw vectors are stored with the
  server-side UTC timestamp and client IP, and a SHA-256 hash over them makes later changes
  detectable (`/verify`).
- **Payments:** no card or bank data reaches this server; Stripe Checkout collects it. Webhooks are
  verified with `STRIPE_WEBHOOK_SECRET`, deduplicated by event id, applied in order using row locks,
  and stale events are ignored. Live keys are refused unless `APP_ENV=production`.
- **Secrets:** only `.env.example` (empty placeholders) is committed; `.env` files are git-ignored.
  On Render, secrets are set in the dashboard or generated by the Blueprint.

## 7. Billing flow

1. **Tiers come from Stripe, not code.** Every active recurring Price whose price or product
   metadata has `tier_id` is a tier. Flat, graduated and volume prices are supported. The catalog is
   mirrored into `billing_prices` by a periodic sync (`STRIPE_CATALOG_TTL_SECONDS`) and by
   `price.*` / `product.*` webhooks.
2. **Choose a tier and a payment method.** The method is US bank account (ACH, no fee) or card
   (`CARD_FEE_PERCENT`, default 5 %). The server quotes the amount, including the fee line.
3. **Stripe Checkout** (subscription mode) collects payment. Card fees are a separate recurring
   line item.
4. **Webhooks** (`checkout.session.*`, `customer.subscription.*`, `invoice.*`) record the tier,
   price, product, amount, interval, quantity, items and metadata exactly as Stripe sends them.
   ACH payments stay "processing" until the async payment events arrive.
5. **Tier changes** (in the app or in the Stripe Dashboard) re-price the fee automatically. Users
   can replace a card or bank account only with the same type. The portal is limited to invoices
   and cancellation.

## 8. Overlay engine (frontend repository)

`overlay/src/secure-flow-overlay.ts` compiles a JSON overlay definition plus user objects
(`Broker_ID`, `Region_Node`, `Document_Status_Bit`) into UI inside a Shadow DOM on the host page.
It refuses to mount on hosts outside `allowedDomains`, writes values only with `textContent`
(no `innerHTML`) and allows only http(s) links. `overlay/proxy/` injects the script into fixture
pages through a proxy and validates the result in a real browser (`npm run validate:overlay`).

## 9. Environments

| Environment | How |
|---|---|
| Local / Windows 11 ARM64 | See `docs/DEPLOYMENT.md` § 3 |
| Cloud (Render) | `render.yaml`, see `docs/DEPLOYMENT.md` § 2 |

## 10. Testing

- `pytest core_backend/tests`: 124 unit tests covering security, ingestion, enclave sandbox and
  sanitisers, signatures, billing, fees and webhooks.
- `core_backend/tests/stripe_double.py` is a local stand-in for the Stripe API, so the billing
  flows can be tested end to end without a Stripe account.
