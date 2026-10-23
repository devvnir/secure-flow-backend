# Milestone 2: Data Ingestion — How It Works and How to Verify It

Everything below was run against the live backend and frontend on 2026-10-22. The numbers shown are real outputs, not illustrations.

## What Milestone 2 delivers

| Requirement | Where it lives | How it's verified |
|---|---|---|
| RESO Web API ingestion (OData `$filter`, `$select`, `$top`, `$skip`) | `core_backend/ingestion.py` → `RESODataIngestionEngine.ingest_from_reso` | Unit tests (fake HTTP transport) + live E2E |
| Dynamic schema translation (RESO → internal, custom mappings at runtime) | `SchemaTranslator`, `POST /api/ingestion/translate-schema`, `POST /api/ingestion/schema-mappings` | Unit + E2E |
| Payload validation (required fields, type checks, per-record errors) | `PayloadValidator`, `POST /api/ingestion/validate-payload` | Unit + E2E |
| Token-bound filtering (records owned by the JWT's user; no cross-user access) | `apply_token_bound_filters`, `GET /api/data-flows/{id}/data` | E2E with two users |
| Run tracking (completed / failed runs with counts and errors) | `data_flow_runs` table, `GET /api/data-flows/{id}/runs` | E2E + UI |
| UI to run ingestion and inspect results | `secure-overlay/app/dashboard/[id]/page.tsx` | Browser test (Edge, Playwright) |

### About the RESO data source

Real RESO feeds (MLS vendors) require vendor-issued credentials, which this project doesn't have yet. The backend includes a **mock RESO OData server** at `/api/mock-reso/odata/{Resource}` with six sample listings. It requires its own bearer token, separate from the user's login token. One listing (`RESO_2026_006`) is deliberately malformed so validation failures can be seen.

To switch to a real feed, set two environment variables. No code changes are needed:

```
RESO_API_BASE_URL=https://<vendor-host>/odata
RESO_API_TOKEN=<vendor-issued token>
```

## Pipeline

```
POST /api/ingestion/reso/ingest   (Authorization: Bearer <user JWT>)
  1. Verify the JWT and that the caller owns the flow (404 otherwise)
  2. Reject flows whose source isn't RESO (400) or that aren't Active (409)
  3. GET {RESO_API_BASE_URL}/Property?$filter=...  (Authorization: Bearer <RESO token>)
  4. Translate each record RESO → internal (ListingKey→listing_id, ListPrice→price as float, timestamps → ISO-8601, ...)
  5. Validate each record (listing_id and address required; price numeric; bedrooms/bathrooms integer)
  6. Tag valid records with the caller's user id and store them in ingested_records
  7. Record the run (status, stored count, rejected count, per-record errors)
```

## Verify it in the browser (about 2 minutes)

1. Start the backend from the project root: `python -m uvicorn core_backend.main:app --port 8000`
2. Start the frontend from `secure-overlay/`: `npm run dev`
3. Sign in and click **New Flow**. Keep **Source Type = RESO**, optionally set a default filter, and create it. The flow opens as **Draft**, and **Run Ingestion** stays disabled until the flow is active.
4. Click **Activate**. In **RESO Ingestion**, enter the filter `ListPrice gt 300000 and ListPrice lt 2000000` and click **Run Ingestion**.

Expected result:

- **Fetched 4 · Stored 3 · Rejected 1**
- Rejected: `RESO_2026_006: Missing required field: address; Field bedrooms has invalid type: expected int, got str`
- **Run History** shows one *Completed* run (3 stored, 1 rejected).
- **Your Ingested Records** lists RESO_2026_001 ($550,000), RESO_2026_002 ($725,000) and RESO_2026_004 ($1,450,000), already in the internal schema.

5. Enter an invalid filter such as `DROP TABLE` and run again. You'll see an error message, and a *Failed* run appears in Run History.
6. **Manual Import** stores records pasted as JSON. The sample imports 1 record and rejects 1.
7. **Pause** blocks ingestion again; **Edit** changes the name and RESO settings; **Delete** asks for confirmation.
8. On **Flows**, search by name or filter by status and source. The summary line counts active flows separately.
9. **Schema Tools** translates a record with any registered mapping, validates a payload against a schema, and registers new custom mappings.
10. Sign in as a different user. That user can't open the first user's flow or its data.

## Verify it with the API

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/login -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"YourPass123!"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Translate a RESO record
curl -s -X POST localhost:8000/api/ingestion/translate-schema -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"record":{"ListingKey":"X1","ListPrice":"500000.50","PropertyAddress":"1 Main St"},"source_schema":"reso","destination_schema":"internal"}'
# -> "translated": {"listing_id":"X1","price":500000.5,"address":"1 Main St"}

# Validate a payload
curl -s -X POST localhost:8000/api/ingestion/validate-payload -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"data":{"price":"cheap"}}'
# -> "valid": false, with errors for listing_id, address and price

# Ingest into a RESO flow you own
curl -s -X POST localhost:8000/api/ingestion/reso/ingest -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"flow_id":"<FLOW_ID>","query_filters":{"resource":"Property","filter":"ListPrice gt 300000 and ListPrice lt 2000000"}}'
# -> records_ingested 4, records_validated 3, records_failed 1

# Read back your records (token-bound)
curl -s localhost:8000/api/data-flows/<FLOW_ID>/data -H "Authorization: Bearer $TOKEN"
```

Interactive API docs are at http://localhost:8000/docs.

## Automated tests

- Unit tests: `python -m pytest core_backend/tests` → **23 passed**. Covers translation, validation, token-bound filtering, the OData filter parser, and HTTP fetching (token and query parameters sent correctly; upstream errors raised).
- Live end-to-end API checks → **56/56 passed**. Covers two-user isolation, status rules (Draft/Paused can't ingest), update/delete, filters, malformed-record rejection, failed-run recording, batch ingest, custom mappings, token refresh rotation, logout revocation, and CORS.
- Browser test (Edge, headless) → **all passed**. Covers register/login errors, create → activate → ingest → manual import → edit → pause, dashboard filters and search, Schema Tools, silent token refresh, delete, logout, and no console errors.

## Known limitations

- The default data source is the bundled mock. Running against a real MLS needs vendor credentials, plus field mappings for any vendor-specific fields.
- The OData parser (in the mock server) supports `eq ne gt ge lt le` joined by `and`. It doesn't support `or`, parentheses or functions.
- Custom schema mappings are kept in memory and are lost when the server restarts.
- Logout revokes the refresh token right away, but an already-issued access token stays valid until it expires (up to 30 minutes).
- There's no password-reset feature, so the login page no longer shows a "Forgot password?" link.
- Ingestion runs synchronously within the request, which is fine for hundreds of records. Large feeds would need a background worker and paging (`$skip`) loops.
