"""
Minimal local stand-in for the Stripe API, for end-to-end tests without network access or keys.

Run:  python -m uvicorn core_backend.tests.stripe_double:app --port 12111
Backend: STRIPE_API_BASE=http://127.0.0.1:12111  STRIPE_SECRET_KEY=sk_test_double  STRIPE_WEBHOOK_SECRET=whsec_double
POST /__complete/{session_id} simulates the customer paying: it sends signed checkout.session.completed,
customer.subscription.created and invoice.paid events to WEBHOOK_URL, as Stripe would.
"""

import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://127.0.0.1:8001/api/stripe/webhook")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_double")
PRICE = {"id": "price_double_base", "object": "price", "active": True, "unit_amount": 25000, "currency": "usd",
         "recurring": {"interval": "month"}, "lookup_key": "secure_flow_base_monthly", "product": "prod_double"}
state = {"customers": {}, "sessions": {}}


def _auth(request: Request):
    if not request.headers.get("authorization", "").startswith("Bearer sk_test_"):
        raise HTTPException(status_code=401, detail={"error": {"message": "Invalid API key", "type": "invalid_request_error"}})


def sign(payload: str, secret: str = WEBHOOK_SECRET, timestamp: int = None) -> str:
    t = timestamp or int(time.time())
    sig = hmac.new(secret.encode(), f"{t}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}"


def event(etype: str, obj: dict, created: int = None) -> dict:
    return {"id": f"evt_{uuid.uuid4().hex[:24]}", "object": "event", "type": etype, "created": created or int(time.time()),
            "livemode": False, "api_version": "2026-08-26.dahlia", "data": {"object": obj}}


@app.get("/v1/prices")
async def list_prices(request: Request):
    _auth(request)
    return {"object": "list", "data": [PRICE], "has_more": False, "url": "/v1/prices"}


@app.post("/v1/customers")
async def create_customer(request: Request):
    _auth(request)
    form = await request.form()
    cid = f"cus_{uuid.uuid4().hex[:14]}"
    state["customers"][cid] = {"id": cid, "object": "customer", "email": form.get("email"), "metadata": {"user_id": form.get("metadata[user_id]")}}
    return state["customers"][cid]


@app.post("/v1/checkout/sessions")
async def create_session(request: Request):
    _auth(request)
    form = await request.form()
    if form.get("line_items[0][price]") != PRICE["id"] or form.get("mode") != "subscription":
        raise HTTPException(status_code=400, detail={"error": {"message": "bad checkout params", "type": "invalid_request_error"}})
    sid = f"cs_test_{uuid.uuid4().hex[:20]}"
    state["sessions"][sid] = {"id": sid, "object": "checkout.session", "mode": "subscription", "customer": form.get("customer"),
                              "client_reference_id": form.get("client_reference_id"), "url": f"https://checkout.stripe.test/c/pay/{sid}",
                              "metadata_user": form.get("subscription_data[metadata][user_id]")}
    return state["sessions"][sid]


@app.post("/v1/billing_portal/sessions")
async def portal(request: Request):
    _auth(request)
    form = await request.form()
    return {"id": f"bps_{uuid.uuid4().hex[:14]}", "object": "billing_portal.session", "url": f"https://billing.stripe.test/p/{form.get('customer')}"}


async def deliver(evt: dict, secret: str = WEBHOOK_SECRET):
    payload = json.dumps(evt)
    async with httpx.AsyncClient() as client:
        r = await client.post(WEBHOOK_URL, content=payload, headers={"Content-Type": "application/json", "Stripe-Signature": sign(payload, secret)})
    return {"type": evt["type"], "id": evt["id"], "status": r.status_code, "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text}


@app.post("/__complete/{session_id}")
async def complete(session_id: str):
    s = state["sessions"].get(session_id)
    if not s:
        raise HTTPException(status_code=404)
    now = int(time.time())
    sub_id = f"sub_{uuid.uuid4().hex[:14]}"
    sub = {"id": sub_id, "object": "subscription", "customer": s["customer"], "status": "active", "cancel_at_period_end": False,
           "metadata": {"user_id": s["metadata_user"]},
           "items": {"object": "list", "data": [{"id": "si_1", "price": PRICE, "current_period_end": now + 30 * 86400}]}}
    invoice = {"id": f"in_{uuid.uuid4().hex[:14]}", "object": "invoice", "customer": s["customer"], "amount_paid": 25000, "amount_due": 25000,
               "currency": "usd", "status": "paid", "parent": {"type": "subscription_details", "subscription_details": {"subscription": sub_id}}}
    results = []
    for evt in (event("checkout.session.completed", {**s, "status": "complete", "subscription": sub_id}, now),
                event("customer.subscription.created", sub, now), event("invoice.paid", invoice, now)):
        results.append(await deliver(evt))
    return {"subscription_id": sub_id, "invoice_id": invoice["id"], "deliveries": results}
