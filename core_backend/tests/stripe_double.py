"""
Minimal local stand-in for the Stripe API, for end-to-end tests without network access or keys.

Run:  python -m uvicorn core_backend.tests.stripe_double:app --port 12111
Backend: STRIPE_API_BASE=http://127.0.0.1:12111  STRIPE_SECRET_KEY=sk_test_double  STRIPE_WEBHOOK_SECRET=whsec_double

Catalog: three tiers (flat "base", "pro" tagged on its product only, graduated per-seat "team"),
plus an untagged price and an inactive tier price that must never be offered.
API calls that change a subscription (modify, item create/modify/delete) answer immediately and
then deliver customer.subscription.updated, as Stripe does.

Simulation hooks, each delivering signed webhooks to WEBHOOK_URL:
  POST /__complete/{session_id}             customer finishes Checkout. Card: paid at once
                                            (checkout.session.completed, customer.subscription.created,
                                            invoice.paid). Bank (ACH): payment processing; no invoice yet.
  POST /__ach/{subscription_id}/succeeded   the bank payment clears: async_payment_succeeded + invoice.paid
  POST /__ach/{subscription_id}/failed      the bank payment fails: async_payment_failed + invoice.payment_failed
  POST /__change/{subscription_id}?price=   tier edited in the Stripe Dashboard: subscription.updated
  POST /__price/{price_id}   {json patch}   price edited: price.updated
  POST /__product/{product_id} {json patch} product edited: product.updated
  GET  /__state                             internal state, for assertions
"""

import copy
import hashlib
import hmac
import json
import os
import time
import uuid

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

app = FastAPI()
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://127.0.0.1:8001/api/stripe/webhook")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_double")

PRODUCTS = {
    "prod_base": {"id": "prod_base", "object": "product", "active": True, "name": "Secure Flow Base", "description": "Base tier",
                  "metadata": {"tier_id": "base"}, "marketing_features": [{"name": "Unlimited data flows"}, {"name": "Encrypted vault"}]},
    "prod_pro": {"id": "prod_pro", "object": "product", "active": True, "name": "Secure Flow Pro", "description": "Pro tier",
                 "metadata": {"tier_id": "pro", "region_nodes": "10"}, "marketing_features": [{"name": "Everything in Base"}, {"name": "Priority support"}]},
    "prod_team": {"id": "prod_team", "object": "product", "active": True, "name": "Secure Flow Team", "description": "Per-seat tier",
                  "metadata": {}, "marketing_features": []},
    "prod_addon": {"id": "prod_addon", "object": "product", "active": True, "name": "Unrelated add-on", "metadata": {}, "marketing_features": []},
}


def _price(pid, product, amount, interval="month", tier=None, active=True, tiers=None, lookup=None):
    p = {"id": pid, "object": "price", "active": active, "currency": "usd", "unit_amount": amount, "product": product,
         "billing_scheme": "tiered" if tiers else "per_unit", "tiers_mode": "graduated" if tiers else None,
         "recurring": {"interval": interval, "interval_count": 1}, "lookup_key": lookup, "nickname": None,
         "metadata": {"tier_id": tier} if tier else {}, "livemode": False, "type": "recurring"}
    if tiers:
        p["_tiers"] = tiers
    return p


PRICES = {
    "price_base_monthly": _price("price_base_monthly", "prod_base", 25000, tier="base", lookup="secure_flow_base_monthly"),
    "price_pro_monthly": _price("price_pro_monthly", "prod_pro", 48000),  # tier only on the product
    "price_team_seats": _price("price_team_seats", "prod_team", None, tier="team",
                               tiers=[{"up_to": 5, "unit_amount": 9000, "flat_amount": None}, {"up_to": None, "unit_amount": 7000, "flat_amount": None}]),
    "price_addon": _price("price_addon", "prod_addon", 1500),  # not a tier
    "price_base_legacy": _price("price_base_legacy", "prod_base", 19900, tier="base", active=False),
}
state = {"customers": {}, "sessions": {}, "subs": {}, "portal_configs": {}, "portal_sessions": [], "setup_intents": {}, "last_created": 0}


def _auth(request: Request):
    if not request.headers.get("authorization", "").startswith("Bearer sk_test_"):
        raise HTTPException(status_code=401, detail={"error": {"message": "Invalid API key", "type": "invalid_request_error"}})


def _err(status: int, message: str):
    raise HTTPException(status_code=status, detail={"error": {"message": message, "type": "invalid_request_error"}})


def sign(payload: str, secret: str = WEBHOOK_SECRET, timestamp: int = None) -> str:
    t = timestamp or int(time.time())
    sig = hmac.new(secret.encode(), f"{t}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}"


def next_created() -> int:
    """Strictly increasing event timestamps, so the ordering of simulated events is unambiguous."""
    state["last_created"] = max(int(time.time()), state["last_created"] + 1)
    return state["last_created"]


def event(etype: str, obj: dict, created: int = None) -> dict:
    return {"id": f"evt_{uuid.uuid4().hex[:24]}", "object": "event", "type": etype, "created": created or next_created(),
            "livemode": False, "api_version": "2026-08-26.dahlia", "data": {"object": obj}}


def nested(pairs) -> dict:
    """Decode Stripe's form encoding (a[b][0][c]=v) into nested dicts and lists."""
    root: dict = {}
    for key, value in pairs:
        parts = key.replace("]", "").split("[")
        node = root
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            if last:
                node[part] = value
            else:
                node = node.setdefault(part, {})
    def listify(n):
        if isinstance(n, dict):
            if n and all(k.isdigit() for k in n):
                return [listify(n[k]) for k in sorted(n, key=int)]
            return {k: listify(v) for k, v in n.items()}
        return n
    return listify(root)


async def form_of(request: Request) -> dict:
    if request.method == "DELETE":
        return nested(request.query_params.multi_items())
    return nested((await request.form()).multi_items())


def render_price(pid: str, expand=()) -> dict:
    """A price as the API returns it: product as an id unless expanded; tiers only when expanded."""
    p = copy.deepcopy(PRICES[pid])
    tiers = p.pop("_tiers", None)
    if "data.product" in expand or "product" in expand:
        p["product"] = copy.deepcopy(PRODUCTS[p["product"]])
    if tiers and ("data.tiers" in expand or "tiers" in expand):
        p["tiers"] = tiers
    return p


def amount_of(pid: str, quantity: int = 1) -> int:
    p = PRICES[pid]
    if p["unit_amount"] is not None:
        return p["unit_amount"] * quantity
    total, prev = 0, 0
    for t in p["_tiers"]:
        cap = t["up_to"]
        units = (quantity if cap is None else min(quantity, cap)) - prev
        if units <= 0:
            break
        total += t["unit_amount"] * units
        if cap is None or quantity <= cap:
            break
        prev = cap
    return total


def price_from_data(data: dict) -> str:
    """Inline price_data creates a one-off price, as Stripe does."""
    if data.get("product") not in PRODUCTS:
        _err(400, f"No such product: '{data.get('product')}'")
    pid = f"price_inline_{uuid.uuid4().hex[:12]}"
    rec = data.get("recurring") or {}
    PRICES[pid] = _price(pid, data["product"], int(data["unit_amount"]), interval=rec.get("interval", "month"))
    PRICES[pid]["recurring"]["interval_count"] = int(rec.get("interval_count") or 1)
    PRICES[pid]["currency"] = data.get("currency", "usd")
    return pid


def _expand(request: Request):
    return [v for k, v in request.query_params.multi_items() if k.startswith("expand")]


# ---------------------------------------------------------------- catalog

@app.get("/v1/prices")
async def list_prices(request: Request):
    _auth(request)
    q = request.query_params
    lookup = [v for k, v in q.multi_items() if k.startswith("lookup_keys")]
    data = []
    for pid, p in PRICES.items():
        if pid.startswith("price_inline_"):
            continue
        if q.get("active") == "true" and not p["active"]:
            continue
        if lookup and p["lookup_key"] not in lookup:
            continue
        data.append(render_price(pid, _expand(request)))
    return {"object": "list", "data": data, "has_more": False, "url": "/v1/prices"}


@app.get("/v1/prices/{pid}")
async def get_price(pid: str, request: Request):
    _auth(request)
    if pid not in PRICES:
        _err(404, f"No such price: '{pid}'")
    return render_price(pid, _expand(request))


@app.get("/v1/products")
async def list_products(request: Request):
    _auth(request)
    return {"object": "list", "data": list(PRODUCTS.values()), "has_more": False, "url": "/v1/products"}


@app.post("/v1/products")
async def create_product(request: Request):
    _auth(request)
    form = await form_of(request)
    pid = f"prod_{uuid.uuid4().hex[:12]}"
    PRODUCTS[pid] = {"id": pid, "object": "product", "active": True, "name": form.get("name"), "description": form.get("description"),
                     "metadata": form.get("metadata") or {}, "marketing_features": []}
    return PRODUCTS[pid]


@app.post("/v1/prices")
async def create_price(request: Request):
    _auth(request)
    form = await form_of(request)
    if form.get("product") not in PRODUCTS:
        _err(400, f"No such product: '{form.get('product')}'")
    pid = f"price_{uuid.uuid4().hex[:12]}"
    rec = form.get("recurring") or {}
    tiers = [{"up_to": None if t.get("up_to") == "inf" else int(t["up_to"]), "unit_amount": int(t["unit_amount"]), "flat_amount": None}
             for t in form.get("tiers") or []] or None
    PRICES[pid] = _price(pid, form["product"], int(form["unit_amount"]) if form.get("unit_amount") else None, interval=rec.get("interval", "month"),
                         tiers=tiers, lookup=form.get("lookup_key"))
    PRICES[pid].update(currency=form.get("currency", "usd"), nickname=form.get("nickname"), metadata=form.get("metadata") or {})
    if tiers:
        PRICES[pid]["tiers_mode"] = form.get("tiers_mode", "graduated")
    return render_price(pid)


# ---------------------------------------------------------------- customers and checkout

@app.post("/v1/customers")
async def create_customer(request: Request):
    _auth(request)
    form = await form_of(request)
    cid = f"cus_{uuid.uuid4().hex[:14]}"
    state["customers"][cid] = {"id": cid, "object": "customer", "email": form.get("email"), "metadata": form.get("metadata") or {}}
    return state["customers"][cid]


@app.post("/v1/checkout/sessions")
async def create_session(request: Request):
    _auth(request)
    form = await form_of(request)
    mode = form.get("mode")
    methods = form.get("payment_method_types") or ["card"]
    sid = f"cs_test_{uuid.uuid4().hex[:20]}"
    session = {"id": sid, "object": "checkout.session", "mode": mode, "customer": form.get("customer"), "currency": form.get("currency", "usd"),
               "client_reference_id": form.get("client_reference_id"), "url": f"https://checkout.stripe.test/c/pay/{sid}",
               "metadata": form.get("metadata") or {}, "payment_method_types": methods,
               "_payment_method_options": form.get("payment_method_options") or {}}
    if mode == "subscription":
        items = []
        for li in form.get("line_items") or []:
            pid = li.get("price") or price_from_data(li.get("price_data") or {})
            if pid not in PRICES or not PRICES[pid]["active"]:
                _err(400, f"Price {pid} is not available")
            items.append({"price": pid, "quantity": int(li.get("quantity") or 1)})
        if not items:
            _err(400, "line_items required")
        session.update(_items=items, amount_total=sum(amount_of(i["price"], i["quantity"]) for i in items),
                       _sub_metadata=(form.get("subscription_data") or {}).get("metadata") or {})
    elif mode != "setup":
        _err(400, "unsupported mode")
    state["sessions"][sid] = session
    return {k: v for k, v in session.items() if not k.startswith("_")}


@app.get("/v1/setup_intents/{sid}")
async def get_setup_intent(sid: str, request: Request):
    _auth(request)
    if sid not in state["setup_intents"]:
        _err(404, f"No such setupintent: '{sid}'")
    return state["setup_intents"][sid]


# ---------------------------------------------------------------- portal

@app.get("/v1/billing_portal/configurations")
async def list_portal_configs(request: Request):
    _auth(request)
    return {"object": "list", "data": list(state["portal_configs"].values()), "has_more": False, "url": "/v1/billing_portal/configurations"}


@app.post("/v1/billing_portal/configurations")
async def create_portal_config(request: Request):
    _auth(request)
    form = await form_of(request)
    cid = f"bpc_{uuid.uuid4().hex[:14]}"
    state["portal_configs"][cid] = {"id": cid, "object": "billing_portal.configuration", "active": True,
                                    "features": form.get("features") or {}, "metadata": form.get("metadata") or {}}
    return state["portal_configs"][cid]


@app.post("/v1/billing_portal/sessions")
async def portal(request: Request):
    _auth(request)
    form = await form_of(request)
    if form.get("configuration") and form["configuration"] not in state["portal_configs"]:
        _err(400, "No such configuration")
    state["portal_sessions"].append({"customer": form.get("customer"), "configuration": form.get("configuration")})
    return {"id": f"bps_{uuid.uuid4().hex[:14]}", "object": "billing_portal.session", "url": f"https://billing.stripe.test/p/{form.get('customer')}"}


# ---------------------------------------------------------------- subscriptions

async def deliver(evt: dict, secret: str = WEBHOOK_SECRET):
    payload = json.dumps(evt)
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(WEBHOOK_URL, content=payload, headers={"Content-Type": "application/json", "Stripe-Signature": sign(payload, secret)})
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    state.setdefault("deliveries", []).append({"type": evt["type"], "status": r.status_code, "body": body})
    return {"type": evt["type"], "id": evt["id"], "status": r.status_code, "body": body}


def subscription_object(sub_id: str) -> dict:
    s = state["subs"][sub_id]
    return {"id": sub_id, "object": "subscription", "customer": s["customer"], "status": s["status"], "cancel_at_period_end": False,
            "metadata": s["metadata"], "default_payment_method": s.get("default_payment_method"),
            "items": {"object": "list", "data": [{"id": i["id"], "object": "subscription_item", "quantity": i["quantity"],
                                                  "price": render_price(i["price"]), "current_period_end": s["period_end"]} for i in s["items"]]}}


def invoice_object(sub_id: str) -> dict:
    s = state["subs"][sub_id]
    lines = [{"id": f"il_{n}", "amount": amount_of(i["price"], i["quantity"]),
              "pricing": {"type": "price_details", "price_details": {"price": i["price"], "product": PRICES[i["price"]]["product"]}}}
             for n, i in enumerate(s["items"])]
    total = sum(line["amount"] for line in lines)
    return {"id": f"in_{uuid.uuid4().hex[:14]}", "object": "invoice", "customer": s["customer"], "amount_paid": total, "amount_due": total,
            "currency": "usd", "status": "paid", "parent": {"type": "subscription_details", "subscription_details": {"subscription": sub_id}},
            "lines": {"object": "list", "data": lines}}


def _sub_or_404(sub_id: str) -> dict:
    if sub_id not in state["subs"]:
        _err(404, f"No such subscription: '{sub_id}'")
    return state["subs"][sub_id]


async def _updated(sub_id: str):
    await deliver(event("customer.subscription.updated", subscription_object(sub_id)))


@app.post("/v1/subscriptions/{sub_id}")
async def modify_subscription(sub_id: str, request: Request, background: BackgroundTasks):
    _auth(request)
    s = _sub_or_404(sub_id)
    form = await form_of(request)
    for change in form.get("items") or []:
        if change.get("id"):
            item = next((i for i in s["items"] if i["id"] == change["id"]), None)
            if not item:
                _err(400, f"No such subscription item: '{change['id']}'")
            if change.get("deleted") == "true":
                s["items"].remove(item)
                continue
            if change.get("price"):
                item["price"] = change["price"]
            if change.get("price_data"):
                item["price"] = price_from_data(change["price_data"])
            if change.get("quantity"):
                item["quantity"] = int(change["quantity"])
        else:
            pid = change.get("price") or price_from_data(change.get("price_data") or {})
            s["items"].append({"id": f"si_{uuid.uuid4().hex[:10]}", "price": pid, "quantity": int(change.get("quantity") or 1)})
    if "metadata" in form:
        s["metadata"] = {**s["metadata"], **form["metadata"]}
    if form.get("default_payment_method"):
        s["default_payment_method"] = form["default_payment_method"]
    s.setdefault("modifications", []).append({k: v for k, v in form.items() if k != "metadata"})
    background.add_task(_updated, sub_id)
    return subscription_object(sub_id)


@app.post("/v1/subscription_items")
async def create_item(request: Request, background: BackgroundTasks):
    _auth(request)
    form = await form_of(request)
    s = _sub_or_404(form.get("subscription"))
    pid = form.get("price") or price_from_data(form.get("price_data") or {})
    item = {"id": f"si_{uuid.uuid4().hex[:10]}", "price": pid, "quantity": int(form.get("quantity") or 1)}
    s["items"].append(item)
    background.add_task(_updated, form["subscription"])
    return {"id": item["id"], "object": "subscription_item", "price": render_price(pid), "quantity": item["quantity"]}


def _find_item(item_id: str):
    for sub_id, s in state["subs"].items():
        for item in s["items"]:
            if item["id"] == item_id:
                return sub_id, s, item
    _err(404, f"No such subscription item: '{item_id}'")


@app.post("/v1/subscription_items/{item_id}")
async def modify_item(item_id: str, request: Request, background: BackgroundTasks):
    _auth(request)
    form = await form_of(request)
    sub_id, s, item = _find_item(item_id)
    if form.get("price_data"):
        item["price"] = price_from_data(form["price_data"])
    if form.get("quantity"):
        item["quantity"] = int(form["quantity"])
    background.add_task(_updated, sub_id)
    return {"id": item_id, "object": "subscription_item", "price": render_price(item["price"]), "quantity": item["quantity"]}


@app.delete("/v1/subscription_items/{item_id}")
async def delete_item(item_id: str, request: Request, background: BackgroundTasks):
    _auth(request)
    sub_id, s, item = _find_item(item_id)
    s["items"].remove(item)
    background.add_task(_updated, sub_id)
    return {"id": item_id, "object": "subscription_item", "deleted": True}


# ---------------------------------------------------------------- simulation hooks

@app.post("/__complete/{session_id}")
async def complete(session_id: str):
    s = state["sessions"].get(session_id)
    if not s:
        raise HTTPException(status_code=404)
    session = {k: v for k, v in s.items() if not k.startswith("_")}
    if s["mode"] == "setup":
        seti = f"seti_{uuid.uuid4().hex[:14]}"
        method_type = s["payment_method_types"][0]
        state["setup_intents"][seti] = {"id": seti, "object": "setup_intent", "status": "succeeded",
                                        "payment_method": f"pm_{method_type}_{uuid.uuid4().hex[:8]}", "payment_method_types": [method_type]}
        return {"setup_intent": seti, "deliveries": [await deliver(event("checkout.session.completed", {**session, "status": "complete", "setup_intent": seti}))]}

    is_ach = s["payment_method_types"] == ["us_bank_account"]
    sub_id = f"sub_{uuid.uuid4().hex[:14]}"
    state["subs"][sub_id] = {"customer": s["customer"], "status": "active", "metadata": s["_sub_metadata"], "session": session_id,
                             "items": [{"id": f"si_{uuid.uuid4().hex[:10]}", **i} for i in s["_items"]],
                             "period_end": int(time.time()) + 30 * 86400, "payment_method_type": s["payment_method_types"][0],
                             "default_payment_method": f"pm_{s['payment_method_types'][0]}_initial"}
    completed = {**session, "status": "complete", "subscription": sub_id, "payment_status": "unpaid" if is_ach else "paid"}
    events = [event("checkout.session.completed", completed), event("customer.subscription.created", subscription_object(sub_id))]
    invoice = None
    if not is_ach:
        invoice = invoice_object(sub_id)
        events.append(event("invoice.paid", invoice))
    results = [await deliver(e) for e in events]
    return {"subscription_id": sub_id, "invoice_id": invoice["id"] if invoice else None, "deliveries": results}


@app.post("/__ach/{sub_id}/{outcome}")
async def ach_outcome(sub_id: str, outcome: str):
    s = _sub_or_404(sub_id)
    session = {k: v for k, v in state["sessions"][s["session"]].items() if not k.startswith("_")}
    invoice = invoice_object(sub_id)
    if outcome == "succeeded":
        events = [event("checkout.session.async_payment_succeeded", {**session, "subscription": sub_id, "payment_status": "paid"}),
                  event("invoice.paid", invoice)]
    elif outcome == "failed":
        s["status"] = "past_due"
        events = [event("checkout.session.async_payment_failed", {**session, "subscription": sub_id, "payment_status": "unpaid"}),
                  event("invoice.payment_failed", {**invoice, "status": "open", "amount_paid": 0})]
    else:
        raise HTTPException(status_code=404)
    return {"invoice_id": invoice["id"], "deliveries": [await deliver(e) for e in events]}


@app.post("/__change/{sub_id}")
async def change(sub_id: str, price: str, quantity: int = 1):
    s = _sub_or_404(sub_id)
    if price not in PRICES:
        raise HTTPException(status_code=404)
    tier_item = next(i for i in s["items"] if PRICES[i["price"]]["product"] in ("prod_base", "prod_pro", "prod_team"))
    tier_item.update(price=price, quantity=quantity)  # metadata keeps the checkout-time tier, as in Stripe
    return await deliver(event("customer.subscription.updated", subscription_object(sub_id)))


@app.post("/__price/{pid}")
async def patch_price(pid: str, request: Request):
    if pid not in PRICES:
        raise HTTPException(status_code=404)
    PRICES[pid].update(await request.json())
    return await deliver(event("price.updated", render_price(pid)))


@app.post("/__product/{prod}")
async def patch_product(prod: str, request: Request):
    if prod not in PRODUCTS:
        raise HTTPException(status_code=404)
    PRODUCTS[prod].update(await request.json())
    return await deliver(event("product.updated", copy.deepcopy(PRODUCTS[prod])))


@app.get("/__state")
async def get_state():
    subs = {sid: {**s, "items": [{**i, "unit_amount": PRICES[i["price"]]["unit_amount"], "product": PRICES[i["price"]]["product"]} for i in s["items"]]}
            for sid, s in state["subs"].items()}
    sessions = {sid: {k.lstrip("_"): v for k, v in sess.items()} for sid, sess in state["sessions"].items()}
    return {"subs": subs, "sessions": sessions, "portal_configs": state["portal_configs"], "portal_sessions": state["portal_sessions"],
            "fee_products": [p for p in PRODUCTS.values() if (p.get("metadata") or {}).get("kind") == "card_processing_fee"]}
