"""Milestone 4: Stripe subscription checkout, status, ledger and the webhook controller."""

import json
import logging
from typing import Literal, Optional

import stripe
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..billing import (
    INVOICE_EVENTS, BillingError, active_tiers, change_tier, create_checkout_session, create_payment_method_session,
    create_portal_session, current_subscription, payment_options, price_amount, process_event, quote,
    subscription_payment_status, tier_view, webhook_secret,
)
from ..database import get_db
from ..models import BillingPrice, StripeEvent, User
from .auth import HTTPAuthCredentials, security, verify_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["billing"])

MAX_WEBHOOK_BYTES = 512 * 1024
WEBHOOK_TOLERANCE_SECONDS = 300


def _user(db: Session, credentials: HTTPAuthCredentials) -> User:
    return db.query(User).filter(User.id == verify_token(credentials, db)).first()


def _billing_call(fn, *args):
    try:
        return fn(*args)
    except BillingError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    except stripe.StripeError as exc:
        logger.error(f"Stripe API error: {exc}")
        raise HTTPException(status_code=502, detail=f"Stripe rejected the request: {getattr(exc, 'user_message', None) or exc.__class__.__name__}")


# Billing endpoints are plain functions: FastAPI runs them in its threadpool, so the blocking
# Stripe SDK calls never stall the event loop (or the webhook deliveries they trigger).

PRICE_ID = r"^price_[A-Za-z0-9_]{1,60}$"


class CheckoutRequest(BaseModel):
    price_id: Optional[str] = Field(None, pattern=PRICE_ID)
    payment_method: Optional[Literal["ach", "card"]] = None


class ChangeTierRequest(BaseModel):
    price_id: str = Field(..., pattern=PRICE_ID)


@router.get("/api/billing/plans")
def plans(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    """Active subscription tiers, as defined in Stripe (synced, and kept current by webhooks)."""
    verify_token(credentials, db)
    return [tier_view(t) for t in _billing_call(active_tiers, db)]


@router.get("/api/billing/payment-options")
def billing_payment_options(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    verify_token(credentials, db)
    return _billing_call(payment_options)


@router.get("/api/billing/quote")
def billing_quote(
    price_id: str = Query(..., pattern=PRICE_ID),
    payment_method: Literal["ach", "card"] = Query(...),
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Per-period price of a tier with the chosen payment method: base, card fee and total."""
    verify_token(credentials, db)
    return _billing_call(quote, db, price_id, payment_method)


@router.post("/api/billing/checkout-session")
def checkout_session(body: Optional[CheckoutRequest] = Body(None), credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    body = body or CheckoutRequest()
    return _billing_call(create_checkout_session, db, _user(db, credentials), body.price_id, body.payment_method)


@router.post("/api/billing/change-tier")
def billing_change_tier(body: ChangeTierRequest, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    return _billing_call(change_tier, db, _user(db, credentials), body.price_id)


@router.post("/api/billing/payment-method-session")
def payment_method_session(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    """Replace the card or bank account on file (same type as chosen at checkout)."""
    return _billing_call(create_payment_method_session, db, _user(db, credentials))


@router.post("/api/billing/portal-session")
def portal_session(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    return _billing_call(create_portal_session, db, _user(db, credentials))


@router.get("/api/billing/subscription")
def subscription(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    sub = current_subscription(db, verify_token(credentials, db))
    if not sub:
        return {"status": "none"}
    catalog = db.get(BillingPrice, sub.price_id) if sub.price_id else None
    if sub.unit_amount is not None:
        base = sub.unit_amount * (sub.quantity or 1)
    else:
        base = price_amount(catalog, sub.quantity or 1) if catalog is not None else None
    return {
        "status": sub.status,
        "stripe_subscription_id": sub.stripe_subscription_id,
        "tier_id": sub.tier_id,
        "price_id": sub.price_id,
        "product_id": sub.product_id,
        "unit_amount": sub.unit_amount,
        "currency": sub.currency,
        "interval": sub.recurring_interval,
        "interval_count": sub.recurring_interval_count,
        "quantity": sub.quantity,
        "items": sub.items or [],
        "metadata": sub.subscription_metadata or {},
        "payment_method": sub.payment_method,
        "payment_status": subscription_payment_status(db, sub),
        "fee_bps": sub.fee_bps or 0,
        "fee_amount": sub.fee_amount or 0,
        "base_amount": base,
        "total_amount": None if base is None else base + (sub.fee_amount or 0),
        "current_period_end": sub.current_period_end,
        "cancel_at_period_end": sub.cancel_at_period_end,
        "plan": tier_view(catalog),
    }


@router.get("/api/billing/ledger")
def ledger(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    """Payment events for reconciliation against the Stripe Dashboard."""
    user_id = verify_token(credentials, db)
    rows = (
        db.query(StripeEvent)
        .filter(StripeEvent.user_id == user_id, StripeEvent.type.in_(INVOICE_EVENTS))
        .order_by(StripeEvent.event_created.desc()).limit(200).all()
    )
    return [
        {"event_id": r.id, "type": r.type, "invoice_id": r.object_id, "amount": r.amount, "fee_amount": r.fee_amount or 0,
         "currency": r.currency, "payment_method": r.payment_method, "price_id": r.price_id, "tier_id": r.tier_id,
         "subscription_id": r.subscription_id, "status": r.status, "created": r.event_created}
        for r in rows
    ]


@router.post("/api/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None, alias="Stripe-Signature"), db: Session = Depends(get_db)):
    try:
        secret = webhook_secret()
    except BillingError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    payload = await request.body()
    if len(payload) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")
    try:
        stripe.WebhookSignature.verify_header(payload, stripe_signature, secret, tolerance=WEBHOOK_TOLERANCE_SECONDS)
        event = json.loads(payload)
    except (stripe.SignatureVerificationError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    if not isinstance(event, dict) or not all(k in event for k in ("id", "type", "created")):
        raise HTTPException(status_code=400, detail="Malformed event")
    try:
        outcome = await run_in_threadpool(process_event, db, event)
    except Exception:
        # Non-2xx makes Stripe retry later; the failure is recorded on the event row.
        raise HTTPException(status_code=500, detail="Event processing failed; Stripe will retry")
    return {"received": True, "outcome": outcome}
