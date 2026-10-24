"""Milestone 4: Stripe subscription checkout, status, ledger and the webhook controller."""

import json
import logging

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from ..billing import PLAN, BillingError, create_checkout_session, create_portal_session, current_subscription, process_event, webhook_secret
from ..database import get_db
from ..models import StripeEvent, User
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


@router.get("/api/billing/plan")
async def plan(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    verify_token(credentials, db)
    return {"name": PLAN["name"], "amount": PLAN["amount"], "currency": PLAN["currency"], "interval": PLAN["interval"]}


@router.post("/api/billing/checkout-session")
async def checkout_session(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    return _billing_call(create_checkout_session, db, _user(db, credentials))


@router.post("/api/billing/portal-session")
async def portal_session(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    return _billing_call(create_portal_session, db, _user(db, credentials))


@router.get("/api/billing/subscription")
async def subscription(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    sub = current_subscription(db, verify_token(credentials, db))
    if not sub:
        return {"status": "none"}
    return {
        "status": sub.status,
        "stripe_subscription_id": sub.stripe_subscription_id,
        "price_id": sub.price_id,
        "current_period_end": sub.current_period_end,
        "cancel_at_period_end": sub.cancel_at_period_end,
        "plan": {"name": PLAN["name"], "amount": PLAN["amount"], "currency": PLAN["currency"], "interval": PLAN["interval"]},
    }


@router.get("/api/billing/ledger")
async def ledger(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    """Payment events for reconciliation against the Stripe Dashboard."""
    user_id = verify_token(credentials, db)
    rows = (
        db.query(StripeEvent)
        .filter(StripeEvent.user_id == user_id, StripeEvent.type.in_(["invoice.paid", "invoice.payment_succeeded", "invoice.payment_failed"]))
        .order_by(StripeEvent.event_created.desc()).limit(200).all()
    )
    return [
        {"event_id": r.id, "type": r.type, "invoice_id": r.object_id, "amount": r.amount, "currency": r.currency, "status": r.status, "created": r.event_created}
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
        outcome = process_event(db, event)
    except Exception:
        # Non-2xx makes Stripe retry later; the failure is recorded on the event row.
        raise HTTPException(status_code=500, detail="Event processing failed; Stripe will retry")
    return {"received": True, "outcome": outcome}
