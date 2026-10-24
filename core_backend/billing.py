"""Stripe subscription billing: one base plan ($250.00 / month) and an idempotent webhook processor."""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

import stripe
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import BillingCustomer, StripeEvent, Subscription, User
from .security import app_env

logger = logging.getLogger(__name__)

PLAN = {
    "name": "Secure Flow Base",
    "lookup_key": "secure_flow_base_monthly",
    "amount": 25000,
    "currency": "usd",
    "interval": "month",
}
ACTIVE_STATUSES = ("active", "trialing", "past_due")
SUBSCRIPTION_EVENTS = ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted")
INVOICE_EVENTS = ("invoice.paid", "invoice.payment_succeeded", "invoice.payment_failed")


class BillingError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def secret_key() -> str:
    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key:
        raise BillingError("Stripe is not configured (set STRIPE_SECRET_KEY)", 503)
    if key.startswith(("sk_live_", "rk_live_")) and app_env() != "production":
        raise BillingError("Refusing to use a live Stripe key outside APP_ENV=production", 503)
    return key


def webhook_secret() -> str:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret:
        raise BillingError("Stripe webhooks are not configured (set STRIPE_WEBHOOK_SECRET)", 503)
    return secret


def configure_client():
    """Allow pointing the SDK at a local Stripe API double in development/tests."""
    base = os.getenv("STRIPE_API_BASE", "").strip()
    if base:
        if app_env() == "production":
            raise BillingError("STRIPE_API_BASE overrides are not allowed in production", 503)
        stripe.api_base = base.rstrip("/")


def frontend_url() -> str:
    return os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")


_price_cache: Dict[str, str] = {}


def plan_price_id() -> str:
    explicit = os.getenv("STRIPE_PRICE_ID", "").strip()
    if explicit:
        return explicit
    key = secret_key()
    if key in _price_cache:
        return _price_cache[key]
    configure_client()
    prices = stripe.Price.list(lookup_keys=[PLAN["lookup_key"]], active=True, limit=1, api_key=key)
    if not prices.data:
        raise BillingError("The $250/month price doesn't exist in this Stripe account yet. Run: python tools/stripe_setup.py", 503)
    price = prices.data[0]
    if price.unit_amount != PLAN["amount"] or price.currency != PLAN["currency"]:
        raise BillingError(f"Price {price.id} does not match the plan (expected {PLAN['amount']} {PLAN['currency']})", 503)
    _price_cache[key] = price.id
    return price.id


# --------------------------------------------------------------------------- #
# Customers, checkout and portal
# --------------------------------------------------------------------------- #

def ensure_customer(db: Session, user: User) -> str:
    row = db.query(BillingCustomer).filter(BillingCustomer.user_id == user.id).first()
    if row:
        return row.stripe_customer_id
    configure_client()
    customer = stripe.Customer.create(
        email=user.email, metadata={"user_id": str(user.id)}, api_key=secret_key(),
        idempotency_key=f"customer-{user.id}",
    )
    db.add(BillingCustomer(user_id=user.id, stripe_customer_id=customer.id))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return db.query(BillingCustomer).filter(BillingCustomer.user_id == user.id).one().stripe_customer_id
    return customer.id


def current_subscription(db: Session, user_id) -> Optional[Subscription]:
    subs = db.query(Subscription).filter(Subscription.user_id == user_id).order_by(Subscription.updated_at.desc()).all()
    for sub in subs:
        if sub.status in ACTIVE_STATUSES:
            return sub
    return subs[0] if subs else None


def create_checkout_session(db: Session, user: User) -> Dict[str, str]:
    configure_client()
    existing = current_subscription(db, user.id)
    if existing and existing.status in ACTIVE_STATUSES:
        raise BillingError("You already have an active subscription", 409)
    price_id = plan_price_id()
    customer_id = ensure_customer(db, user)
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        client_reference_id=str(user.id),
        line_items=[{"price": price_id, "quantity": 1}],
        subscription_data={"metadata": {"user_id": str(user.id)}},
        success_url=f"{frontend_url()}/billing?checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{frontend_url()}/billing?checkout=cancelled",
        api_key=secret_key(),
    )
    return {"id": session.id, "url": session.url}


def create_portal_session(db: Session, user: User) -> Dict[str, str]:
    row = db.query(BillingCustomer).filter(BillingCustomer.user_id == user.id).first()
    if not row:
        raise BillingError("No billing account yet; start a subscription first", 404)
    configure_client()
    portal = stripe.billing_portal.Session.create(customer=row.stripe_customer_id, return_url=f"{frontend_url()}/billing", api_key=secret_key())
    return {"url": portal.url}


# --------------------------------------------------------------------------- #
# Webhook processing
# --------------------------------------------------------------------------- #

def _ts(value) -> Optional[datetime]:
    return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(tzinfo=None) if value else None


def _user_for_customer(db: Session, customer_id: Optional[str]) -> Optional[UUID]:
    if not customer_id:
        return None
    row = db.query(BillingCustomer).filter(BillingCustomer.stripe_customer_id == customer_id).first()
    return row.user_id if row else None


def _valid_user(db: Session, value) -> Optional[UUID]:
    try:
        uid = UUID(str(value))
    except (TypeError, ValueError):
        return None
    return uid if db.query(User.id).filter(User.id == uid).first() else None


def _period_end(sub: Dict[str, Any]):
    # API versions from 2025-03-31 moved current_period_end onto subscription items.
    if sub.get("current_period_end"):
        return sub["current_period_end"]
    items = (sub.get("items") or {}).get("data") or []
    return items[0].get("current_period_end") if items else None


def _price_of(sub: Dict[str, Any]) -> Optional[str]:
    items = (sub.get("items") or {}).get("data") or []
    return ((items[0].get("price") or {}).get("id")) if items else None


def _invoice_subscription(inv: Dict[str, Any]) -> Optional[str]:
    if inv.get("subscription"):
        return inv["subscription"] if isinstance(inv["subscription"], str) else inv["subscription"].get("id")
    details = ((inv.get("parent") or {}).get("subscription_details") or {})
    return details.get("subscription")


def _handle_checkout_completed(db: Session, obj: Dict[str, Any], record: StripeEvent) -> str:
    user_id = _valid_user(db, obj.get("client_reference_id"))
    customer_id = obj.get("customer")
    record.user_id, record.object_id = user_id, obj.get("id")
    if not user_id or not customer_id:
        return "ignored"
    if not db.query(BillingCustomer).filter(BillingCustomer.user_id == user_id).first():
        db.add(BillingCustomer(user_id=user_id, stripe_customer_id=customer_id))
    return "processed"


def _handle_subscription(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    customer_id = obj.get("customer")
    user_id = _valid_user(db, (obj.get("metadata") or {}).get("user_id")) or _user_for_customer(db, customer_id)
    record.user_id, record.object_id = user_id, obj.get("id")
    if not user_id:
        raise BillingError(f"Subscription {obj.get('id')} belongs to an unknown customer {customer_id}")
    sub = db.query(Subscription).filter(Subscription.stripe_subscription_id == obj["id"]).first()
    if sub and sub.last_event_created > event["created"]:
        record.error = "Older than the last applied event for this subscription; skipped"
        return "ignored"
    if not sub:
        sub = Subscription(stripe_subscription_id=obj["id"], user_id=user_id, stripe_customer_id=customer_id, status=obj.get("status", "incomplete"))
        db.add(sub)
    sub.status = "canceled" if event["type"] == "customer.subscription.deleted" else obj.get("status", sub.status)
    sub.price_id = _price_of(obj) or sub.price_id
    sub.current_period_end = _ts(_period_end(obj)) or sub.current_period_end
    sub.cancel_at_period_end = bool(obj.get("cancel_at_period_end"))
    sub.last_event_created = event["created"]
    sub.updated_at = datetime.utcnow()
    return "processed"


def _handle_invoice(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    record.object_id = obj.get("id")
    record.user_id = _user_for_customer(db, obj.get("customer"))
    record.currency = obj.get("currency")
    record.amount = obj.get("amount_paid") if event["type"] != "invoice.payment_failed" else obj.get("amount_due")
    sub_id = _invoice_subscription(obj)
    if sub_id and event["type"] == "invoice.payment_failed":
        sub = db.query(Subscription).filter(Subscription.stripe_subscription_id == sub_id).first()
        if sub and sub.last_event_created <= event["created"] and sub.status == "active":
            sub.status = "past_due"
    return "processed"


def process_event(db: Session, event: Dict[str, Any]) -> str:
    """Apply one verified Stripe event exactly once. Returns processed | ignored | duplicate."""
    existing = db.query(StripeEvent).filter(StripeEvent.id == event["id"]).first()
    if existing and existing.status in ("processed", "ignored"):
        return "duplicate"
    record = existing or StripeEvent(id=event["id"], type=event["type"], livemode=bool(event.get("livemode")), event_created=int(event["created"]), payload=event, status="received")
    if not existing:
        db.add(record)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return "duplicate"

    obj = (event.get("data") or {}).get("object") or {}
    try:
        if event["type"] == "checkout.session.completed":
            outcome = _handle_checkout_completed(db, obj, record)
        elif event["type"] in SUBSCRIPTION_EVENTS:
            outcome = _handle_subscription(db, event, obj, record)
        elif event["type"] in INVOICE_EVENTS:
            outcome = _handle_invoice(db, event, obj, record)
        else:
            outcome = "ignored"
        record.status, record.processed_at = outcome, datetime.utcnow()
        if outcome == "processed":
            record.error = None
        db.commit()
        return outcome
    except Exception as exc:
        db.rollback()
        failed = db.query(StripeEvent).filter(StripeEvent.id == event["id"]).first()
        if failed is None:
            failed = StripeEvent(id=event["id"], type=event["type"], livemode=bool(event.get("livemode")), event_created=int(event["created"]), payload=event)
            db.add(failed)
        failed.status, failed.error = "failed", str(exc)[:1000]
        db.commit()
        logger.error(f"Stripe event {event['id']} ({event['type']}) failed: {exc}")
        raise
