"""
Stripe subscription billing with a dynamic tier catalog and an idempotent webhook processor.

Tiers are defined in Stripe, not in code: any active recurring Price whose metadata (or whose
product's metadata) carries tier_id is a Secure Flow tier. The catalog is mirrored into
billing_prices by a periodic sync and by price/product webhooks, and every subscription records
the tier, price, product, amounts and metadata exactly as Stripe transmits them.

Amounts always come from Stripe's own price, checkout and invoice fields. Metadata identifies the
tier (tier_id, price_id, user_id) but is never trusted for a dollar figure, and the browser can
only choose a price_id that is in the active catalog.

Payment is a one-time choice at checkout between a US bank account (ACH, no fee) and a card
(a processing fee line item); see "Payment methods and the card processing fee" below.
"""

import logging
import os
import time
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Dict, List, Optional
from uuid import UUID

import stripe
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import BillingCustomer, BillingPrice, StripeEvent, Subscription, User
from .security import app_env

logger = logging.getLogger(__name__)

TIER_KEY = "tier_id"
ACTIVE_STATUSES = ("active", "trialing", "past_due")
SUBSCRIPTION_EVENTS = ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted")
INVOICE_EVENTS = ("invoice.paid", "invoice.payment_succeeded", "invoice.payment_failed")
CHECKOUT_ASYNC_EVENTS = ("checkout.session.async_payment_succeeded", "checkout.session.async_payment_failed")
PRICE_EVENTS = ("price.created", "price.updated", "price.deleted")
PRODUCT_EVENTS = ("product.created", "product.updated", "product.deleted")
CATALOG_TTL_SECONDS = int(os.getenv("STRIPE_CATALOG_TTL_SECONDS", "600"))


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


def _plain(obj) -> Dict[str, Any]:
    return obj.to_dict() if hasattr(obj, "to_dict") else dict(obj or {})


def _id(value) -> Optional[str]:
    if isinstance(value, dict):
        return value.get("id")
    return value if isinstance(value, str) else None


# --------------------------------------------------------------------------- #
# Tier catalog
# --------------------------------------------------------------------------- #

_last_sync = {"at": 0.0}


def _tier_of(price: Dict[str, Any], product: Optional[Dict[str, Any]], row: Optional[BillingPrice] = None) -> Optional[str]:
    return (
        (price.get("metadata") or {}).get(TIER_KEY)
        or ((product or {}).get("metadata") or {}).get(TIER_KEY)
        or (row.tier_id if row else None)
    )


def _apply_product(row: BillingPrice, product: Dict[str, Any], stamp: int):
    if row.product_event_created > stamp:
        return
    row.product_name = product.get("name")
    row.product_description = product.get("description")
    row.product_metadata = product.get("metadata") or {}
    row.features = [f.get("name") for f in (product.get("marketing_features") or []) if f.get("name")]
    tier = (product.get("metadata") or {}).get(TIER_KEY)
    if tier and not (row.price_metadata or {}).get(TIER_KEY):
        row.tier_id = tier
    if product.get("active") is False:
        row.active = False
    row.product_event_created = stamp
    row.updated_at = datetime.utcnow()


def _upsert_price(db: Session, price: Dict[str, Any], product: Optional[Dict[str, Any]], stamp: int) -> Optional[BillingPrice]:
    """Register a Stripe price as transmitted. Returns None for prices that are not tiers."""
    if isinstance(price.get("product"), dict):
        product = product or price["product"]
    row = db.get(BillingPrice, price["id"])
    tier = _tier_of(price, product, row)
    if not tier:
        return None
    if not row:
        row = BillingPrice(id=price["id"], currency=price.get("currency") or "usd", product_id=_id(price.get("product")) or (product or {}).get("id"),
                           price_metadata={}, product_metadata={}, features=[], price_event_created=0, product_event_created=0)
        db.add(row)
    if row.price_event_created <= stamp:
        # Fields absent from the payload keep their stored value; present ones (even null) win.
        for field, column in (("nickname", "nickname"), ("lookup_key", "lookup_key"), ("unit_amount", "unit_amount"),
                              ("tiers_mode", "tiers_mode"), ("tiers", "tiers")):
            if field in price:
                setattr(row, column, price[field])
        if "billing_scheme" in price:
            row.billing_scheme = price["billing_scheme"] or "per_unit"
        if "recurring" in price:
            recurring = price["recurring"] or {}
            row.recurring_interval = recurring.get("interval")
            row.recurring_interval_count = recurring.get("interval_count")
        if "metadata" in price:
            row.price_metadata = price["metadata"] or {}
        if "livemode" in price:
            row.livemode = bool(price["livemode"])
        row.product_id = _id(price.get("product")) or (product or {}).get("id") or row.product_id
        row.tier_id = (row.price_metadata or {}).get(TIER_KEY) or ((product or {}).get("metadata") or {}).get(TIER_KEY) or row.tier_id or tier
        row.currency = price.get("currency") or row.currency
        row.active = bool(price.get("active", row.active if row.active is not None else True)) and bool(row.recurring_interval)
        row.price_event_created = stamp
        row.updated_at = datetime.utcnow()
    if product:
        _apply_product(row, product, stamp)
    return row


def sync_catalog(db: Session) -> int:
    """Mirror every active recurring tier price from Stripe. Returns the number of active tiers."""
    key = secret_key()
    configure_client()
    stamp = int(time.time())
    seen = set()
    prices = stripe.Price.list(active=True, type="recurring", limit=100, expand=["data.product", "data.tiers"], api_key=key)
    for obj in prices.auto_paging_iter():
        price = _plain(obj)
        row = _upsert_price(db, price, price.get("product") if isinstance(price.get("product"), dict) else None, stamp)
        if row:
            seen.add(row.id)
    for row in db.query(BillingPrice).filter(BillingPrice.active.is_(True)).all():
        if row.id not in seen and row.livemode == (not key.startswith(("sk_test_", "rk_test_"))):
            row.active = False
            row.updated_at = datetime.utcnow()
    db.commit()
    _last_sync["at"] = time.time()
    return len(seen)


def active_tiers(db: Session, refresh: bool = False) -> List[BillingPrice]:
    if refresh or time.time() - _last_sync["at"] > CATALOG_TTL_SECONDS:
        try:
            sync_catalog(db)
        except (stripe.StripeError, BillingError) as exc:
            db.rollback()
            # Serve the last mirrored catalog; webhooks keep it current between syncs.
            logger.warning(f"Stripe catalog sync failed, serving cached tiers: {exc}")
            if isinstance(exc, BillingError) and not db.query(BillingPrice.id).first():
                raise
    return (
        db.query(BillingPrice)
        .filter(BillingPrice.active.is_(True), BillingPrice.tier_id.isnot(None))
        .order_by(BillingPrice.unit_amount.asc().nullslast(), BillingPrice.tier_id.asc())
        .all()
    )


def tier_view(row: Optional[BillingPrice]) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "price_id": row.id,
        "tier_id": row.tier_id,
        "product_id": row.product_id,
        "name": row.product_name or row.nickname or row.tier_id,
        "description": row.product_description,
        "nickname": row.nickname,
        "billing_scheme": row.billing_scheme,
        "unit_amount": row.unit_amount,
        "currency": row.currency,
        "tiers_mode": row.tiers_mode,
        "tiers": row.tiers,
        "interval": row.recurring_interval,
        "interval_count": row.recurring_interval_count,
        "features": row.features or [],
        "metadata": {**(row.product_metadata or {}), **(row.price_metadata or {})},
        "active": row.active,
    }


# --------------------------------------------------------------------------- #
# Payment methods and the card processing fee
# --------------------------------------------------------------------------- #
#
# The customer chooses once, at checkout: "ach" (US bank account, no fee) or "card" (a processing
# fee line item of CARD_FEE_PERCENT on top of the tier price). Bank details are entered on
# Stripe's Checkout page and never reach this server. The fee is calculated here from Stripe's own
# price (never from metadata), billed as its own recurring line so every invoice shows it, and
# re-aligned whenever the tier or quantity changes.

PAYMENT_METHODS = ("ach", "card")
STRIPE_METHOD_TYPES = {"ach": "us_bank_account", "card": "card"}
FEE_PRODUCT_KIND = "card_processing_fee"
CARD_NETWORK_SURCHARGE_CAP_BPS = 300  # Visa's surcharge cap (3%); main.py warns when the fee is higher


def card_fee_bps() -> int:
    """CARD_FEE_PERCENT in basis points (5 -> 500). Defaults to 5%."""
    raw = os.getenv("CARD_FEE_PERCENT", "5").strip()
    try:
        pct = Decimal(raw)
    except InvalidOperation:
        raise BillingError("CARD_FEE_PERCENT must be a number such as 5 or 2.9", 503)
    if not pct.is_finite() or pct < 0 or pct > 10:
        raise BillingError("CARD_FEE_PERCENT must be between 0 and 10", 503)
    return int((pct * 100).to_integral_value(rounding=ROUND_HALF_UP))


def fee_for(amount: int, bps: int) -> int:
    """Fee in the smallest currency unit, rounded half up (10000 at 500 bps -> 500)."""
    return int((Decimal(amount) * bps / 10000).to_integral_value(rounding=ROUND_HALF_UP))


def price_amount(row: BillingPrice, quantity: int) -> Optional[int]:
    """One period of `quantity` units at a Stripe price: per-unit, graduated or volume tiers."""
    if row.billing_scheme != "tiered":
        return None if row.unit_amount is None else row.unit_amount * quantity
    tiers = row.tiers or []
    if not tiers:
        return None
    if row.tiers_mode == "volume":
        for t in tiers:
            if t.get("up_to") is None or quantity <= t["up_to"]:
                return (t.get("unit_amount") or 0) * quantity + (t.get("flat_amount") or 0)
        return None
    total, previous_cap = 0, 0
    for t in tiers:  # graduated: each band is priced separately
        cap = t.get("up_to")
        units = (quantity if cap is None else min(quantity, cap)) - previous_cap
        if units <= 0:
            break
        total += (t.get("unit_amount") or 0) * units + (t.get("flat_amount") or 0)
        if cap is None or quantity <= cap:
            break
        previous_cap = cap
    return total


_fee_product: Dict[str, str] = {}


def fee_product_id() -> str:
    """The Stripe product that carries card fee line items (created once per Stripe account)."""
    key = secret_key()
    if key in _fee_product:
        return _fee_product[key]
    configure_client()
    for product in stripe.Product.list(active=True, limit=100, api_key=key).auto_paging_iter():
        if (_plain(product).get("metadata") or {}).get("kind") == FEE_PRODUCT_KIND:
            _fee_product[key] = product.id
            return product.id
    product = stripe.Product.create(
        name="Card processing fee", description="Added to subscriptions paid by card",
        metadata={"app": "secure-flow", "kind": FEE_PRODUCT_KIND}, api_key=key,
        idempotency_key="secure-flow-card-fee-product",
    )
    _fee_product[key] = product.id
    return product.id


def _fee_price_data(currency: str, interval: str, interval_count: Optional[int], amount: int) -> Dict[str, Any]:
    return {"currency": currency, "product": fee_product_id(), "unit_amount": amount,
            "recurring": {"interval": interval, "interval_count": interval_count or 1}}


def _quote(tier: BillingPrice, payment_method: str, quantity: int = 1, bps: Optional[int] = None) -> Dict[str, Any]:
    base = price_amount(tier, quantity)
    if base is None:
        raise BillingError("This tier's price cannot be calculated", 409)
    if bps is None:
        bps = card_fee_bps() if payment_method == "card" else 0
    fee = fee_for(base, bps) if payment_method == "card" else 0
    return {
        "price_id": tier.id, "tier_id": tier.tier_id, "payment_method": payment_method, "quantity": quantity,
        "currency": tier.currency, "interval": tier.recurring_interval, "interval_count": tier.recurring_interval_count,
        "base_amount": base, "fee_bps": bps if payment_method == "card" else 0, "fee_amount": fee, "total_amount": base + fee,
    }


def _check_method(payment_method: Optional[str]) -> str:
    if payment_method not in PAYMENT_METHODS:
        raise BillingError("Choose how to pay: payment_method must be 'ach' or 'card'", 422)
    return payment_method


def payment_options() -> Dict[str, Any]:
    bps = card_fee_bps()
    return {"methods": [
        {"id": "ach", "label": "Bank account (ACH)", "fee_bps": 0, "fee_percent": 0.0},
        {"id": "card", "label": "Credit or debit card", "fee_bps": bps, "fee_percent": bps / 100},
    ]}


def quote(db: Session, price_id: str, payment_method: Optional[str]) -> Dict[str, Any]:
    _check_method(payment_method)
    tier = next((t for t in active_tiers(db) if t.id == price_id), None)
    if not tier:
        raise BillingError("That tier is not available", 422)
    return _quote(tier, payment_method)


# --------------------------------------------------------------------------- #
# Customers, checkout, tier changes and the portal
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


def _resolve_tier(db: Session, price_id: Optional[str]) -> BillingPrice:
    tiers = active_tiers(db)
    if not tiers:
        raise BillingError("No subscription tiers are configured in Stripe yet. Run: python tools/stripe_setup.py", 503)
    if not price_id:
        if len(tiers) == 1:
            return tiers[0]
        raise BillingError("Choose a tier (price_id)", 422)
    row = next((t for t in tiers if t.id == price_id), None)
    if not row:
        raise BillingError("That tier is not available", 422)
    # Re-check with Stripe at the moment of purchase; the mirror could be a few minutes old.
    live = _plain(stripe.Price.retrieve(price_id, expand=["product"], api_key=secret_key()))
    product = live.get("product") if isinstance(live.get("product"), dict) else {}
    if not live.get("active") or not live.get("recurring") or product.get("active") is False:
        row.active = False
        db.commit()
        raise BillingError("That tier is no longer available", 409)
    return row


def _method_params(payment_method: str) -> Dict[str, Any]:
    params: Dict[str, Any] = {"payment_method_types": [STRIPE_METHOD_TYPES[payment_method]]}
    if payment_method == "ach":
        # Instant verification through Financial Connections, or manual routing/account entry
        # with micro-deposit verification. Either way the numbers are entered on Stripe's page.
        params["payment_method_options"] = {"us_bank_account": {"verification_method": "automatic", "financial_connections": {"permissions": ["payment_method"]}}}
    return params


def create_checkout_session(db: Session, user: User, price_id: Optional[str] = None, payment_method: Optional[str] = None) -> Dict[str, Any]:
    _check_method(payment_method)
    configure_client()
    existing = current_subscription(db, user.id)
    if existing and existing.status in ACTIVE_STATUSES:
        raise BillingError("You already have an active subscription; switch tier from the billing page", 409)
    tier = _resolve_tier(db, price_id)
    q = _quote(tier, payment_method)
    customer_id = ensure_customer(db, user)
    metadata = {
        "user_id": str(user.id), TIER_KEY: tier.tier_id, "price_id": tier.id, "payment_method": payment_method,
        "fee_bps": str(q["fee_bps"]), "base_amount": str(q["base_amount"]), "fee_amount": str(q["fee_amount"]),
    }
    line_items = [{"price": tier.id, "quantity": 1}]
    if q["fee_amount"]:
        line_items.append({"price_data": _fee_price_data(tier.currency, tier.recurring_interval, tier.recurring_interval_count, q["fee_amount"]), "quantity": 1})
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        client_reference_id=str(user.id),
        line_items=line_items,
        metadata=metadata,
        subscription_data={"metadata": metadata},
        success_url=f"{frontend_url()}/billing?checkout=success&session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{frontend_url()}/billing?checkout=cancelled",
        api_key=secret_key(),
        **_method_params(payment_method),
    )
    return {"id": session.id, "url": session.url, **q}


def _sub_items(sub: Subscription):
    items = sub.items or []
    return next((i for i in items if i.get("kind") != "fee"), None), [i for i in items if i.get("kind") == "fee"]


def change_tier(db: Session, user: User, price_id: Optional[str]) -> Dict[str, Any]:
    """Move an active subscription to another tier, re-pricing the card fee in the same update."""
    configure_client()
    sub = current_subscription(db, user.id)
    if not sub or sub.status not in ("active", "trialing"):
        raise BillingError("There is no active subscription to change", 409)
    if not price_id or sub.price_id == price_id:
        raise BillingError("Choose a different tier", 422)
    tier = _resolve_tier(db, price_id)
    if sub.currency and tier.currency != sub.currency:
        raise BillingError("That tier is billed in a different currency; cancel and subscribe to it instead", 409)
    tier_item, fee_items = _sub_items(sub)
    if not tier_item or not tier_item.get("item_id"):
        raise BillingError("The subscription is still being set up; try again in a moment", 409)
    quantity = tier_item.get("quantity") or 1
    method = sub.payment_method or "ach"
    # The fee rate is fixed when the customer subscribes.
    q = _quote(tier, method, quantity, bps=sub.fee_bps if method == "card" and sub.fee_bps is not None else None)
    items: List[Dict[str, Any]] = [{"id": tier_item["item_id"], "price": tier.id, "quantity": quantity}]
    if method == "card" and q["fee_amount"]:
        fee = {"price_data": _fee_price_data(tier.currency, tier.recurring_interval, tier.recurring_interval_count, q["fee_amount"]), "quantity": 1}
        items.append({"id": fee_items[0]["item_id"], **fee} if fee_items else fee)
        items += [{"id": extra["item_id"], "deleted": True} for extra in fee_items[1:]]
    else:
        items += [{"id": extra["item_id"], "deleted": True} for extra in fee_items]
    metadata = {**(sub.subscription_metadata or {}), TIER_KEY: tier.tier_id, "price_id": tier.id,
                "base_amount": str(q["base_amount"]), "fee_amount": str(q["fee_amount"])}
    stripe.Subscription.modify(sub.stripe_subscription_id, items=items, metadata=metadata, proration_behavior="create_prorations", api_key=secret_key())
    return q


_portal_config: Dict[str, str] = {}
PORTAL_CONFIG_VERSION = "1"


def portal_configuration_id() -> str:
    """
    Billing portal for invoices and cancellation only. Payment method changes and tier changes are
    disabled there: the payment method is a fixed choice (bank vs card) and tier changes go through
    change_tier() so the card fee is always re-priced.
    """
    key = secret_key()
    if key in _portal_config:
        return _portal_config[key]
    for cfg in stripe.billing_portal.Configuration.list(active=True, limit=100, api_key=key).auto_paging_iter():
        meta = _plain(cfg).get("metadata") or {}
        if meta.get("app") == "secure-flow" and meta.get("version") == PORTAL_CONFIG_VERSION:
            _portal_config[key] = cfg.id
            return cfg.id
    cfg = stripe.billing_portal.Configuration.create(
        business_profile={"headline": "Secure Flow billing"},
        features={
            "invoice_history": {"enabled": True},
            "customer_update": {"enabled": False},
            "payment_method_update": {"enabled": False},
            "subscription_cancel": {"enabled": True, "mode": "at_period_end"},
            "subscription_update": {"enabled": False},
        },
        metadata={"app": "secure-flow", "version": PORTAL_CONFIG_VERSION},
        api_key=key,
    )
    _portal_config[key] = cfg.id
    return cfg.id


def create_portal_session(db: Session, user: User) -> Dict[str, str]:
    row = db.query(BillingCustomer).filter(BillingCustomer.user_id == user.id).first()
    if not row:
        raise BillingError("No billing account yet; start a subscription first", 404)
    configure_client()
    portal = stripe.billing_portal.Session.create(
        customer=row.stripe_customer_id, configuration=portal_configuration_id(),
        return_url=f"{frontend_url()}/billing", api_key=secret_key(),
    )
    return {"url": portal.url}


def create_payment_method_session(db: Session, user: User) -> Dict[str, str]:
    """Replace the card or bank account on file, keeping the same payment method type."""
    configure_client()
    sub = current_subscription(db, user.id)
    if not sub or sub.status not in ACTIVE_STATUSES or sub.payment_method not in PAYMENT_METHODS:
        raise BillingError("There is no active subscription to update", 409)
    customer = db.query(BillingCustomer).filter(BillingCustomer.user_id == user.id).first()
    session = stripe.checkout.Session.create(
        mode="setup",
        customer=customer.stripe_customer_id,
        currency=sub.currency or "usd",
        metadata={"purpose": "update_payment_method", "user_id": str(user.id), "subscription_id": sub.stripe_subscription_id},
        success_url=f"{frontend_url()}/billing?payment_method=updated",
        cancel_url=f"{frontend_url()}/billing",
        api_key=secret_key(),
        **_method_params(sub.payment_method),
    )
    return {"id": session.id, "url": session.url}


def subscription_payment_status(db: Session, sub: Subscription) -> str:
    """paid | failed | processing (bank payments clear in a few business days) | pending."""
    latest = (
        db.query(StripeEvent)
        .filter(StripeEvent.subscription_id == sub.stripe_subscription_id, StripeEvent.type.in_(INVOICE_EVENTS + CHECKOUT_ASYNC_EVENTS))
        .order_by(StripeEvent.event_created.desc(), StripeEvent.received_at.desc())
        .first()
    )
    if latest is None:
        return "processing" if sub.payment_method == "ach" else "pending"
    return "failed" if latest.type in ("invoice.payment_failed", "checkout.session.async_payment_failed") else "paid"


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


def _items(sub: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (sub.get("items") or {}).get("data") or []


def _period_end(sub: Dict[str, Any]):
    # API versions from 2025-03-31 moved current_period_end onto subscription items.
    if sub.get("current_period_end"):
        return sub["current_period_end"]
    items = _items(sub)
    return items[0].get("current_period_end") if items else None


def _invoice_subscription(inv: Dict[str, Any]) -> Optional[str]:
    if inv.get("subscription"):
        return _id(inv["subscription"])
    details = ((inv.get("parent") or {}).get("subscription_details") or {})
    return details.get("subscription")


def _fee_product_or_none() -> Optional[str]:
    try:
        return fee_product_id()
    except BillingError:
        return None


def _invoice_lines(inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Invoice lines as (price_id, product_id, amount), for old (line.price) and new (line.pricing) API shapes."""
    out = []
    for line in ((inv.get("lines") or {}).get("data") or []):
        price, product = line.get("price"), None
        if price:
            product = _id(price.get("product")) if isinstance(price, dict) else None
            price = _id(price)
        else:
            details = ((line.get("pricing") or {}).get("price_details") or {})
            price, product = _id(details.get("price")), _id(details.get("product"))
        out.append({"price_id": price, "product_id": product, "amount": line.get("amount")})
    return out


def _invoice_price(inv: Dict[str, Any], fee_product: Optional[str] = None) -> Optional[str]:
    """The tier price on an invoice (fee lines are skipped)."""
    for line in _invoice_lines(inv):
        if line["price_id"] and (not fee_product or line["product_id"] != fee_product):
            return line["price_id"]
    return None


def _handle_checkout_completed(db: Session, obj: Dict[str, Any], record: StripeEvent) -> str:
    metadata = obj.get("metadata") or {}
    if obj.get("mode") == "setup":
        return _handle_payment_method_update(db, obj, record)
    user_id = _valid_user(db, obj.get("client_reference_id")) or _valid_user(db, metadata.get("user_id"))
    customer_id = _id(obj.get("customer"))
    record.user_id, record.object_id = user_id, obj.get("id")
    record.amount, record.currency = obj.get("amount_total"), obj.get("currency")
    record.price_id, record.tier_id = metadata.get("price_id"), metadata.get(TIER_KEY)
    record.subscription_id, record.payment_method = _id(obj.get("subscription")), metadata.get("payment_method")
    if not user_id or not customer_id:
        return "ignored"
    if not db.query(BillingCustomer).filter(BillingCustomer.user_id == user_id).first():
        db.add(BillingCustomer(user_id=user_id, stripe_customer_id=customer_id))
    return "processed"


def _handle_checkout_async(db: Session, obj: Dict[str, Any], record: StripeEvent) -> str:
    """A bank (ACH) payment started at checkout has cleared or failed, days after checkout."""
    metadata = obj.get("metadata") or {}
    record.user_id = _valid_user(db, obj.get("client_reference_id")) or _user_for_customer(db, _id(obj.get("customer")))
    record.object_id, record.subscription_id = obj.get("id"), _id(obj.get("subscription"))
    record.amount, record.currency = obj.get("amount_total"), obj.get("currency")
    record.price_id, record.tier_id, record.payment_method = metadata.get("price_id"), metadata.get(TIER_KEY), metadata.get("payment_method")
    return "processed" if record.user_id else "ignored"


def _handle_payment_method_update(db: Session, obj: Dict[str, Any], record: StripeEvent) -> str:
    """Setup-mode checkout finished: make the new card / bank account the subscription's default."""
    metadata = obj.get("metadata") or {}
    sub = db.query(Subscription).filter(Subscription.stripe_subscription_id == metadata.get("subscription_id")).first()
    record.object_id = obj.get("id")
    if metadata.get("purpose") != "update_payment_method" or not sub or str(sub.user_id) != metadata.get("user_id"):
        return "ignored"
    record.user_id, record.subscription_id, record.payment_method = sub.user_id, sub.stripe_subscription_id, sub.payment_method
    configure_client()
    intent = _plain(stripe.SetupIntent.retrieve(_id(obj.get("setup_intent")), api_key=secret_key()))
    method = _id(intent.get("payment_method"))
    if not method:
        raise BillingError(f"Setup intent {intent.get('id')} has no payment method")
    stripe.Subscription.modify(sub.stripe_subscription_id, default_payment_method=method, api_key=secret_key())
    return "processed"


def _reconcile_fee(db: Session, sub: Subscription, primary: Dict[str, Any], fee_items: List[Dict[str, Any]]):
    """Keep the card fee line equal to fee_bps of the tier price, after any tier or quantity change."""
    if not primary or sub.status not in ACTIVE_STATUSES:
        return
    expected = 0
    if sub.payment_method == "card" and sub.fee_bps:
        row = db.get(BillingPrice, primary["price_id"])
        base = price_amount(row, primary["quantity"]) if row else (
            primary["unit_amount"] * primary["quantity"] if primary.get("unit_amount") is not None else None)
        if base is None:
            raise BillingError(f"Cannot price the card fee for {primary['price_id']}: price not in the tier catalog")
        expected = fee_for(base, sub.fee_bps)
    current = sum((i.get("unit_amount") or 0) * (i.get("quantity") or 1) for i in fee_items)
    aligned = all(i.get("interval") == primary.get("interval") and i.get("currency") == primary.get("currency") for i in fee_items)
    if expected == current and len(fee_items) <= (1 if expected else 0) and aligned:
        sub.fee_amount = expected
        return
    key = secret_key()
    configure_client()
    keep = fee_items[0] if expected and fee_items else None
    price_data = _fee_price_data(primary["currency"], primary["interval"], primary.get("interval_count"), expected) if expected else None
    if keep:
        stripe.SubscriptionItem.modify(keep["item_id"], price_data=price_data, quantity=1, proration_behavior="none", api_key=key)
    elif expected:
        stripe.SubscriptionItem.create(subscription=sub.stripe_subscription_id, price_data=price_data, quantity=1, proration_behavior="none", api_key=key)
    for extra in fee_items:
        if extra is not keep:
            stripe.SubscriptionItem.delete(extra["item_id"], proration_behavior="none", api_key=key)
    sub.fee_amount = expected
    logger.info(f"Card fee for {sub.stripe_subscription_id} set to {expected} (was {current})")


def _handle_subscription(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    customer_id = _id(obj.get("customer"))
    metadata = obj.get("metadata") or {}
    user_id = _valid_user(db, metadata.get("user_id")) or _user_for_customer(db, customer_id)
    record.user_id, record.object_id, record.subscription_id = user_id, obj.get("id"), obj.get("id")
    if not user_id:
        raise BillingError(f"Subscription {obj.get('id')} belongs to an unknown customer {customer_id}")
    # Row lock: concurrent deliveries for one subscription are applied one at a time, in order.
    sub = db.query(Subscription).filter(Subscription.stripe_subscription_id == obj["id"]).with_for_update().first()
    if sub and sub.last_event_created > event["created"]:
        record.error = "Older than the last applied event for this subscription; skipped"
        return "ignored"
    if not sub:
        sub = Subscription(stripe_subscription_id=obj["id"], user_id=user_id, stripe_customer_id=customer_id, status=obj.get("status", "incomplete"))
        db.add(sub)

    # Register every item's price exactly as transmitted (amounts, interval, tier array, metadata).
    fee_product = _fee_product_or_none()
    items = []
    for item in _items(obj):
        price = item.get("price")
        if not isinstance(price, dict) or not price.get("id"):
            continue
        is_fee = fee_product is not None and _id(price.get("product")) == fee_product
        row = None if is_fee else _upsert_price(db, price, None, event["created"])
        recurring = price.get("recurring") or {}
        items.append({
            "item_id": item.get("id"),
            "kind": "fee" if is_fee else "tier",
            "price_id": price["id"],
            "product_id": _id(price.get("product")),
            "tier_id": None if is_fee else (price.get("metadata") or {}).get(TIER_KEY) or (row.tier_id if row else None),
            "quantity": item.get("quantity", 1),
            "unit_amount": price.get("unit_amount"),
            "currency": price.get("currency"),
            "billing_scheme": price.get("billing_scheme"),
            "interval": recurring.get("interval"),
            "interval_count": recurring.get("interval_count"),
        })
    tier_items = [i for i in items if i["kind"] == "tier"]
    fee_items = [i for i in items if i["kind"] == "fee"]
    primary = tier_items[0] if tier_items else {}
    # The tier named in the checkout metadata applies while the subscription is still on that
    # price; after a tier change, the new price's tier applies.
    tier = primary.get("tier_id")
    if metadata.get(TIER_KEY) and (not primary or primary.get("price_id") == metadata.get("price_id")):
        tier = metadata[TIER_KEY]

    sub.status = "canceled" if event["type"] == "customer.subscription.deleted" else obj.get("status", sub.status)
    sub.price_id = primary.get("price_id") or sub.price_id
    sub.tier_id = tier or sub.tier_id
    sub.product_id = primary.get("product_id") or sub.product_id
    sub.unit_amount = primary.get("unit_amount") if primary else sub.unit_amount
    sub.currency = primary.get("currency") or sub.currency
    sub.recurring_interval = primary.get("interval") or sub.recurring_interval
    sub.recurring_interval_count = primary.get("interval_count") or sub.recurring_interval_count
    sub.quantity = primary.get("quantity") if primary else sub.quantity
    sub.items = items or sub.items
    sub.subscription_metadata = metadata
    # The payment method is a one-time choice made at checkout; it is never switched afterwards.
    if not sub.payment_method and metadata.get("payment_method") in PAYMENT_METHODS:
        sub.payment_method = metadata["payment_method"]
        sub.fee_bps = int(metadata.get("fee_bps") or 0) if sub.payment_method == "card" else 0
    sub.fee_amount = sum((i.get("unit_amount") or 0) * (i.get("quantity") or 1) for i in fee_items)
    sub.current_period_end = _ts(_period_end(obj)) or sub.current_period_end
    sub.cancel_at_period_end = bool(obj.get("cancel_at_period_end"))
    sub.last_event_created = event["created"]
    sub.updated_at = datetime.utcnow()
    if event["type"] != "customer.subscription.deleted" and fee_product:
        _reconcile_fee(db, sub, primary, fee_items)
    record.price_id, record.tier_id, record.payment_method, record.fee_amount = sub.price_id, sub.tier_id, sub.payment_method, sub.fee_amount
    return "processed"


def _handle_invoice(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    record.object_id = obj.get("id")
    record.user_id = _user_for_customer(db, _id(obj.get("customer")))
    record.currency = obj.get("currency")
    record.amount = obj.get("amount_paid") if event["type"] != "invoice.payment_failed" else obj.get("amount_due")
    sub_id = _invoice_subscription(obj)
    sub = db.query(Subscription).filter(Subscription.stripe_subscription_id == sub_id).with_for_update().first() if sub_id else None
    fee_product = _fee_product_or_none()
    lines = _invoice_lines(obj)
    record.subscription_id = sub_id
    record.payment_method = sub.payment_method if sub else None
    record.fee_amount = sum(line["amount"] or 0 for line in lines if fee_product and line["product_id"] == fee_product)
    record.price_id = _invoice_price(obj, fee_product) or (sub.price_id if sub else None)
    price_row = db.get(BillingPrice, record.price_id) if record.price_id else None
    record.tier_id = (price_row.tier_id if price_row else None) or (sub.tier_id if sub else None)
    if sub and event["type"] == "invoice.payment_failed" and sub.last_event_created <= event["created"] and sub.status == "active":
        sub.status = "past_due"
    return "processed"


def _handle_price(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    record.object_id = obj.get("id")
    price = dict(obj)
    if event["type"] == "price.deleted":
        price["active"] = False
    row = _upsert_price(db, price, None, event["created"])
    if not row:
        return "ignored"
    record.price_id, record.tier_id = row.id, row.tier_id
    return "processed"


def _handle_product(db: Session, event: Dict[str, Any], obj: Dict[str, Any], record: StripeEvent) -> str:
    record.object_id = obj.get("id")
    product = dict(obj)
    if event["type"] == "product.deleted":
        product["active"] = False
    rows = db.query(BillingPrice).filter(BillingPrice.product_id == obj.get("id")).all()
    for row in rows:
        _apply_product(row, product, event["created"])
    tier = (obj.get("metadata") or {}).get(TIER_KEY)
    if tier and not rows:
        _last_sync["at"] = 0.0  # new tier product: pick up its prices on the next catalog read
    return "processed" if rows or tier else "ignored"


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
        elif event["type"] in CHECKOUT_ASYNC_EVENTS:
            outcome = _handle_checkout_async(db, obj, record)
        elif event["type"] in SUBSCRIPTION_EVENTS:
            outcome = _handle_subscription(db, event, obj, record)
        elif event["type"] in INVOICE_EVENTS:
            outcome = _handle_invoice(db, event, obj, record)
        elif event["type"] in PRICE_EVENTS:
            outcome = _handle_price(db, event, obj, record)
        elif event["type"] in PRODUCT_EVENTS:
            outcome = _handle_product(db, event, obj, record)
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
