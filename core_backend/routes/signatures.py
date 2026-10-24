"""Milestone 4: single-party canvas signatures stored as raw vectors with UTC timestamp and session IP."""

from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Signature
from ..security import client_ip
from ..signatures import SignatureError, canonical_hash, hash_inputs, normalize_strokes, render_svg, utc_timestamp
from .auth import HTTPAuthCredentials, security, verify_token, verify_token_claims

router = APIRouter(prefix="/api/signatures", tags=["signatures"])

DOCUMENT_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,119}$"


class Point(BaseModel):
    x: float
    y: float
    t: int = Field(..., ge=0, le=3_600_000)


class Canvas(BaseModel):
    width: int = Field(..., ge=50, le=4000)
    height: int = Field(..., ge=50, le=4000)


class SignatureCreate(BaseModel):
    document_ref: str = Field(..., pattern=DOCUMENT_REF_PATTERN)
    canvas: Canvas
    strokes: List[List[Point]] = Field(..., min_length=1, max_length=200)


def _summary(sig: Signature) -> dict:
    return {
        "id": str(sig.id),
        "document_ref": sig.document_ref,
        "signed_at_utc": sig.signed_at_utc,
        "ip_address": str(sig.ip_address),
        "stroke_count": sig.stroke_count,
        "point_count": sig.point_count,
        "canvas": {"width": sig.canvas_width, "height": sig.canvas_height},
        "signature_hash": sig.signature_hash,
    }


def _owned(db: Session, signature_id: UUID, user_id: str) -> Signature:
    sig = db.query(Signature).filter(Signature.id == signature_id, Signature.user_id == user_id).first()
    if not sig:
        raise HTTPException(status_code=404, detail="Signature not found")
    return sig


@router.post("", status_code=201)
async def create_signature(body: SignatureCreate, request: Request, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    claims = verify_token_claims(credentials, db)
    user_id = claims["sub"]
    try:
        strokes = normalize_strokes([[p.model_dump() for p in s] for s in body.strokes], body.canvas.width, body.canvas.height)
    except SignatureError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    signed_at = utc_timestamp()
    ip = client_ip(request)
    sig = Signature(
        user_id=UUID(user_id), document_ref=body.document_ref, strokes=strokes,
        canvas_width=body.canvas.width, canvas_height=body.canvas.height,
        stroke_count=len(strokes), point_count=sum(len(s) for s in strokes),
        signed_at_utc=signed_at, ip_address=ip,
        user_agent=(request.headers.get("user-agent") or "")[:500] or None,
        session_jti=claims.get("jti"),
        signature_hash=canonical_hash(hash_inputs(user_id, body.document_ref, body.canvas.width, body.canvas.height, strokes, signed_at, ip)),
    )
    db.add(sig)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This document has already been signed")
    db.refresh(sig)
    return _summary(sig)


@router.get("")
async def list_signatures(document_ref: Optional[str] = Query(None, max_length=120), credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    q = db.query(Signature).filter(Signature.user_id == user_id)
    if document_ref:
        q = q.filter(Signature.document_ref == document_ref)
    return [_summary(s) for s in q.order_by(Signature.created_at.desc()).limit(500).all()]


@router.get("/{signature_id}")
async def get_signature(signature_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    sig = _owned(db, signature_id, verify_token(credentials, db))
    return {**_summary(sig), "strokes": sig.strokes, "user_agent": sig.user_agent}


@router.get("/{signature_id}/svg")
async def signature_svg(signature_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    sig = _owned(db, signature_id, verify_token(credentials, db))
    return Response(render_svg(sig.strokes, sig.canvas_width, sig.canvas_height), media_type="image/svg+xml", headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})


@router.get("/{signature_id}/verify")
async def verify_signature(signature_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    sig = _owned(db, signature_id, verify_token(credentials, db))
    expected = canonical_hash(hash_inputs(str(sig.user_id), sig.document_ref, sig.canvas_width, sig.canvas_height, sig.strokes, sig.signed_at_utc, str(sig.ip_address)))
    return {"id": str(sig.id), "valid": expected == sig.signature_hash, "signature_hash": sig.signature_hash}
