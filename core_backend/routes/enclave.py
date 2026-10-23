"""Milestone 3: secure process enclave API (key exchange, sandboxed sanitization, forensic records)."""

import asyncio
import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..enclave.audit import CANONICALIZATION, GENESIS_HASH, compute_hash, record_payload, verify_payloads
from ..enclave.keys import get_keyring
from ..enclave.sandbox import MEMORY_LIMIT_BYTES, TIMEOUT_SECONDS, EnclaveError, run_in_enclave
from ..enclave.sanitizers import MAX_INPUT_BYTES
from ..models import EnclaveRecord
from .auth import HTTPAuthCredentials, security, verify_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/enclave", tags=["enclave"])

MAX_CIPHERTEXT_B64 = ((MAX_INPUT_BYTES + 16 + 2) // 3) * 4
SUPPORTED_TYPES = ["docx/docm", "xlsx/xlsm", "pptx/pptm", "pdf", "html", "svg", "csv", "txt/md/json", "png", "jpeg", "gif"]


class SanitizeRequest(BaseModel):
    kid: str = Field(..., max_length=64)
    wrapped_key: str = Field(..., max_length=1024)
    iv: str = Field(..., max_length=32)
    ciphertext: str = Field(..., max_length=MAX_CIPHERTEXT_B64)
    name_iv: str = Field(..., max_length=32)
    name_ct: str = Field(..., max_length=2048)


def _summary(rec: EnclaveRecord) -> dict:
    report = rec.report or {}
    return {
        "id": str(rec.id),
        "seq": rec.seq,
        "created_at": rec.created_at,
        "verdict": rec.verdict,
        "detected_type": rec.detected_type,
        "threat_count": sum(t.get("count", 0) for t in report.get("threats", [])),
        "anchor_count": report.get("anchor_count", 0),
        "input_sha256": rec.input_sha256,
        "output_sha256": rec.output_sha256,
        "prev_hash": rec.prev_hash,
        "record_hash": rec.record_hash,
    }


def _full(rec: EnclaveRecord) -> dict:
    return {**_summary(rec), "report": rec.report}


def _append_record(db: Session, user_id: str, verdict: str, detected_type, input_sha, output_sha, report: dict) -> EnclaveRecord:
    for _ in range(5):
        last = (
            db.query(EnclaveRecord).filter(EnclaveRecord.user_id == user_id)
            .order_by(EnclaveRecord.seq.desc()).with_for_update().first()
        )
        rec = EnclaveRecord(
            user_id=UUID(user_id), seq=(last.seq + 1) if last else 1, verdict=verdict, detected_type=detected_type,
            input_sha256=input_sha, output_sha256=output_sha, report=report,
            prev_hash=last.record_hash if last else GENESIS_HASH, created_at=datetime.utcnow(),
        )
        rec.record_hash = compute_hash(record_payload(rec))
        db.add(rec)
        try:
            db.commit()
            db.refresh(rec)
            return rec
        except IntegrityError:
            db.rollback()
    raise HTTPException(status_code=503, detail="Could not append the forensic record; please retry")


@router.get("/public-key")
async def public_key(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    verify_token(credentials, db)
    return {
        **get_keyring().public_info(),
        "upload_cipher": "AES-256-GCM, 96-bit IV, key id as additional authenticated data",
        "max_file_bytes": MAX_INPUT_BYTES,
        "supported_types": SUPPORTED_TYPES,
        "sandbox": {"timeout_s": TIMEOUT_SECONDS, "memory_limit_mb": MEMORY_LIMIT_BYTES // (1024 * 1024)},
    }


@router.post("/sanitize")
async def sanitize(request: SanitizeRequest, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    ring = get_keyring()
    if request.kid != ring.kid:
        raise HTTPException(status_code=409, detail="The enclave key has rotated. Fetch the current public key and retry.")

    received_at = datetime.utcnow()
    try:
        resp = await asyncio.to_thread(run_in_enclave, {**request.model_dump(), "private_key_pem": ring.private_pem})
    except EnclaveError as exc:
        logger.error(f"Enclave failure for user {user_id}: {exc}")
        _append_record(db, user_id, "error", None, None, None, {"error": "enclave_failure", "message": str(exc), "received_at": received_at.isoformat() + "Z", "enclave_kid": ring.kid})
        raise HTTPException(status_code=502, detail=f"Enclave processing failed: {exc}")

    common = {
        "received_at": received_at.isoformat() + "Z",
        "completed_at": datetime.utcnow().isoformat() + "Z",
        "enclave_kid": ring.kid,
        "purge": resp.get("purge"),
        "sandbox": resp.get("sandbox"),
    }
    if not resp.get("ok"):
        _append_record(db, user_id, "error", None, None, None, {**common, "error": resp.get("error"), "message": resp.get("message")})
        raise HTTPException(status_code=400, detail=resp.get("message") or "The upload could not be processed")

    report = {
        **common,
        "detected_type": resp.get("detected_type"),
        "verdict": resp["verdict"],
        "rejection": resp.get("rejection"),
        "threats": resp.get("threats", []),
        "anchors": resp.get("anchors", []),
        "anchor_count": resp.get("anchor_count", 0),
        "notes": resp.get("notes", []),
        "verification": resp.get("verification"),
        "input_bytes": resp.get("input_bytes"),
        "output_bytes": resp.get("output_bytes"),
        "timings_ms": resp.get("timings_ms"),
    }
    rec = _append_record(db, user_id, resp["verdict"], resp.get("detected_type"), resp.get("input_sha256"), resp.get("output_sha256"), report)
    return {"record": _full(rec), "result": resp.get("result")}


@router.get("/records")
async def list_records(limit: int = Query(100, ge=1, le=500), credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    recs = db.query(EnclaveRecord).filter(EnclaveRecord.user_id == user_id).order_by(EnclaveRecord.seq.desc()).limit(limit).all()
    return [_summary(r) for r in recs]


@router.get("/records/{record_id}")
async def get_record(record_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    rec = db.query(EnclaveRecord).filter(EnclaveRecord.id == record_id, EnclaveRecord.user_id == user_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Record not found")
    return _full(rec)


def _chain(db: Session, user_id: str):
    return db.query(EnclaveRecord).filter(EnclaveRecord.user_id == user_id).order_by(EnclaveRecord.seq.asc()).all()


@router.get("/verify")
async def verify_chain(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    return {**verify_payloads((record_payload(r), r.record_hash) for r in _chain(db, user_id)), "verified_at": datetime.utcnow()}


@router.get("/export")
async def export_records(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    recs = _chain(db, user_id)
    entries = [(record_payload(r), r.record_hash) for r in recs]
    return {
        "format": "secure-flow-forensic-export/v1",
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "user_id": user_id,
        "hash_algorithm": "SHA-256",
        "canonicalization": CANONICALIZATION,
        "genesis_hash": GENESIS_HASH,
        "chain_rule": "record_hash = SHA-256(canonical(payload)); payload.prev_hash = previous record_hash (genesis for seq 1)",
        "verification": verify_payloads(entries),
        "records": [{"payload": p, "record_hash": h} for p, h in entries],
    }
