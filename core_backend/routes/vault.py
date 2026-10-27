"""Milestone 3: crypto vault. Files are encrypted in the browser; the server only stores ciphertext."""

import base64
import binascii
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..enclave.sanitizers import MAX_INPUT_BYTES
from ..models import EnclaveRecord, VaultConfig, VaultItem
from .auth import HTTPAuthCredentials, security, verify_token

router = APIRouter(prefix="/api/vault", tags=["vault"])

MIN_PBKDF2_ITERATIONS = 310_000
MAX_ITEM_B64 = ((MAX_INPUT_BYTES + 16 + 2) // 3) * 4


def _b64(value: str, field: str, min_len: int = 1, max_len: int = None) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail=f"{field} must be base64")
    if len(raw) < min_len or (max_len and len(raw) > max_len):
        raise HTTPException(status_code=422, detail=f"{field} has an invalid length")
    return raw


class VaultSetup(BaseModel):
    kdf: str = Field("PBKDF2-SHA256", pattern="^PBKDF2-SHA256$")
    iterations: int = Field(..., ge=MIN_PBKDF2_ITERATIONS, le=10_000_000)
    salt: str = Field(..., max_length=128)
    verifier_iv: str = Field(..., max_length=32)
    verifier_ct: str = Field(..., max_length=512)


class VaultItemCreate(BaseModel):
    record_id: UUID
    name_iv: str = Field(..., max_length=32)
    name_ct: str = Field(..., max_length=2048)
    iv: str = Field(..., max_length=32)
    ciphertext: str = Field(..., max_length=MAX_ITEM_B64)


def _config_dict(cfg: VaultConfig) -> dict:
    return {"configured": True, "kdf": cfg.kdf, "iterations": cfg.iterations, "salt": cfg.salt, "verifier_iv": cfg.verifier_iv, "verifier_ct": cfg.verifier_ct, "created_at": cfg.created_at}


def _item_dict(item: VaultItem, record: EnclaveRecord = None, with_ciphertext=False) -> dict:
    d = {
        "id": str(item.id), "record_id": str(item.record_id) if item.record_id else None, "name_iv": item.name_iv, "name_ct": item.name_ct,
        "iv": item.iv, "size_bytes": item.size_bytes, "created_at": item.created_at,
        "verdict": record.verdict if record else None,
        "threat_count": sum(t.get("count", 0) for t in (record.report or {}).get("threats", [])) if record else None,
        "detected_type": record.detected_type if record else None,
    }
    if with_ciphertext:
        d["ciphertext"] = base64.b64encode(item.ciphertext).decode("ascii")
    return d


@router.get("")
async def get_vault(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    cfg = db.query(VaultConfig).filter(VaultConfig.user_id == user_id).first()
    # Not having a vault yet is a normal state, not an error: the client shows the setup step.
    if not cfg:
        return {"configured": False}
    return _config_dict(cfg)


@router.post("", status_code=201)
async def create_vault(body: VaultSetup, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    if db.query(VaultConfig).filter(VaultConfig.user_id == user_id).first():
        raise HTTPException(status_code=409, detail="A vault already exists for this account")
    _b64(body.salt, "salt", 16, 64)
    _b64(body.verifier_iv, "verifier_iv", 12, 12)
    _b64(body.verifier_ct, "verifier_ct", 17, 256)
    cfg = VaultConfig(user_id=UUID(user_id), **body.model_dump())
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return _config_dict(cfg)


@router.delete("")
async def destroy_vault(confirm: bool = Query(False), credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    if not confirm:
        raise HTTPException(status_code=400, detail="Pass confirm=true to permanently delete the vault and every file in it")
    items = db.query(VaultItem).filter(VaultItem.user_id == user_id).delete(synchronize_session=False)
    db.query(VaultConfig).filter(VaultConfig.user_id == user_id).delete(synchronize_session=False)
    db.commit()
    return {"deleted_items": items}


@router.get("/items")
async def list_items(credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    rows = (
        db.query(VaultItem, EnclaveRecord).outerjoin(EnclaveRecord, VaultItem.record_id == EnclaveRecord.id)
        .filter(VaultItem.user_id == user_id).order_by(VaultItem.created_at.desc()).all()
    )
    return [_item_dict(item, rec) for item, rec in rows]


@router.post("/items", status_code=201)
async def add_item(body: VaultItemCreate, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    if not db.query(VaultConfig).filter(VaultConfig.user_id == user_id).first():
        raise HTTPException(status_code=409, detail="Set up the vault first")
    record = db.query(EnclaveRecord).filter(EnclaveRecord.id == body.record_id, EnclaveRecord.user_id == user_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Enclave record not found")
    if record.verdict not in ("clean", "sanitized"):
        raise HTTPException(status_code=409, detail=f"Only files that passed the enclave can be stored (this one was {record.verdict})")
    if db.query(VaultItem).filter(VaultItem.record_id == record.id).first():
        raise HTTPException(status_code=409, detail="This enclave result is already stored in the vault")
    _b64(body.name_iv, "name_iv", 12, 12)
    _b64(body.iv, "iv", 12, 12)
    ciphertext = _b64(body.ciphertext, "ciphertext", 16, MAX_INPUT_BYTES + 16)
    item = VaultItem(
        user_id=UUID(user_id), record_id=record.id, name_iv=body.name_iv, name_ct=body.name_ct,
        iv=body.iv, ciphertext=ciphertext, size_bytes=len(ciphertext) - 16,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return _item_dict(item, record)


@router.get("/items/{item_id}")
async def get_item(item_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    item = db.query(VaultItem).filter(VaultItem.id == item_id, VaultItem.user_id == user_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Vault item not found")
    record = db.query(EnclaveRecord).filter(EnclaveRecord.id == item.record_id).first() if item.record_id else None
    return _item_dict(item, record, with_ciphertext=True)


@router.delete("/items/{item_id}")
async def delete_item(item_id: UUID, credentials: HTTPAuthCredentials = Depends(security), db: Session = Depends(get_db)):
    user_id = verify_token(credentials, db)
    deleted = db.query(VaultItem).filter(VaultItem.id == item_id, VaultItem.user_id == user_id).delete(synchronize_session=False)
    db.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Vault item not found")
    return {"deleted": True}
