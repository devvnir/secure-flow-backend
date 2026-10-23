"""
Milestone 2: Data Ingestion API Routes
Endpoints for RESO Web API ingestion, schema translation, and token-bound filtering
"""

import logging
from datetime import datetime
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..ingestion import RESODataIngestionEngine, schema_translator, payload_validator
from ..models import DataFlow, DataFlowRun, IngestedRecord
from ..schemas import (
    BatchDataPayload,
    DataIngestionRequest,
    DataIngestionResponse,
    SchemaMapping,
    TranslateRecordRequest,
    ValidatePayloadRequest,
)
from .auth import HTTPAuthCredentials, security, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingestion", tags=["data-ingestion"])


def _get_owned_flow(db: Session, flow_id: UUID, user_id: str) -> DataFlow:
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()
    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")
    return flow


def _require_active(flow: DataFlow) -> None:
    if flow.status != "active":
        raise HTTPException(status_code=409, detail=f"Flow is {flow.status}; activate it before ingesting data")


def _store_records(db: Session, records, flow_id: UUID, run_id, user_id: str) -> None:
    for record in records:
        db.add(IngestedRecord(
            flow_id=flow_id,
            run_id=run_id,
            user_id=UUID(user_id),
            source_key=str(record.get("listing_id")) if record.get("listing_id") is not None else None,
            data=record,
        ))


@router.post("/reso/ingest", response_model=DataIngestionResponse)
async def ingest_from_reso(
    request: DataIngestionRequest,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """RESO fetch -> schema translation -> validation -> token-bound filtering -> storage."""
    user_id = verify_token(credentials, db)
    flow = _get_owned_flow(db, request.flow_id, user_id)
    if flow.source_type.upper() != "RESO":
        raise HTTPException(status_code=400, detail=f"Flow source is {flow.source_type}; RESO ingestion requires a RESO source")
    _require_active(flow)

    source_config = flow.source_config or {}
    query = request.query_filters
    resource = query.resource if query else source_config.get("resource", "Property")
    odata_filter = query.filter if query and query.filter else source_config.get("filter")
    select_fields = query.select if query else None
    top = query.top if query else 100
    skip = query.skip if query else 0

    run = DataFlowRun(flow_id=flow.id, status="running", started_at=datetime.utcnow())
    db.add(run)
    db.commit()
    db.refresh(run)

    engine = RESODataIngestionEngine()
    try:
        records = await engine.ingest_from_reso(
            resource_type=resource,
            filters=odata_filter,
            select_fields=select_fields,
            top=top,
            skip=skip,
        )
        valid_records, failed_records = await engine.process_ingestion_batch(
            records,
            source_schema="reso",
            dest_schema="internal",
            validate=request.validate_schema,
        )
        filtered_records = await engine.apply_token_bound_filters(valid_records, user_id=user_id)
    except (ValueError, httpx.HTTPError) as e:
        run.status = "failed"
        run.completed_at = datetime.utcnow()
        run.error_log = {"error": str(e)}
        db.commit()
        status_code = 400 if isinstance(e, ValueError) else 502
        raise HTTPException(status_code=status_code, detail=f"Ingestion failed: {e}")
    finally:
        await engine.close()

    _store_records(db, filtered_records, flow.id, run.id, user_id)

    run.status = "completed"
    run.completed_at = datetime.utcnow()
    run.records_processed = len(filtered_records)
    run.records_failed = len(failed_records)
    if failed_records:
        run.error_log = {
            "failed_count": len(failed_records),
            "failures": [
                {"source_key": f["original"].get("ListingKey"), "errors": f["errors"]}
                for f in failed_records[:20]
            ],
        }
    db.commit()
    db.refresh(run)

    logger.info(
        f"RESO ingestion for flow {flow.id}: {len(records)} fetched, "
        f"{len(filtered_records)} stored, {len(failed_records)} failed"
    )

    return DataIngestionResponse(
        run_id=run.id,
        flow_id=flow.id,
        status=run.status,
        records_ingested=len(records),
        records_validated=len(filtered_records),
        records_failed=len(failed_records),
        error_details=run.error_log,
        timestamp=run.completed_at,
    )


@router.post("/validate-payload")
async def validate_payload(
    request: ValidatePayloadRequest,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    verify_token(credentials, db)
    is_valid, errors = payload_validator.validate_payload(request.data, request.schema_name)
    return {
        "valid": is_valid,
        "errors": errors,
        "schema_name": request.schema_name,
        "validation_timestamp": datetime.utcnow(),
    }


@router.post("/translate-schema")
async def translate_schema(
    request: TranslateRecordRequest,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    verify_token(credentials, db)
    mapping_key = f"{request.source_schema}_to_{request.destination_schema}"
    if mapping_key not in schema_translator.mappings:
        raise HTTPException(status_code=404, detail=f"No schema mapping registered for {mapping_key}")

    translated = schema_translator.translate_record(
        request.record, request.source_schema, request.destination_schema
    )
    return {
        "mapping": mapping_key,
        "original": request.record,
        "translated": translated,
        "unmapped_fields": [k for k in request.record if k not in schema_translator.mappings[mapping_key]],
    }


@router.get("/schema-mappings")
async def list_schema_mappings(
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    verify_token(credentials, db)
    mappings = []
    for key, fields in schema_translator.mappings.items():
        source, _, destination = key.partition("_to_")
        mappings.append({"key": key, "source_schema": source, "destination_schema": destination, "field_mappings": fields})
    return mappings


@router.get("/schemas")
async def list_validation_schemas(
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    verify_token(credentials, db)

    def type_names(t):
        return [x.__name__ for x in (t if isinstance(t, tuple) else (t,))]

    return [
        {
            "name": name,
            "required": schema.get("required", []),
            "types": {field: type_names(t) for field, t in schema.get("types", {}).items()},
        }
        for name, schema in payload_validator.schemas.items()
    ]


@router.post("/schema-mappings")
async def register_schema_mapping(
    mapping: SchemaMapping,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    verify_token(credentials, db)
    if not mapping.field_mappings:
        raise HTTPException(status_code=400, detail="field_mappings must not be empty")
    schema_translator.add_custom_mapping(
        mapping.source_schema, mapping.destination_schema, mapping.field_mappings
    )
    return {
        "status": "success",
        "mapping": f"{mapping.source_schema}_to_{mapping.destination_schema}",
        "fields": len(mapping.field_mappings),
    }


@router.post("/batch-ingest")
async def batch_ingest(
    batch: BatchDataPayload,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Validate, token-bind and store payloads that are already in the internal schema."""
    user_id = verify_token(credentials, db)
    flow = _get_owned_flow(db, batch.flow_id, user_id)
    _require_active(flow)

    engine = RESODataIngestionEngine()
    try:
        valid_records, failed_records = await engine.process_ingestion_batch(
            [p.data for p in batch.payloads],
            source_schema="internal",
            dest_schema="internal",
            validate=True,
        )
        filtered_records = await engine.apply_token_bound_filters(valid_records, user_id=user_id)
    finally:
        await engine.close()

    _store_records(db, filtered_records, flow.id, None, user_id)
    db.commit()

    return {
        "status": "success",
        "records_processed": len(batch.payloads),
        "records_valid": len(valid_records),
        "records_failed": len(failed_records),
        "records_ingested": len(filtered_records),
        "failures": [f["errors"] for f in failed_records],
        "timestamp": datetime.utcnow(),
    }
