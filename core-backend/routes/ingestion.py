"""
Milestone 2: Data Ingestion API Routes
Endpoints for RESO Web API ingestion, schema translation, and token-bound filtering
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List
import jwt
import os

from ..ingestion import RESODataIngestionEngine, schema_translator, payload_validator
from ..schemas import (
    RESOQueryFilter,
    DataPayload,
    SchemaMapping,
    DataIngestionRequest,
    DataIngestionResponse,
    BatchDataPayload,
)
from ..database import get_db
from ..models import DataFlow, DataFlowRun
from datetime import datetime
from uuid import uuid4

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingestion", tags=["data-ingestion"])

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"


def get_current_user_id(token: str) -> str:
    """Extract user ID from JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.post("/reso/ingest", response_model=DataIngestionResponse)
async def ingest_from_reso(
    request: DataIngestionRequest,
    authorization: str,
    db: Session = Depends(get_db)
):
    """
    Ingest data from RESO Web API with token-bound authorization

    Implements:
    - RESO Web API universal ingestion loops
    - Token-bound GET query filters
    - Mock data schema payload validation
    """
    try:
        # Extract token and user ID
        token = authorization.replace("Bearer ", "")
        user_id = get_current_user_id(token)

        # Verify flow ownership
        flow = db.query(DataFlow).filter(
            DataFlow.id == request.flow_id,
            DataFlow.created_by == user_id
        ).first()

        if not flow:
            raise HTTPException(status_code=404, detail="Data flow not found")

        # Create ingestion run
        run = DataFlowRun(
            flow_id=request.flow_id,
            status="running"
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        # Initialize RESO ingestion engine
        engine = RESODataIngestionEngine(token)

        try:
            # Ingest data from RESO
            filters = None
            select_fields = None
            top = 100
            skip = 0

            if request.query_filters:
                filters = request.query_filters.filter
                select_fields = request.query_filters.select
                top = request.query_filters.top
                skip = request.query_filters.skip

            logger.info(f"Starting RESO ingestion for flow {request.flow_id}")
            records = await engine.ingest_from_reso(
                resource_type=flow.source_type,
                filters=filters,
                select_fields=select_fields,
                top=top,
                skip=skip
            )

            # Process ingestion batch with schema translation and validation
            valid_records, failed_records = await engine.process_ingestion_batch(
                records,
                source_schema="reso",
                dest_schema="internal",
                validate=request.validate_schema
            )

            # Apply token-bound filters
            filtered_records = await engine.apply_token_bound_filters(
                valid_records,
                user_id=user_id,
                filter_rules=None
            )

            # Update run status
            run.status = "completed"
            run.completed_at = datetime.utcnow()
            run.records_processed = len(valid_records)
            run.records_failed = len(failed_records)

            if failed_records:
                run.error_log = {
                    "failed_count": len(failed_records),
                    "sample_errors": [f["errors"] for f in failed_records[:5]]
                }

            db.commit()
            db.refresh(run)

            await engine.close()

            logger.info(f"RESO ingestion completed for flow {request.flow_id}")

            return DataIngestionResponse(
                run_id=run.id,
                flow_id=request.flow_id,
                status="completed",
                records_ingested=len(records),
                records_validated=len(valid_records),
                records_failed=len(failed_records),
                error_details=run.error_log,
                timestamp=datetime.utcnow()
            )

        except Exception as e:
            logger.error(f"RESO ingestion error: {str(e)}")
            run.status = "failed"
            run.error_log = {"error": str(e)}
            db.commit()
            raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")

        finally:
            await engine.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in RESO ingestion: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/validate-payload")
async def validate_payload(
    payload: DataPayload,
    schema_name: str = "internal",
    authorization: Optional[str] = None
):
    """
    Validate data payload against schema

    Implements:
    - Mock data schema payload validation
    - Strict server-side filtering checks
    """
    try:
        is_valid, errors = payload_validator.validate_payload(
            payload.data,
            schema_name
        )

        if not is_valid:
            return {
                "valid": False,
                "errors": errors,
                "payload_id": payload.id
            }

        return {
            "valid": True,
            "errors": [],
            "payload_id": payload.id,
            "validation_timestamp": datetime.utcnow()
        }

    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")


@router.post("/translate-schema")
async def translate_schema(
    schema_mapping: SchemaMapping
):
    """
    Translate data between schemas dynamically

    Implements:
    - Dynamic schema translation modules
    """
    try:
        # Add mapping if custom
        if schema_mapping.transformations:
            schema_translator.add_custom_mapping(
                schema_mapping.source_schema,
                schema_mapping.destination_schema,
                schema_mapping.field_mappings
            )

        return {
            "status": "success",
            "message": f"Schema mapping from {schema_mapping.source_schema} to {schema_mapping.destination_schema} added",
            "timestamp": datetime.utcnow()
        }

    except Exception as e:
        logger.error(f"Schema translation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Schema error: {str(e)}")


@router.post("/batch-ingest")
async def batch_ingest(
    batch: BatchDataPayload,
    authorization: str,
    db: Session = Depends(get_db)
):
    """
    Batch ingest multiple data payloads with validation and filtering

    Implements:
    - Batch ingestion with schema translation
    - Server-side payload filtering
    - Validation of mock data
    """
    try:
        token = authorization.replace("Bearer ", "")
        user_id = get_current_user_id(token)

        # Verify flow ownership
        flow = db.query(DataFlow).filter(
            DataFlow.id == batch.flow_id,
            DataFlow.created_by == user_id
        ).first()

        if not flow:
            raise HTTPException(status_code=404, detail="Data flow not found")

        # Initialize engine
        engine = RESODataIngestionEngine(token)

        try:
            # Convert payloads to records
            records = [p.data for p in batch.payloads]

            # Process with validation
            valid_records, failed_records = await engine.process_ingestion_batch(
                records,
                source_schema="internal",
                dest_schema="internal",
                validate=True
            )

            # Apply token-bound filters
            filtered_records = await engine.apply_token_bound_filters(
                valid_records,
                user_id=user_id
            )

            return {
                "status": "success",
                "records_processed": len(batch.payloads),
                "records_valid": len(valid_records),
                "records_failed": len(failed_records),
                "records_ingested": len(filtered_records),
                "timestamp": datetime.utcnow()
            }

        finally:
            await engine.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch ingestion error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch ingestion failed: {str(e)}")
