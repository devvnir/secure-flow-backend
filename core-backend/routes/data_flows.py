from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from datetime import datetime
from uuid import UUID
from ..models import DataFlow, DataFlowRun, User
from ..schemas import DataFlowCreate, DataFlowUpdate, DataFlowResponse, DataFlowRunResponse
from ..database import get_db
from ..routes.auth import security, verify_token, HTTPAuthCredentials

router = APIRouter(prefix="/api/data-flows", tags=["data-flows"])

@router.get("/", response_model=list[DataFlowResponse])
async def list_data_flows(
    status: str = Query(None),
    source_type: str = Query(None),
    destination_type: str = Query(None),
    search: str = Query(None),
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)

    query = db.query(DataFlow).filter(DataFlow.created_by == user_id)

    if status:
        query = query.filter(DataFlow.status == status)
    if source_type:
        query = query.filter(DataFlow.source_type == source_type)
    if destination_type:
        query = query.filter(DataFlow.destination_type == destination_type)
    if search:
        query = query.filter(DataFlow.name.ilike(f"%{search}%"))

    flows = query.all()
    return flows

@router.get("/{flow_id}", response_model=DataFlowResponse)
async def get_data_flow(
    flow_id: UUID,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")
    return flow

@router.post("/", response_model=DataFlowResponse)
async def create_data_flow(
    flow_data: DataFlowCreate,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_flow = DataFlow(
        name=flow_data.name,
        description=flow_data.description,
        source_type=flow_data.source_type,
        destination_type=flow_data.destination_type,
        source_config=flow_data.source_config,
        destination_config=flow_data.destination_config,
        encryption_enabled=flow_data.encryption_enabled,
        status="draft",
        created_by=user_id
    )

    db.add(new_flow)
    db.commit()
    db.refresh(new_flow)
    return new_flow

@router.put("/{flow_id}", response_model=DataFlowResponse)
async def update_data_flow(
    flow_id: UUID,
    flow_data: DataFlowUpdate,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")

    update_data = flow_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(flow, key, value)

    flow.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(flow)
    return flow

@router.delete("/{flow_id}")
async def delete_data_flow(
    flow_id: UUID,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")

    db.delete(flow)
    db.commit()
    return {"message": "Data flow deleted successfully"}

@router.post("/{flow_id}/runs")
async def trigger_data_flow_run(
    flow_id: UUID,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")

    if flow.status != "active":
        raise HTTPException(status_code=400, detail="Data flow must be active to run")

    new_run = DataFlowRun(
        flow_id=flow_id,
        status="pending"
    )

    db.add(new_run)
    db.commit()
    db.refresh(new_run)

    return {"run_id": str(new_run.id), "status": "pending"}

@router.get("/{flow_id}/runs", response_model=list[DataFlowRunResponse])
async def list_data_flow_runs(
    flow_id: UUID,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")

    runs = db.query(DataFlowRun).filter(DataFlowRun.flow_id == flow_id).all()
    return runs

@router.get("/{flow_id}/runs/{run_id}", response_model=DataFlowRunResponse)
async def get_data_flow_run(
    flow_id: UUID,
    run_id: UUID,
    credentials: HTTPAuthCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_token(credentials, db)
    flow = db.query(DataFlow).filter(
        DataFlow.id == flow_id,
        DataFlow.created_by == user_id
    ).first()

    if not flow:
        raise HTTPException(status_code=404, detail="Data flow not found")

    run = db.query(DataFlowRun).filter(DataFlowRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Data flow run not found")

    return run
