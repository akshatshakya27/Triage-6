from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from pydantic import BaseModel
from backend.database import get_db
from backend.models import Incident, SeverityLevel, IncidentStatus

router = APIRouter()


# Pydantic schemas
class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    alert_id: int | None = None
    impact_assessment: str | None = None
    remediation_steps: str | None = None
    assigned_to: str | None = None


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: SeverityLevel | None = None
    status: IncidentStatus | None = None
    impact_assessment: str | None = None
    remediation_steps: str | None = None
    assigned_to: str | None = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: SeverityLevel
    status: IncidentStatus
    alert_id: int | None
    impact_assessment: str | None
    remediation_steps: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    assigned_to: str | None

    class Config:
        from_attributes = True


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    """Create a new security incident"""
    db_incident = Incident(**incident.model_dump())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    skip: int = 0,
    limit: int = 100,
    severity: SeverityLevel | None = None,
    status: IncidentStatus | None = None,
    db: Session = Depends(get_db)
):
    """List all security incidents with optional filters"""
    query = db.query(Incident)
    
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    
    incidents = query.offset(skip).limit(limit).all()
    return incidents


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Get a specific incident by ID"""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, incident_update: IncidentUpdate, db: Session = Depends(get_db)):
    """Update an existing incident"""
    db_incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not db_incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    update_data = incident_update.model_dump(exclude_unset=True)
    
    # If status is being changed to resolved or closed, set resolved_at
    if update_data.get("status") in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
        update_data["resolved_at"] = datetime.utcnow()
    
    for field, value in update_data.items():
        setattr(db_incident, field, value)
    
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(incident_id: int, db: Session = Depends(get_db)):
    """Delete an incident"""
    db_incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not db_incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    db.delete(db_incident)
    db.commit()
    return None
