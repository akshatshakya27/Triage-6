from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from pydantic import BaseModel
from backend.database import get_db
from backend.models import Alert, SeverityLevel, AlertStatus

router = APIRouter()


# Pydantic schemas
class AlertCreate(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    source: str
    threat_type: str | None = None
    assigned_to: str | None = None


class AlertUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: SeverityLevel | None = None
    status: AlertStatus | None = None
    threat_type: str | None = None
    assigned_to: str | None = None
    ai_analysis: str | None = None


class AlertResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: SeverityLevel
    status: AlertStatus
    source: str
    threat_type: str | None
    ai_analysis: str | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    assigned_to: str | None

    class Config:
        from_attributes = True


@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(alert: AlertCreate, db: Session = Depends(get_db)):
    """Create a new security alert"""
    db_alert = Alert(**alert.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


@router.get("/", response_model=List[AlertResponse])
def list_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: SeverityLevel | None = None,
    status: AlertStatus | None = None,
    db: Session = Depends(get_db)
):
    """List all security alerts with optional filters"""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    
    alerts = query.offset(skip).limit(limit).all()
    return alerts


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get a specific alert by ID"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, alert_update: AlertUpdate, db: Session = Depends(get_db)):
    """Update an existing alert"""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    update_data = alert_update.model_dump(exclude_unset=True)
    
    # If status is being changed to resolved, set resolved_at
    if update_data.get("status") == AlertStatus.RESOLVED:
        update_data["resolved_at"] = datetime.utcnow()
    
    for field, value in update_data.items():
        setattr(db_alert, field, value)
    
    db.commit()
    db.refresh(db_alert)
    return db_alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    """Delete an alert"""
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(db_alert)
    db.commit()
    return None
