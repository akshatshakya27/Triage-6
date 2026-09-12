from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from pydantic import BaseModel
from backend.database import get_db
from backend.models import ComplianceReport, ComplianceStatus

router = APIRouter()


# Pydantic schemas
class ComplianceReportCreate(BaseModel):
    incident_id: int
    report_type: str
    report_data: str


class ComplianceReportUpdate(BaseModel):
    status: ComplianceStatus | None = None
    report_data: str | None = None


class ComplianceReportResponse(BaseModel):
    id: int
    incident_id: int
    report_type: str
    status: ComplianceStatus
    report_data: str
    submitted_at: datetime | None
    acknowledged_at: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
def create_compliance_report(report: ComplianceReportCreate, db: Session = Depends(get_db)):
    """Create a new CERT-In compliance report"""
    db_report = ComplianceReport(**report.model_dump())
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report


@router.get("/", response_model=List[ComplianceReportResponse])
def list_compliance_reports(
    skip: int = 0,
    limit: int = 100,
    status: ComplianceStatus | None = None,
    db: Session = Depends(get_db)
):
    """List all compliance reports with optional filters"""
    query = db.query(ComplianceReport)
    
    if status:
        query = query.filter(ComplianceReport.status == status)
    
    reports = query.offset(skip).limit(limit).all()
    return reports


@router.get("/{report_id}", response_model=ComplianceReportResponse)
def get_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific compliance report by ID"""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    return report


@router.put("/{report_id}", response_model=ComplianceReportResponse)
def update_compliance_report(report_id: int, report_update: ComplianceReportUpdate, db: Session = Depends(get_db)):
    """Update an existing compliance report"""
    db_report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    
    update_data = report_update.model_dump(exclude_unset=True)
    
    # If status is being changed to submitted, set submitted_at
    if update_data.get("status") == ComplianceStatus.SUBMITTED and not db_report.submitted_at:
        update_data["submitted_at"] = datetime.utcnow()
    
    # If status is being changed to acknowledged, set acknowledged_at
    if update_data.get("status") == ComplianceStatus.ACKNOWLEDGED and not db_report.acknowledged_at:
        update_data["acknowledged_at"] = datetime.utcnow()
    
    for field, value in update_data.items():
        setattr(db_report, field, value)
    
    db.commit()
    db.refresh(db_report)
    return db_report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_compliance_report(report_id: int, db: Session = Depends(get_db)):
    """Delete a compliance report"""
    db_report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    
    db.delete(db_report)
    db.commit()
    return None
