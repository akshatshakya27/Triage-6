from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from backend.database import Base


class SeverityLevel(str, enum.Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    """Alert status types"""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, enum.Enum):
    """Incident status types"""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ComplianceStatus(str, enum.Enum):
    """Compliance report status"""
    PENDING = "pending"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"


class Alert(Base):
    """Security alert model"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False, default=SeverityLevel.MEDIUM)
    status = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.NEW)
    source = Column(String(100), nullable=False)
    threat_type = Column(String(100))
    ai_analysis = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)
    assigned_to = Column(String(100))
    
    # Relationships
    incidents = relationship("Incident", back_populates="alert")


class Incident(Base):
    """Security incident model"""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    status = Column(Enum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    impact_assessment = Column(Text)
    remediation_steps = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)
    assigned_to = Column(String(100))
    
    # Relationships
    alert = relationship("Alert", back_populates="incidents")
    compliance_reports = relationship("ComplianceReport", back_populates="incident")


class ComplianceReport(Base):
    """CERT-In compliance report model"""
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    report_type = Column(String(100), nullable=False)
    status = Column(Enum(ComplianceStatus), nullable=False, default=ComplianceStatus.PENDING)
    report_data = Column(Text, nullable=False)
    submitted_at = Column(DateTime)
    acknowledged_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", back_populates="compliance_reports")
