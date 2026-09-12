from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from backend.database import Base

class Event(Base):
    __tablename__ = 'triage_events'
    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(64), unique=True, nullable=False)
    timestamp = Column(String(80), nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source = Column(String(30), default='suricata')
    event_type = Column(String(40))
    src_ip = Column(String(80))
    dest_ip = Column(String(80))
    proto = Column(String(20))
    title = Column(String(300))
    status = Column(String(30), default='new')
    assigned_to = Column(String(100), default='')
    severity = Column(String(20), default='info')
    priority = Column(Float, nullable=True)
    raw = Column(Text, nullable=False)
    analysis = Column(Text, default='{}')
    processing = Column(String(30), default='queued')
    reviewed_at = Column(DateTime)

class Draft(Base):
    __tablename__ = 'triage_drafts'
    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    markdown = Column(Text, nullable=False)
    fields = Column(Text, nullable=False)

class Audit(Base):
    __tablename__ = 'triage_audit'
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(30))
    action = Column(String(60))
    event_id = Column(Integer, nullable=True)
    detail = Column(Text)

class CsvRun(Base):
    __tablename__ = 'triage_csv_runs'
    id = Column(String(36), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    filename = Column(String(250), nullable=False)
    status = Column(String(30), default='queued')
    total_rows = Column(Integer, nullable=False)
    sample_rows = Column(Integer, nullable=False)
    processed = Column(Integer, default=0)
    failures = Column(Integer, default=0)
    seed = Column(Integer, default=42)
    samples = Column(Text, nullable=False)
    results = Column(Text, default='[]')
    metadata_json = Column(Text, default='{}')
    metrics_json = Column(Text, default='{}')
    error = Column(Text, default='')
