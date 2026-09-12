from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from backend.config import settings
from backend.database import engine, Base
from backend.routers import alerts, incidents, compliance, triage, csv_runs
from backend.auth import authorize
from backend.triage_models import Event, CsvRun
from backend.database import SessionLocal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting Security Operations Platform")
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")
    with SessionLocal() as db:
        db.query(Event).filter(Event.processing.in_(["queued", "processing"])).update({"processing":"interrupted"})
        db.query(CsvRun).filter(CsvRun.status.in_(["queued", "processing"])).update({"status":"interrupted", "error":"Backend restarted. Partial results retained; upload again to start a fresh run."})
        db.commit()
    yield
    logger.info("Shutting down Security Operations Platform")


app = FastAPI(
    title="Triage-6",
    description="AI-powered threat intelligence and compliance automation platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"], dependencies=[Depends(authorize)])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"], dependencies=[Depends(authorize)])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"], dependencies=[Depends(authorize)])


app.include_router(triage.router, prefix="/api/v1/triage", tags=["Triage-6"])
app.include_router(triage.ws_router)
app.include_router(csv_runs.router, prefix="/api/v1/triage", tags=["CSV testing"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Security Operations Platform API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
