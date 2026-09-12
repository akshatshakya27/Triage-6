# Security Operations Platform

AI-powered threat intelligence and compliance automation platform designed to transform security operations from reactive alert firefighting to proactive threat intelligence.

## Product Vision

Transform security operations from reactive alert firefighting to proactive threat intelligence by providing AI-powered triage that explains threats in human terms, automates compliance workflows, and empowers analysts to focus on strategic defense rather than administrative overhead.

## Target Audience

- Security Operations Center (SOC) analysts
- Security operations managers
- Compliance officers
- Chief Information Security Officers (CISOs)
- Mid-to-large enterprises requiring CERT-In compliance and advanced threat detection

## Core Features

- **Alert Management**: Create, read, update, and delete security alerts with severity levels and status tracking
- **Incident Management**: Track and manage security incidents with impact assessment and remediation steps
- **Compliance Reporting**: Automated CERT-In compliance report generation and tracking

## Technology Stack

- **Backend Framework**: FastAPI 0.104.1
- **Database**: SQLAlchemy 2.0.23 with SQLite (configurable for PostgreSQL/MySQL)
- **Validation**: Pydantic 2.5.0
- **Server**: Uvicorn 0.24.0
- **Architecture**: Modular Monolith with clear separation of concerns

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <project-directory>
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r backend/requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env and set your SECRET_KEY and other configuration
```

## Running Locally

1. Activate your virtual environment (if not already activated):
```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Start the application:
```bash
cd backend
python main.py
```

The API will be available at `http://localhost:8000`

3. Access the interactive API documentation:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## API Endpoints

### Alerts
- `POST /api/v1/alerts` - Create a new alert
- `GET /api/v1/alerts` - List all alerts (with optional filters)
- `GET /api/v1/alerts/{alert_id}` - Get a specific alert
- `PUT /api/v1/alerts/{alert_id}` - Update an alert
- `DELETE /api/v1/alerts/{alert_id}` - Delete an alert

### Incidents
- `POST /api/v1/incidents` - Create a new incident
- `GET /api/v1/incidents` - List all incidents (with optional filters)
- `GET /api/v1/incidents/{incident_id}` - Get a specific incident
- `PUT /api/v1/incidents/{incident_id}` - Update an incident
- `DELETE /api/v1/incidents/{incident_id}` - Delete an incident

### Compliance
- `POST /api/v1/compliance` - Create a compliance report
- `GET /api/v1/compliance` - List all compliance reports (with optional filters)
- `GET /api/v1/compliance/{report_id}` - Get a specific report
- `PUT /api/v1/compliance/{report_id}` - Update a compliance report
- `DELETE /api/v1/compliance/{report_id}` - Delete a compliance report

## Environment Variables

See `.env.example` for all available configuration options:

- `SECRET_KEY`: Secret key for JWT token generation (REQUIRED - change in production)
- `DATABASE_URL`: Database connection string
- `DEBUG`: Enable debug mode (default: False)
- `PORT`: Server port (default: 8000)
- `CERT_IN_REPORTING_ENABLED`: Enable CERT-In compliance reporting
- `AI_MODEL_ENABLED`: Enable AI-powered threat analysis

## Project Structure

```
.
├── backend/
│   ├── main.py              # Application entry point
│   ├── config.py            # Configuration management
│   ├── database.py          # Database setup and session management
│   ├── models.py            # SQLAlchemy database models
│   └── routers/             # API route handlers
│       ├── alerts.py        # Alert management endpoints
│       ├── incidents.py     # Incident management endpoints
│       └── compliance.py    # Compliance reporting endpoints
├── .env.example             # Example environment variables
├── README.md                # This file
└── requirements.txt         # Python dependencies
```

## Architecture Overview

The application follows a **Modular Monolith** architecture with clear separation of concerns:

- **Routers**: Handle HTTP requests and responses
- **Models**: Define database schema and relationships
- **Database**: Manage database connections and sessions
- **Config**: Centralized configuration management

## Development

### Adding New Features

1. Define models in `backend/models.py`
2. Create router in `backend/routers/`
3. Register router in `backend/main.py`
4. Update database schema (migrations recommended for production)

### Code Quality

- Follow PEP 8 style guidelines
- Use type hints for better code clarity
- Add docstrings to functions and classes
- Implement proper error handling

## Security Best Practices

- Never commit `.env` file with real credentials
- Change `SECRET_KEY` in production
- Use HTTPS in production
- Implement rate limiting for production deployments
- Regular security audits and dependency updates

## License

[Add your license here]

## Support

For issues and questions, please contact your security operations team.
