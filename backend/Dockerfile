FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ARG INSTALL_ML=false
COPY requirements.txt requirements-ml.txt ./
RUN if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt; else pip install --no-cache-dir -r requirements.txt; fi
COPY backend ./backend
COPY samples ./samples
COPY model ./model
RUN mkdir -p /data && useradd -u 10001 -m triage && chown triage /data
USER triage
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
