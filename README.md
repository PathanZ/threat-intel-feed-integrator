# Threat Intelligence Feed Integrator

This project aggregates threat intelligence feeds (AlienVault, VirusTotal, AbuseIPDB, MISP) into a centralized dashboard for SOC teams.

## Features
- IOC ingestion and tagging
- Automated feed updates
- API for integration with security tools
- MongoDB backend
- FastAPI for high-performance endpoints

## How to Run
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
Visit `http://127.0.0.1:8000/docs` for the Swagger UI.
