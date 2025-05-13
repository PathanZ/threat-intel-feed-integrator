# 🛡️ Threat Intelligence Feed Integrator

> 🚧 **Work in Progress** — Active project for SOC tool development

This is a cybersecurity tool designed to automatically ingest and classify threat intelligence data from sources like **AlienVault OTX**, **VirusTotal**, **AbuseIPDB**, and **MISP**. It will provide a central dashboard for easy integration into a Security Operations Center (SOC) workflow.

## 🔧 Stack

- **FastAPI** (Python backend)
- **MongoDB** (IOC database)
- **VirusTotal, OTX, MISP APIs**
- **Dashboard** (to visualize threat activity - upcoming)

## 📌 Features (Planned)
- [x] Project scaffold with FastAPI
- [ ] IOC ingestion from public feeds
- [ ] Automated tagging system (Malware, Phishing, C2)
- [ ] MongoDB integration
- [ ] Visualization dashboard
- [ ] Docker deployment

## 🚀 Run Locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
