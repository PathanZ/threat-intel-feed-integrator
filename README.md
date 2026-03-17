# 🛡️ Threat Intelligence Feed Integrator

> 🚧 **Work in Progress** — Active project for SOC tool development

This is a cybersecurity tool designed to automatically ingest and classify threat intelligence data from sources like **AlienVault OTX**, **VirusTotal**, **AbuseIPDB**, and **MISP**. It provides a centralized dashboard for Security Operations Centers (SOC) to easily access, tag, and visualize threat intelligence.

---

## 🔧 Stack

- **FastAPI** (Python backend)
- **MongoDB** (IOC database)
- **VirusTotal, OTX, MISP APIs**
- **Dashboard** (to visualize threat activity – coming soon)

---

## 📌 Features

- ✅ Project scaffold with FastAPI
- 🛠 IOC ingestion from public feeds (in development)
- 🏷 IOC tagging system (Malware, Phishing, C2)
- 🗃 MongoDB storage
- 📊 Dashboard & visualization
- 🐳 Docker support (upcoming)

---

## 🚀 How to Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload
