# Threat Intelligence Feed Integrator

A Python tool that aggregates Indicators of Compromise (IOCs) from multiple threat intelligence sources, scores them, and generates actionable reports.

Built as a SOC home-lab project to practice threat hunting and external-asset visibility.

## Features

- **Multi-source enrichment** — queries OTX AlienVault, VirusTotal, and AbuseIPDB in parallel
- **Threat scoring** — weighted 0–100 score combining detections from all sources
- **Auto-classification** — verdicts: `malicious` / `suspicious` / `clean`
- **Three output formats** — JSON (for SIEM/automation), CSV (for spreadsheet analysis), HTML (human-readable report)
- **IOC auto-detection** — automatically identifies IPv4, domain, or file hash
- **Demo mode** — test outputs without API keys

## Architecture

```
OTX AlienVault ─┐
VirusTotal      ─┼─▶  IOC Aggregator  ─▶  Threat Scorer  ─▶  JSON / CSV / HTML
AbuseIPDB      ─┘
```

## Scoring Logic

| Source | Max points | Notes |
|--------|-----------|-------|
| VirusTotal | 50 pts | Ratio of malicious/total engines |
| AbuseIPDB | 30 pts | Direct confidence score (IPs only) |
| OTX AlienVault | 20 pts | Log-scaled pulse count |

**Verdict thresholds:**
- `malicious` → score ≥ 70  
- `suspicious` → score 30–69  
- `clean` → score < 30  

## Setup

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-feed-integrator.git
cd threat-intel-feed-integrator
pip install -r requirements.txt
```

### 2. Get free API keys

| Service | Free tier | Sign up |
|---------|-----------|---------|
| OTX AlienVault | Unlimited | https://otx.alienvault.com |
| VirusTotal | 500 req/day | https://www.virustotal.com |
| AbuseIPDB | 1000 req/day | https://www.abuseipdb.com |

### 3. Set environment variables

```bash
cp .env.example .env
# Edit .env with your keys, then:
export $(cat .env | xargs)
```

## Usage

### Demo mode (no API keys needed)

```bash
python threat_intel.py --demo
```

### Scan from a file

```bash
python threat_intel.py --file sample_iocs.txt --out reports/
```

### Scan inline IOCs

```bash
python threat_intel.py --iocs "185.220.101.45,evil-domain.xyz,8.8.8.8"
```

### Output

All three formats are saved to the output directory:

```
output/
  threat_report_20250317_143022.json
  threat_report_20250317_143022.csv
  threat_report_20250317_143022.html   ← open this in browser
```

## Sample HTML Report

The HTML report shows a summary dashboard + sortable table:

- Summary cards (malicious / suspicious / clean counts)
- Colour-coded threat score bars per IOC
- Source attribution (which feeds flagged each IOC)
- VirusTotal detection ratio, OTX pulse count, AbuseIPDB confidence

## Project Structure

```
threat-intel-feed-integrator/
├── threat_intel.py      # Main script
├── sample_iocs.txt      # Sample IOC list for testing
├── requirements.txt
├── .env.example
└── README.md
```

## Extending This Project

Ideas to level it up further:

- Add a **MISP** or **OpenCTI** feed integration
- Schedule it with **cron** to monitor your public-facing assets daily
- Forward results to **Splunk / Elastic** via JSON output
- Add **IPv6 and URL** IOC type support
- Build a **Slack/email alert** for new malicious IOCs

## Skills Demonstrated

- Python scripting for security automation
- REST API integration (OTX, VirusTotal, AbuseIPDB)
- Threat intelligence concepts (IOCs, scoring, enrichment)
- SOC workflows — ingestion → enrichment → reporting
- Clean output for analyst consumption

---

*Part of my SOC home-lab series. See also: [your other projects]*
