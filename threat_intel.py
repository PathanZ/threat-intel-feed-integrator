"""
Threat Intelligence Feed Integrator
Aggregates IOCs from OTX, VirusTotal, and AbuseIPDB
Outputs scored JSON, CSV, and HTML report
"""

import os
import json
import csv
import time
import datetime
import argparse
import requests
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Config ────────────────────────────────────────────────────────────────────

OTX_API_KEY      = os.getenv("OTX_API_KEY", "")
VT_API_KEY       = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_KEY", "")

OTX_BASE         = "https://otx.alienvault.com/api/v1"
VT_BASE          = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE   = "https://api.abuseipdb.com/api/v2"


# ─── Data model ────────────────────────────────────────────────────────────────

@dataclass
class IOCResult:
    ioc: str
    ioc_type: str                        # ip, domain, hash
    threat_score: int = 0                # 0–100
    verdict: str = "clean"              # clean / suspicious / malicious
    sources_hit: list = field(default_factory=list)

    # OTX
    otx_pulses: int = 0

    # VirusTotal
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total_engines: int = 0

    # AbuseIPDB  (IP only)
    abuse_confidence: int = 0
    abuse_total_reports: int = 0
    abuse_country: str = ""

    error: str = ""


# ─── Lookup functions ───────────────────────────────────────────────────────────

def otx_lookup(ioc: str, ioc_type: str) -> dict:
    """Query OTX AlienVault for pulse count on an IOC."""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}

    section_map = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    section = section_map.get(ioc_type, "IPv4")
    url = f"{OTX_BASE}/indicators/{section}/{ioc}/general"

    try:
        r = requests.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=10)
        r.raise_for_status()
        data = r.json()
        return {"pulse_count": data.get("pulse_info", {}).get("count", 0)}
    except requests.RequestException as e:
        return {"error": str(e)}


def virustotal_lookup(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal for detection counts."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    endpoint_map = {"ip": f"ip_addresses/{ioc}", "domain": f"domains/{ioc}", "hash": f"files/{ioc}"}
    url = f"{VT_BASE}/{endpoint_map.get(ioc_type, f'ip_addresses/{ioc}')}"

    try:
        r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=10)
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total":      sum(stats.values()),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def abuseipdb_lookup(ip: str) -> dict:
    """Query AbuseIPDB for abuse confidence score (IP only)."""
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_KEY not set"}

    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "confidence":    d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country":       d.get("countryCode", ""),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


# ─── Scoring ────────────────────────────────────────────────────────────────────

def calculate_score(result: IOCResult) -> int:
    """
    Weighted threat score 0–100.
      VT malicious detections  → up to 50 pts
      AbuseIPDB confidence     → up to 30 pts
      OTX pulse count          → up to 20 pts
    """
    score = 0

    # VirusTotal weight (50 pts max)
    if result.vt_total_engines > 0:
        ratio = result.vt_malicious / result.vt_total_engines
        score += int(ratio * 50)
        if result.vt_suspicious > 0:
            score += min(5, result.vt_suspicious)

    # AbuseIPDB weight (30 pts max)
    score += int(result.abuse_confidence * 0.30)

    # OTX weight (20 pts max) – logarithmic so 1 pulse ≠ 0
    if result.otx_pulses > 0:
        import math
        score += min(20, int(math.log(result.otx_pulses + 1, 2) * 4))

    return min(score, 100)


def assign_verdict(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "clean"


# ─── Core enrichment ───────────────────────────────────────────────────────────

def enrich(ioc: str, ioc_type: str) -> IOCResult:
    result = IOCResult(ioc=ioc, ioc_type=ioc_type)
    print(f"  [*] Enriching {ioc_type}: {ioc}")

    # OTX
    otx = otx_lookup(ioc, ioc_type)
    if "error" not in otx:
        result.otx_pulses = otx.get("pulse_count", 0)
        if result.otx_pulses:
            result.sources_hit.append("OTX")
    else:
        result.error += f"OTX: {otx['error']}  "

    # VirusTotal
    vt = virustotal_lookup(ioc, ioc_type)
    if "error" not in vt:
        result.vt_malicious      = vt.get("malicious", 0)
        result.vt_suspicious     = vt.get("suspicious", 0)
        result.vt_total_engines  = vt.get("total", 0)
        if result.vt_malicious or result.vt_suspicious:
            result.sources_hit.append("VirusTotal")
    else:
        result.error += f"VT: {vt['error']}  "

    # AbuseIPDB – IPs only
    if ioc_type == "ip":
        ab = abuseipdb_lookup(ioc)
        if "error" not in ab:
            result.abuse_confidence   = ab.get("confidence", 0)
            result.abuse_total_reports = ab.get("total_reports", 0)
            result.abuse_country      = ab.get("country", "")
            if result.abuse_confidence > 0:
                result.sources_hit.append("AbuseIPDB")
        else:
            result.error += f"AbuseIPDB: {ab['error']}  "

    result.threat_score = calculate_score(result)
    result.verdict      = assign_verdict(result.threat_score)
    return result


# ─── Output helpers ─────────────────────────────────────────────────────────────

def save_json(results: list[IOCResult], path: str):
    with open(path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"  [+] JSON saved → {path}")


def save_csv(results: list[IOCResult], path: str):
    fields = ["ioc", "ioc_type", "threat_score", "verdict", "sources_hit",
              "otx_pulses", "vt_malicious", "vt_suspicious", "vt_total_engines",
              "abuse_confidence", "abuse_total_reports", "abuse_country", "error"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = asdict(r)
            row["sources_hit"] = ", ".join(row["sources_hit"])
            w.writerow({k: row[k] for k in fields})
    print(f"  [+] CSV saved  → {path}")


def save_html(results: list[IOCResult], path: str):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    malicious  = [r for r in results if r.verdict == "malicious"]
    suspicious = [r for r in results if r.verdict == "suspicious"]
    clean      = [r for r in results if r.verdict == "clean"]

    def verdict_badge(v):
        colors = {"malicious": "#e53e3e", "suspicious": "#dd6b20", "clean": "#38a169"}
        return f'<span style="background:{colors[v]};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{v.upper()}</span>'

    def score_bar(score):
        color = "#e53e3e" if score >= 70 else "#dd6b20" if score >= 30 else "#38a169"
        return f'<div style="background:#e2e8f0;border-radius:4px;height:8px;width:100%;margin-top:4px"><div style="background:{color};width:{score}%;height:8px;border-radius:4px"></div></div>'

    rows = ""
    for r in sorted(results, key=lambda x: -x.threat_score):
        rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:13px">{r.ioc}</td>
          <td><span style="background:#e2e8f0;padding:2px 6px;border-radius:4px;font-size:12px">{r.ioc_type}</span></td>
          <td>
            <strong>{r.threat_score}</strong>/100
            {score_bar(r.threat_score)}
          </td>
          <td>{verdict_badge(r.verdict)}</td>
          <td style="font-size:12px">{", ".join(r.sources_hit) or "—"}</td>
          <td style="font-size:12px">{r.otx_pulses}</td>
          <td style="font-size:12px">{r.vt_malicious}/{r.vt_total_engines}</td>
          <td style="font-size:12px">{r.abuse_confidence}%</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intelligence Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f7fafc; color: #2d3748; padding: 24px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 4px; }}
  .meta {{ color: #718096; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 28px; }}
  .card {{ background: #fff; border-radius: 10px; padding: 18px 24px; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-left: 4px solid #ccc; }}
  .card.red  {{ border-color: #e53e3e; }}
  .card.orange {{ border-color: #dd6b20; }}
  .card.green  {{ border-color: #38a169; }}
  .card .num {{ font-size: 32px; font-weight: 700; }}
  .card .label {{ font-size: 13px; color: #718096; margin-top: 2px; }}
  table {{ width: 100%; background: #fff; border-radius: 10px; border-collapse: collapse; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }}
  th {{ background: #2d3748; color: #fff; text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #e2e8f0; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f7fafc; }}
  .footer {{ margin-top: 20px; font-size: 12px; color: #a0aec0; text-align: center; }}
</style>
</head>
<body>
<h1>&#128737; Threat Intelligence Report</h1>
<p class="meta">Generated: {now} &nbsp;|&nbsp; Total IOCs: {len(results)}</p>

<div class="cards">
  <div class="card red">
    <div class="num">{len(malicious)}</div>
    <div class="label">Malicious</div>
  </div>
  <div class="card orange">
    <div class="num">{len(suspicious)}</div>
    <div class="label">Suspicious</div>
  </div>
  <div class="card green">
    <div class="num">{len(clean)}</div>
    <div class="label">Clean</div>
  </div>
  <div class="card" style="border-color:#4a5568">
    <div class="num">{len(results)}</div>
    <div class="label">Total IOCs</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>IOC</th><th>Type</th><th>Score</th><th>Verdict</th>
      <th>Sources</th><th>OTX pulses</th><th>VT detections</th><th>Abuse %</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<p class="footer">Threat Intelligence Feed Integrator &mdash; Sources: OTX AlienVault &bull; VirusTotal &bull; AbuseIPDB</p>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"  [+] HTML saved → {path}")


# ─── CLI entrypoint ─────────────────────────────────────────────────────────────

def detect_type(ioc: str) -> str:
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-f0-9]{32,64}$", ioc, re.I):
        return "hash"
    return "domain"


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Feed Integrator")
    parser.add_argument("--iocs",  help="Comma-separated IOCs (IPs, domains, hashes)")
    parser.add_argument("--file",  help="Path to file with one IOC per line")
    parser.add_argument("--out",   default="output", help="Output directory (default: output)")
    parser.add_argument("--demo",  action="store_true", help="Run with sample IOCs (no API keys needed)")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.demo:
        print("[*] Demo mode — using sample IOCs and mock data\n")
        results = _demo_results()
    else:
        ioc_list = []
        if args.file:
            with open(args.file) as f:
                ioc_list = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        elif args.iocs:
            ioc_list = [i.strip() for i in args.iocs.split(",")]
        else:
            parser.print_help()
            return

        print(f"[*] Enriching {len(ioc_list)} IOC(s)...\n")
        results = []
        for ioc in ioc_list:
            ioc_type = detect_type(ioc)
            results.append(enrich(ioc, ioc_type))
            time.sleep(0.5)   # be kind to rate limits

    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    save_json(results, f"{args.out}/threat_report_{ts}.json")
    save_csv (results, f"{args.out}/threat_report_{ts}.csv")
    save_html(results, f"{args.out}/threat_report_{ts}.html")

    print(f"\n[✓] Done — {len(results)} IOC(s) enriched.")
    malicious = sum(1 for r in results if r.verdict == "malicious")
    if malicious:
        print(f"[!] {malicious} malicious IOC(s) found!")


def _demo_results():
    """Return pre-built demo results so you can test outputs without API keys."""
    demo = [
        IOCResult("185.220.101.45", "ip",     threat_score=88, verdict="malicious",
                  sources_hit=["OTX","VirusTotal","AbuseIPDB"],
                  otx_pulses=14, vt_malicious=32, vt_suspicious=3, vt_total_engines=72,
                  abuse_confidence=95, abuse_total_reports=412, abuse_country="DE"),
        IOCResult("evil-domain.xyz", "domain", threat_score=72, verdict="malicious",
                  sources_hit=["OTX","VirusTotal"],
                  otx_pulses=6, vt_malicious=18, vt_suspicious=5, vt_total_engines=70),
        IOCResult("45.33.32.156",   "ip",     threat_score=41, verdict="suspicious",
                  sources_hit=["AbuseIPDB"],
                  abuse_confidence=45, abuse_total_reports=23, abuse_country="US"),
        IOCResult("update-flash-player.com", "domain", threat_score=55, verdict="suspicious",
                  sources_hit=["OTX","VirusTotal"],
                  otx_pulses=3, vt_malicious=8, vt_suspicious=7, vt_total_engines=65),
        IOCResult("8.8.8.8",        "ip",     threat_score=0,  verdict="clean",
                  sources_hit=[],
                  abuse_confidence=0, abuse_total_reports=0, abuse_country="US"),
        IOCResult("github.com",     "domain", threat_score=0,  verdict="clean",
                  sources_hit=[]),
        IOCResult("44d88612fea8a8f36de82e1278abb02f", "hash", threat_score=95, verdict="malicious",
                  sources_hit=["VirusTotal"],
                  vt_malicious=60, vt_suspicious=2, vt_total_engines=68),
    ]
    return demo


if __name__ == "__main__":
    main()
