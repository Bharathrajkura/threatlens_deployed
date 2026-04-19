"""
API Analyzer — Stage 3
Queries VirusTotal v3 and AbuseIPDB for threat intelligence on the URL/domain.
Falls back to graceful degradation when API keys are not provided.
"""

import re
import requests
import socket
from urllib.parse import urlparse


class APIAnalyzer:

    VT_URL    = "https://www.virustotal.com/api/v3/urls"
    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

    def analyze(self, url: str, vt_key: str = "", abuse_key: str = "") -> dict:
        hostname = urlparse(url).netloc.replace("www.", "")
        ip       = self._resolve_ip(hostname)

        vt_result    = self._virustotal(url, vt_key)    if vt_key    else self._no_key("VirusTotal")
        abuse_result = self._abuseipdb(ip, abuse_key)   if (abuse_key and ip) else self._no_key("AbuseIPDB")

        # Blend scores
        scores = [r["raw_score"] for r in [vt_result, abuse_result] if r["raw_score"] is not None]
        if scores:
            combined = sum(scores) / len(scores)
        else:
            combined = 0.3  # neutral when no API keys

        flags = vt_result["flags"] + abuse_result["flags"]

        return {
            "score":         round(combined, 3),
            "risk_level":    self._level(combined),
            "virustotal":    vt_result,
            "abuseipdb":     abuse_result,
            "resolved_ip":   ip,
            "flags":         flags,
            "summary":       self._summary(combined, vt_result, abuse_result),
            "stage":         "Threat Intelligence API Analysis"
        }

    # ── VirusTotal ─────────────────────────────────────────────────────────────

    def _virustotal(self, url: str, api_key: str) -> dict:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            headers = {"x-apikey": api_key}
            # Try GET first (cached result)
            resp = requests.get(f"{self.VT_URL}/{url_id}", headers=headers, timeout=10)

            if resp.status_code == 404:
                # Submit for scan
                post_resp = requests.post(
                    self.VT_URL,
                    headers=headers,
                    data={"url": url},
                    timeout=10
                )
                if post_resp.status_code != 200:
                    return self._vt_error(f"Submission failed: {post_resp.status_code}")
                import time; time.sleep(3)
                resp = requests.get(f"{self.VT_URL}/{url_id}", headers=headers, timeout=10)

            if resp.status_code != 200:
                return self._vt_error(f"HTTP {resp.status_code}")

            data    = resp.json().get("data", {}).get("attributes", {})
            stats   = data.get("last_analysis_stats", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + harmless + undetected or 1

            raw_score = min((malicious * 1.0 + suspicious * 0.5) / total, 1.0)
            flags = []
            if malicious > 0:   flags.append(f"{malicious} security vendors flagged as malicious")
            if suspicious > 0:  flags.append(f"{suspicious} vendors flagged as suspicious")

            return {
                "available":    True,
                "raw_score":    round(raw_score, 3),
                "malicious":    malicious,
                "suspicious":   suspicious,
                "harmless":     harmless,
                "undetected":   undetected,
                "total_engines": total,
                "flags":        flags,
                "reputation":   data.get("reputation", 0),
                "categories":   data.get("categories", {}),
            }
        except Exception as e:
            return self._vt_error(str(e))

    def _vt_error(self, msg):
        return {"available": True, "raw_score": None, "flags": [f"VirusTotal error: {msg}"],
                "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0}

    # ── AbuseIPDB ──────────────────────────────────────────────────────────────

    def _abuseipdb(self, ip: str, api_key: str) -> dict:
        try:
            resp = requests.get(
                self.ABUSE_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=10
            )
            if resp.status_code != 200:
                return self._abuse_error(f"HTTP {resp.status_code}")

            d = resp.json().get("data", {})
            confidence = d.get("abuseConfidenceScore", 0)
            raw_score  = confidence / 100.0
            flags = []
            if confidence > 0:  flags.append(f"AbuseIPDB confidence score: {confidence}%")
            if d.get("totalReports", 0) > 0:
                flags.append(f"IP reported {d['totalReports']} times by {d.get('numDistinctUsers',0)} users")
            if d.get("isWhitelisted"): flags = []  # whitelisted — clear flags

            return {
                "available":          True,
                "raw_score":          round(raw_score, 3),
                "ip":                 ip,
                "confidence_score":   confidence,
                "total_reports":      d.get("totalReports", 0),
                "distinct_users":     d.get("numDistinctUsers", 0),
                "country":            d.get("countryCode", "Unknown"),
                "isp":                d.get("isp", "Unknown"),
                "domain":             d.get("domain", "Unknown"),
                "is_whitelisted":     d.get("isWhitelisted", False),
                "last_reported":      d.get("lastReportedAt", None),
                "flags":              flags,
            }
        except Exception as e:
            return self._abuse_error(str(e))

    def _abuse_error(self, msg):
        return {"available": True, "raw_score": None, "flags": [f"AbuseIPDB error: {msg}"],
                "confidence_score": 0, "total_reports": 0}

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _no_key(self, service):
        return {
            "available":  False,
            "raw_score":  None,
            "flags":      [],
            "message":    f"{service} API key not provided — skipped",
        }

    def _resolve_ip(self, hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return ""

    def _level(self, s):
        if s < 0.25: return "LOW"
        if s < 0.50: return "MEDIUM"
        if s < 0.75: return "HIGH"
        return "CRITICAL"

    def _summary(self, score, vt, abuse):
        parts = []
        if vt.get("available") and vt.get("raw_score") is not None:
            m = vt.get("malicious", 0)
            parts.append(f"VirusTotal: {m} engine(s) flagged this URL")
        else:
            parts.append("VirusTotal: API key not configured")

        if abuse.get("available") and abuse.get("raw_score") is not None:
            c = abuse.get("confidence_score", 0)
            parts.append(f"AbuseIPDB: {c}% abuse confidence")
        else:
            parts.append("AbuseIPDB: API key not configured")

        return " | ".join(parts)
