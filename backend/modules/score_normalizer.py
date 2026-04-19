"""
Score Normalizer — Final Stage (High Accuracy)
===============================================
Root causes of inaccuracy in old version:
  1. API score always treated as equal weight even when it clearly flags MALICIOUS
  2. No override logic — if VT says 40/70 engines flagged malicious, final could still be LOW
  3. Weights only adjusted for API availability, not for API severity

Fixes in this version:
  ✅ API OVERRIDE: if VirusTotal flags ≥5 engines OR AbuseIPDB ≥75% confidence
     → final score is boosted to minimum 0.80 (MALICIOUS) regardless of ML/NLP
  ✅ API DOMINANCE: if any API flags danger, API weight raised to 0.60
  ✅ Without API keys → ML+NLP split 50/50 with no API penalty
  ✅ Score floor: if ML OR NLP alone is CRITICAL (≥0.80) → final minimum 0.65
"""


class ScoreNormalizer:

    VERDICTS = {
        (0.00, 0.20): ("SAFE",        "#22c55e", "This URL appears safe to visit."),
        (0.20, 0.40): ("LOW RISK",    "#84cc16", "Low risk detected. Exercise basic caution."),
        (0.40, 0.60): ("SUSPICIOUS",  "#f59e0b", "Suspicious indicators found. Avoid entering personal data."),
        (0.60, 0.80): ("HIGH RISK",   "#f97316", "High risk. Do not visit or provide any information."),
        (0.80, 1.01): ("MALICIOUS",   "#ef4444", "This URL is likely malicious. Do not visit."),
    }

    def combine(self, ml: dict, nlp: dict, api: dict) -> dict:
        ml_score  = ml["score"]
        nlp_score = nlp["score"]
        api_score = api["score"]

        vt    = api.get("virustotal", {})
        abuse = api.get("abuseipdb", {})

        vt_malicious     = vt.get("malicious", 0) or 0
        vt_available     = vt.get("available", False) and vt.get("raw_score") is not None
        abuse_confidence = abuse.get("confidence_score", 0) or 0
        abuse_available  = abuse.get("available", False) and abuse.get("raw_score") is not None
        api_available    = vt_available or abuse_available

        # ── API OVERRIDE — API is authoritative when it clearly flags danger ──
        # If VirusTotal ≥5 engines flag it OR AbuseIPDB ≥75% confidence
        # → force final score to at least 0.82 (MALICIOUS) regardless of ML/NLP
        api_override = False
        if vt_available and vt_malicious >= 5:
            api_override = True
        if abuse_available and abuse_confidence >= 75:
            api_override = True

        if api_override:
            # Still blend for the exact number, but floor at 0.82
            raw = 0.20 * ml_score + 0.20 * nlp_score + 0.60 * (api_score or 0.9)
            normalized = round(max(min(raw, 1.0), 0.82), 3)

        elif api_available:
            # API flagged something but not at override threshold
            # Check if API score is elevated (>0.40) — give it more weight
            api_s = api_score or 0.3
            if api_s >= 0.40:
                # API sees a threat — raise its weight to 0.60
                w_ml, w_nlp, w_api = 0.20, 0.20, 0.60
            else:
                # API sees nothing — standard weights
                w_ml, w_nlp, w_api = 0.30, 0.30, 0.40
            raw = w_ml * ml_score + w_nlp * nlp_score + w_api * api_s
            normalized = round(min(max(raw, 0.0), 1.0), 3)

        else:
            # No API keys — ML + NLP split 50/50
            raw = 0.50 * ml_score + 0.50 * nlp_score
            normalized = round(min(max(raw, 0.0), 1.0), 3)

        # ── Score floor — if ML or NLP alone is CRITICAL, raise floor to 0.65 ─
        if (ml_score >= 0.80 or nlp_score >= 0.80) and normalized < 0.65:
            normalized = 0.65

        verdict_text, color, message = self._get_verdict(normalized)

        # Confidence: agreement between stages
        scores   = [ml_score, nlp_score, api_score if api_score is not None else normalized]
        variance = sum((s - normalized) ** 2 for s in scores) / len(scores)
        confidence = round(max(0, 1.0 - variance * 4), 2)

        all_flags = ml.get("flags", []) + nlp.get("flags", []) + api.get("flags", [])

        # Add override notice to flags if triggered
        if api_override:
            all_flags.insert(0, f"⚠ API OVERRIDE ACTIVE: VirusTotal flagged {vt_malicious} engines" if vt_malicious >= 5
                             else f"⚠ API OVERRIDE ACTIVE: AbuseIPDB confidence {abuse_confidence}%")

        return {
            "normalized_score": normalized,
            "verdict":          verdict_text,
            "verdict_color":    color,
            "message":          message,
            "confidence":       confidence,
            "api_override":     api_override,
            "score_bands": [
                {"label": "SAFE", "min": 0.00, "max": 0.20, "color": "#22c55e"},
                {"label": "LOW RISK", "min": 0.20, "max": 0.40, "color": "#84cc16"},
                {"label": "SUSPICIOUS", "min": 0.40, "max": 0.60, "color": "#f59e0b"},
                {"label": "HIGH RISK", "min": 0.60, "max": 0.80, "color": "#f97316"},
                {"label": "MALICIOUS", "min": 0.80, "max": 1.00, "color": "#ef4444"},
            ],
            "score_breakdown": {
                "ml_score":    ml_score,
                "nlp_score":   nlp_score,
                "api_score":   api_score,
                "weights_used": self._weights_label(api_available, api_override,
                                                     api_score or 0),
            },
            "all_flags":  all_flags,
            "flag_count": len(all_flags),
        }

    def _weights_label(self, api_available, api_override, api_score):
        if api_override:
            return {"ml": 0.20, "nlp": 0.20, "api": 0.60, "note": "API OVERRIDE"}
        if api_available and api_score >= 0.40:
            return {"ml": 0.20, "nlp": 0.20, "api": 0.60, "note": "API DOMINANT"}
        if api_available:
            return {"ml": 0.30, "nlp": 0.30, "api": 0.40, "note": "standard"}
        return {"ml": 0.50, "nlp": 0.50, "api": 0.00, "note": "no API keys"}

    def _get_verdict(self, score: float):
        for (lo, hi), (label, color, msg) in self.VERDICTS.items():
            if lo <= score < hi:
                return label, color, msg
        return "UNKNOWN", "#6b7280", "Could not determine threat level."
