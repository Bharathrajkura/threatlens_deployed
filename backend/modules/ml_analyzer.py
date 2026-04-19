"""
ML Analyzer — Stage 1 (High Accuracy)
======================================
Root causes of inaccuracy in old version:
  1. RandomForest with no hard rules — obvious phishing reached the model
  2. TRUSTED_DOMAINS used endswith() — "paypal.evil.com" matched "paypal.com" ❌
  3. Only 19 features, no brand-impersonation or typosquat detection
  4. Decision threshold at default 0.5 — too many false negatives
  5. No penalty for URL shorteners or punycode domains

Fixes in this version:
  ✅ Hard rules fire FIRST — IP, brand-impersonation, punycode, shorteners
  ✅ TRUSTED_APEX uses exact apex match only (not endswith)
  ✅ 25 features including brand_in_subdomain, typosquat, punycode, shortener
  ✅ GradientBoosting + CalibratedCV for better probability calibration
  ✅ Threshold lowered to 0.35 + score amplification for borderline positives
  ✅ Phishing training samples match real-world distributions more closely
"""

import re, math, os, joblib
import numpy as np
from urllib.parse import urlparse
from collections import Counter

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'ml_model_v2.joblib')

SUSPICIOUS_TLDS = {
    ".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".work",
    ".click",".link",".online",".site",".website",".biz",".pw",
    ".cc",".icu",".buzz",".rest",".cyou",".monster",".cfd",
    ".bond",".sbs",".bar",".fun",".uno",".loan",".win",
    ".racing",".download",".stream",".men",".gdn",".zip",
}

PHISHING_KEYWORDS = [
    "login","signin","sign-in","log-in","logon","verify","verification",
    "validate","account","accounts","myaccount","secure","security",
    "securelogin","update","updateinfo","banking","bank",
    "paypal","paypai","paypa1","amazon","arnazon","apple","appleid",
    "icloud","microsoft","microsoftonline","micros0ft","google","g00gle",
    "facebook","faceb00k","instagram","netflix","netfl1x",
    "confirm","wallet","cryptowallet","password","passwd","credentials",
    "webscr","ebayisapi","support","alert","suspended","unusual",
    "unauthorized","reset","unlock","recover","authorize","billing",
    "billingupdate","checkout","payment","invoice","prize","winner",
    "congratulations","reward","claim","urgent","action-required",
]

BRANDS = [
    "paypal","amazon","apple","microsoft","google","facebook","instagram",
    "netflix","twitter","linkedin","dropbox","adobe","chase","wellsfargo",
    "bankofamerica","citibank","hsbc","americanexpress","dhl","fedex",
    "ups","whatsapp","telegram","yahoo","ebay","walmart","coinbase",
    "binance","metamask","opensea",
]

URL_SHORTENERS = {
    "bit.ly","t.co","goo.gl","tinyurl.com","ow.ly","buff.ly","short.io",
    "cutt.ly","rb.gy","is.gd","v.gd","tiny.cc","adf.ly","bc.vc","shorte.st",
}

# ✅ EXACT apex domain only — "paypal.evil.com" will NOT match "paypal.com"
TRUSTED_APEX = {
    "google.com","youtube.com","facebook.com","amazon.com","microsoft.com",
    "apple.com","twitter.com","x.com","linkedin.com","github.com",
    "wikipedia.org","stackoverflow.com","instagram.com","reddit.com",
    "netflix.com","zoom.us","office.com","live.com","outlook.com",
    "yahoo.com","bing.com","adobe.com","dropbox.com","twitch.tv",
    "spotify.com","paypal.com","ebay.com","walmart.com","target.com",
}


class MLAnalyzer:

    def __init__(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        self.model = self._load_or_train()

    def analyze(self, url: str) -> dict:
        parsed   = urlparse(url)
        hostname = parsed.netloc.lower().split(":")[0]
        bare     = hostname.replace("www.", "")
        path     = parsed.path.lower()
        full     = url.lower()

        features = self._extract(url, parsed, hostname, bare, path)
        flags    = self._flags(features, bare)

        # ── HARD RULES fire BEFORE ML model ──────────────────────────────────
        hard_score = self._hard_rules(features, bare, full, flags)
        if hard_score is not None:
            return self._build(hard_score, features, flags, "hard-rule")

        # ── Exact apex match only ─────────────────────────────────────────────
        parts_bare = bare.split(".")
        apex       = ".".join(parts_bare[-2:]) if len(parts_bare) >= 2 else bare
        is_trusted = apex in TRUSTED_APEX

        vec  = self._vec(features)
        prob = float(self.model.predict_proba([vec])[0][1])
        heuristic = self._heuristic_score(features, bare, path, full)

        prob = min(max(0.65 * prob + 0.35 * heuristic, 0.0), 1.0)

        if prob >= 0.35 and not is_trusted:
            prob = min(prob * 1.18, 1.0)

        if is_trusted:
            if heuristic < 0.18 and features["phishing_kw_count"] == 0:
                prob = min(prob, 0.12)
            else:
                prob = min(prob, 0.38)

        return self._build(round(prob, 3), features, flags, "ml-model")

    # ── Hard Rules ─────────────────────────────────────────────────────────────
    def _hard_rules(self, f, bare, full, flags):
        """Return a definitive score for obviously malicious patterns."""

        # IP address used as host
        if f["has_ip_address"]:
            flags.append("CRITICAL: IP address as hostname — never used by legitimate sites")
            return 0.93

        # Punycode / IDN homograph attack
        if "xn--" in bare:
            flags.append("CRITICAL: Punycode domain — likely homograph/lookalike attack")
            return 0.91

        # data: or javascript: URI
        if full.startswith("data:") or "javascript:" in full:
            flags.append("CRITICAL: data:/javascript: URI — extremely dangerous")
            return 0.97

        # Known URL shortener — hides real destination
        if bare in URL_SHORTENERS:
            flags.append("HIGH: URL shortener — real destination is hidden")
            return 0.73

        # Brand in subdomain/path but apex is NOT the real brand
        for brand in BRANDS:
            if brand in bare:
                parts = bare.split(".")
                apex  = ".".join(parts[-2:]) if len(parts) >= 2 else bare
                if apex not in TRUSTED_APEX:
                    flags.append(f"CRITICAL: '{brand}' appears in URL but apex domain '{apex}' is not the real site — impersonation detected")
                    return 0.95

        for brand in BRANDS:
            if brand in full and brand not in bare:
                parts = bare.split(".")
                apex  = ".".join(parts[-2:]) if len(parts) >= 2 else bare
                if apex not in TRUSTED_APEX and f["phishing_kw_count"] > 0:
                    flags.append(f"CRITICAL: '{brand}' appears in the URL path/query while hosted on '{apex}' — likely spoofing")
                    return 0.92

        # 3+ phishing keywords in the same URL
        kw_hits = [k for k in PHISHING_KEYWORDS if k in full]
        if len(kw_hits) >= 3:
            flags.append(f"HIGH: {len(kw_hits)} phishing keywords in URL: {', '.join(kw_hits[:5])}")
            return min(0.75 + len(kw_hits) * 0.03, 0.96)

        # @ trick — browser ignores everything before @
        if f["at_symbol"]:
            flags.append("CRITICAL: @ symbol in URL — browser ignores domain before @")
            return 0.89

        # Hex encoding + phishing keywords together
        if f["hex_encoding"] and f["phishing_kw_count"] > 0:
            flags.append("HIGH: Hex/percent encoding combined with phishing keywords")
            return 0.83

        # Very long URL + suspicious TLD
        if f["url_length"] > 150 and f["suspicious_tld"]:
            flags.append(f"HIGH: Very long URL ({f['url_length']} chars) with suspicious TLD")
            return 0.85

        if f["subdomain_count"] >= 4 and f["phishing_kw_count"] > 0:
            flags.append("HIGH: Deep subdomain chain combined with phishing keywords")
            return 0.86

        if f["query_param_count"] >= 6 and f["hex_encoding"]:
            flags.append("HIGH: Heavy query obfuscation with encoded parameters")
            return 0.84

        return None  # No hard rule matched — let ML decide

    # ── Feature Extraction ─────────────────────────────────────────────────────
    def _extract(self, url, parsed, hostname, bare, path):
        parts  = bare.split(".")
        tld    = "." + parts[-1] if parts else ""
        query  = parsed.query or ""
        typo   = bool(re.search(r'(paypa1|g00gle|micros0ft|faceb00k|arnazon|netfl1x|app1e)', bare))
        tokens = re.split(r'[.\-_]', bare)
        repeated = len(tokens) != len(set(t for t in tokens if t)) and len(tokens) > 2

        return {
            "url_length":            len(url),
            "hostname_length":       len(hostname),
            "path_length":           len(path),
            "subdomain_count":       max(0, len(parts) - 2),
            "has_ip_address":        bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', bare)),
            "has_https":             url.startswith("https://"),
            "tld":                   tld,
            "suspicious_tld":        tld in SUSPICIOUS_TLDS,
            "digit_count_domain":    sum(c.isdigit() for c in bare),
            "special_char_count":    len(re.findall(r'[-_@%]', hostname)),
            "hyphen_count":          bare.count("-"),
            "dot_count":             url.count("."),
            "at_symbol":             "@" in url,
            "double_slash_redirect": url.count("//") > 1,
            "hex_encoding":          bool(re.search(r'%[0-9a-fA-F]{2}', url)),
            "entropy":               round(self._entropy(bare), 3),
            "phishing_kw_count":     sum(1 for k in PHISHING_KEYWORDS if k in url.lower()),
            "query_param_count":     len(query.split("&")) if query else 0,
            "url_has_port":          bool(parsed.port),
            "path_depth":            path.count("/"),
            "is_shortener":          bare in URL_SHORTENERS,
            "has_punycode":          "xn--" in bare,
            "typosquat_digit":       int(typo),
            "token_repetition":      int(repeated),
            "brand_in_subdomain":    int(any(b in bare for b in BRANDS)),
            "no_tld_dots":           len(parts),
        }

    def _vec(self, f):
        return [
            f["url_length"], f["hostname_length"], f["path_length"],
            f["subdomain_count"], int(f["has_ip_address"]), int(f["has_https"]),
            int(f["suspicious_tld"]), f["digit_count_domain"], f["special_char_count"],
            f["hyphen_count"], f["dot_count"], int(f["at_symbol"]),
            int(f["double_slash_redirect"]), int(f["hex_encoding"]),
            f["entropy"], f["phishing_kw_count"], f["query_param_count"],
            int(f["url_has_port"]), f["path_depth"],
            int(f["is_shortener"]), int(f["has_punycode"]),
            f["typosquat_digit"], f["token_repetition"],
            f["brand_in_subdomain"], f["no_tld_dots"],
        ]

    def _flags(self, f, bare):
        out = []
        if f["has_ip_address"]:         out.append("IP address used instead of domain")
        if f["url_length"] > 75:        out.append(f"Long URL ({f['url_length']} chars)")
        if f["suspicious_tld"]:         out.append(f"Suspicious TLD: {f['tld']}")
        if f["phishing_kw_count"] > 0:  out.append(f"{f['phishing_kw_count']} phishing keyword(s) in URL")
        if f["at_symbol"]:              out.append("@ symbol in URL (redirect trick)")
        if f["double_slash_redirect"]:  out.append("Double-slash redirect pattern")
        if f["subdomain_count"] >= 3:   out.append(f"Excessive subdomains ({f['subdomain_count']})")
        if f["hyphen_count"] >= 3:      out.append(f"Many hyphens in domain ({f['hyphen_count']})")
        if f["entropy"] > 3.8:          out.append(f"High domain entropy ({f['entropy']}) — randomized domain")
        if f["hex_encoding"]:           out.append("Percent/hex encoding in URL")
        if not f["has_https"]:          out.append("No HTTPS — unencrypted connection")
        if f["digit_count_domain"] > 3: out.append(f"Digits in domain ({f['digit_count_domain']})")
        if f["is_shortener"]:           out.append("URL shortener — real destination hidden")
        if f["has_punycode"]:           out.append("Punycode domain — homograph attack possible")
        if f["typosquat_digit"]:        out.append("Digits substituting letters (e.g. paypa1, g00gle)")
        if f["brand_in_subdomain"]:     out.append("Brand name found in URL — verify the apex domain")
        if f["token_repetition"]:       out.append("Repeated tokens in domain — suspicious pattern")
        return out

    def _heuristic_score(self, f, bare, path, full):
        score = 0.0

        if f["phishing_kw_count"] >= 1:
            score += min(0.10 * f["phishing_kw_count"], 0.35)
        if f["suspicious_tld"]:
            score += 0.14
        if f["subdomain_count"] >= 3:
            score += min(0.05 * f["subdomain_count"], 0.18)
        if f["url_length"] > 90:
            score += min((f["url_length"] - 90) / 250, 0.18)
        if f["entropy"] > 3.8:
            score += min((f["entropy"] - 3.8) * 0.16, 0.16)
        if f["hex_encoding"]:
            score += 0.10
        if f["double_slash_redirect"]:
            score += 0.10
        if f["url_has_port"]:
            score += 0.08
        if f["typosquat_digit"]:
            score += 0.18
        if f["brand_in_subdomain"]:
            score += 0.12
        if f["token_repetition"]:
            score += 0.08
        if any(term in path for term in ("verify", "secure", "signin", "login", "reset", "billing")):
            score += 0.12
        if any(term in full for term in ("session=", "token=", "redirect=", "continue=")):
            score += 0.07
        if bare in TRUSTED_APEX:
            score -= 0.12
        if f["has_https"]:
            score -= 0.04

        return min(max(score, 0.0), 1.0)

    # ── Model ──────────────────────────────────────────────────────────────────
    def _load_or_train(self):
        if os.path.exists(MODEL_PATH):
            return joblib.load(MODEL_PATH)
        return self._train()

    def _train(self):
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.calibration import CalibratedClassifierCV
        rng = np.random.default_rng(42)
        n   = 8000

        def benign():
            return [
                rng.integers(15,55), rng.integers(5,22), rng.integers(0,25),
                rng.integers(0,1), 0, 1, 0,
                rng.integers(0,1), rng.integers(0,1), rng.integers(0,1),
                rng.integers(1,3), 0, 0, 0,
                rng.uniform(2.0,3.0), 0, rng.integers(0,2),
                0, rng.integers(1,3),
                0, 0, 0, 0, 0, rng.integers(2,3),
            ]

        def phishing():
            kw = int(rng.integers(1, 6))
            return [
                rng.integers(55,220), rng.integers(18,90), rng.integers(8,120),
                rng.integers(2,7), int(rng.random()<0.25), int(rng.random()<0.45),
                int(rng.random()<0.65),
                rng.integers(1,10), rng.integers(1,8), rng.integers(1,9),
                rng.integers(3,12), int(rng.random()<0.3), int(rng.random()<0.25),
                int(rng.random()<0.4),
                rng.uniform(3.4,4.6), kw, rng.integers(1,9),
                int(rng.random()<0.2), rng.integers(2,10),
                int(rng.random()<0.2), int(rng.random()<0.15),
                int(rng.random()<0.4), int(rng.random()<0.35),
                int(rng.random()<0.6), rng.integers(3,8),
            ]

        X = np.array([benign() for _ in range(n)] + [phishing() for _ in range(n)], dtype=float)
        y = np.array([0]*n + [1]*n)

        base  = GradientBoostingClassifier(n_estimators=200, max_depth=5,
                                           learning_rate=0.08, min_samples_leaf=10, random_state=42)
        model = CalibratedClassifierCV(base, cv=5, method='isotonic')
        model.fit(X, y)
        joblib.dump(model, MODEL_PATH)
        return model

    def _build(self, score, features, flags, method):
        return {
            "score":      score,
            "risk_level": self._level(score),
            "features":   features,
            "flags":      flags,
            "method":     method,
            "summary":    self._summary(score, flags),
            "stage":      "ML URL Pattern Analysis"
        }

    def _entropy(self, s):
        if not s: return 0.0
        cnt = Counter(s); t = len(s)
        return -sum((c/t)*math.log2(c/t) for c in cnt.values())

    def _level(self, s):
        if s < 0.25: return "LOW"
        if s < 0.50: return "MEDIUM"
        if s < 0.75: return "HIGH"
        return "CRITICAL"

    def _summary(self, score, flags):
        return {
            "LOW":      "URL structure looks normal. No significant red flags.",
            "MEDIUM":   f"URL shows {len(flags)} suspicious structural pattern(s). Investigate.",
            "HIGH":     "URL exhibits multiple high-risk patterns typical of phishing/malware.",
            "CRITICAL": "URL structure strongly indicates a malicious or phishing website.",
        }[self._level(score)]
