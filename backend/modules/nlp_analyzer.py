"""
NLP Analyzer — Stage 2 (High Accuracy)
=======================================
Root causes of inaccuracy in old version:
  1. Only 8 phishing training texts × 300 — model saw very little vocabulary variety
  2. Urgency words too short — "account", "update", "limited" matched benign pages too
  3. Page fetch failure returned 0.3 (LOW risk) — should be 0.45 (MEDIUM, unknown = suspicious)
  4. Benign deductions too aggressive — legitimate sites with "sign in" got penalized wrong
  5. No login-form detection (password field + email = credential harvest form)

Fixes in this version:
  ✅ 40 diverse phishing training texts × 300 — much richer vocabulary
  ✅ Threat lexicons use full phrases not single words (less false-positive noise)
  ✅ Login form detection (pw + email/text input together = +0.25 penalty)
  ✅ Page fetch failure → 0.45 (not 0.3)
  ✅ Hard structural penalties: pw field +0.20, cc field +0.25, hidden iframe +0.15
  ✅ Benign deductions capped lower so real threats aren't washed out
"""

import re, os, joblib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

NLP_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'nlp_model.joblib')
ALT_NLP_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'nlp_model_v2.joblib')

# ── Full-phrase lexicons (less noise than single words) ───────────────────────

URGENCY_PHRASES = [
    "urgent","immediately","expires","act now","verify now","verify your",
    "account has been suspended","account suspended","account locked",
    "account disabled","account will be closed","security alert",
    "unusual activity","unauthorized access","confirm your identity",
    "update required","within 24 hours","within 48 hours",
    "failure to respond","immediate action required","click here to verify",
    "we detected suspicious","suspicious login","your password has expired",
    "action required","last warning","final notice","important security notice",
    "your account will be terminated","limited time offer","you have been selected",
]

CREDENTIAL_PHRASES = [
    "enter your password","confirm your password","type your password",
    "enter your username","social security number","ssn","credit card number",
    "card number","cvv","expiration date","expiry date","billing address",
    "bank account number","routing number","date of birth","mother's maiden",
    "pin number","security question","secret answer","tax identification",
    "passport number","driver license number","government issued id",
    "verify your card","update your billing","update payment method",
]

FORM_BAIT_PHRASES = [
    "keep me signed in","confirm to continue","continue to secure area",
    "download invoice","view document","open secure message",
    "unlock now","claim now","restore access","avoid suspension",
]

BRAND_IMPERSONATION = [
    "paypal customer service","amazon security team","apple id verification",
    "microsoft account team","google security alert","facebook security",
    "netflix billing department","your apple account","your amazon account",
    "your paypal account","dear valued customer","dear account holder",
    "verify your paypal","update your amazon","confirm your apple id",
    "your account has been compromised","we noticed unusual",
]

BENIGN_SIGNALS = [
    "privacy policy","terms of service","terms and conditions",
    "cookie policy","all rights reserved","about us","contact us",
    "sitemap","accessibility statement","careers","press room",
    "help center","return policy","frequently asked questions",
    "open source","api documentation","release notes","changelog",
]


class NLPAnalyzer:

    def __init__(self):
        os.makedirs(os.path.dirname(NLP_MODEL_PATH), exist_ok=True)
        bundle = self._load_or_train()
        self.vectorizer = bundle["vectorizer"]
        self.clf        = bundle["clf"]

    def analyze(self, url: str) -> dict:
        page = self._fetch(url)

        if not page["success"]:
            # Unknown = suspicious, not safe (0.45 not 0.3)
            return {
                "score":      0.45,
                "risk_level": "MEDIUM",
                "flags":      [f"Page fetch failed: {page.get('error','timeout')} — treated as suspicious"],
                "summary":    "Page content unavailable. Moderate risk score applied.",
                "page_info":  page,
                "stage":      "NLP Content Analysis"
            }

        text      = page["text"]
        flags     = self._detect_flags(page, text)
        ml_prob   = self._classify(text)
        rule_sc   = self._rule_score(page, text)
        rule_floor = self._high_risk_floor(page, text)

        score = min(0.58 * ml_prob + 0.42 * rule_sc, 1.0)
        score = round(max(score, rule_floor), 3)

        return {
            "score":      score,
            "risk_level": self._level(score),
            "flags":      flags,
            "page_info":  {k: v for k, v in page.items() if k != "text"},
            "summary":    self._summary(score, flags),
            "stage":      "NLP Content Analysis"
        }

    # ── Page Fetch ─────────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> dict:
        try:
            headers = {"User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )}
            resp = requests.get(url, headers=headers, timeout=9, allow_redirects=True)
            soup = BeautifulSoup(resp.text, "lxml")

            for tag in soup(["script","style","meta","head","noscript"]):
                tag.decompose()
            text = " ".join(soup.get_text(separator=" ").split()).lower()

            forms   = soup.find_all("form")
            inputs  = soup.find_all("input")
            buttons = soup.find_all("button")
            scripts = soup.find_all("script", src=True)
            iframes = soup.find_all("iframe")

            pw_field = any(i.get("type","").lower() == "password" for i in inputs)
            hidden_inputs = [i for i in inputs if i.get("type", "").lower() == "hidden"]
            cc_field = any(
                any(w in (i.get("name","") + i.get("placeholder","") + i.get("id","")).lower()
                    for w in ["card","cvv","credit","debit","expiry","exp","billing"])
                for i in inputs
            )
            # Login form = password field + email or text input on same page
            has_login_form = pw_field and any(
                i.get("type","").lower() in ["email","text"] for i in inputs
            )

            parsed_host   = urlparse(url).netloc
            ext_scripts   = [s["src"] for s in scripts
                             if s["src"].startswith("http") and parsed_host not in s["src"]]
            external_forms = [
                f for f in forms
                if (f.get("action") or "").startswith("http") and parsed_host not in (f.get("action") or "")
            ]
            hidden_frames = [f for f in iframes
                             if f.get("width","2") in ["0","1","0px"]
                             or f.get("height","2") in ["0","1","0px"]]
            submit_controls = [
                i for i in inputs if i.get("type", "").lower() in ["submit", "button", "image"]
            ] + [
                b for b in buttons if (b.get("type") or "submit").lower() == "submit"
            ]

            title_tag = soup.find("title")
            title     = title_tag.get_text(strip=True) if title_tag else ""

            return {
                "success":               True,
                "status_code":           resp.status_code,
                "text":                  text[:6000],
                "title":                 title,
                "form_count":            len(forms),
                "has_password_field":    pw_field,
                "has_login_form":        has_login_form,
                "has_credit_card_field": cc_field,
                "external_script_count": len(ext_scripts),
                "external_form_action_count": len(external_forms),
                "hidden_iframe_count":   len(hidden_frames),
                "hidden_input_count":    len(hidden_inputs),
                "redirect_count":        len(resp.history),
                "final_url":             resp.url,
                "content_length":        len(resp.text),
                "input_count":           len(inputs),
                "submit_count":          len(submit_controls),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Classification ─────────────────────────────────────────────────────────
    def _classify(self, text: str) -> float:
        try:
            vec = self.vectorizer.transform([text])
            return float(self.clf.predict_proba(vec)[0][1])
        except Exception:
            return 0.4

    def _rule_score(self, page: dict, text: str) -> float:
        score = 0.0

        urgency_hits = sum(1 for p in URGENCY_PHRASES if p in text)
        cred_hits    = sum(1 for p in CREDENTIAL_PHRASES if p in text)
        brand_hits   = sum(1 for p in BRAND_IMPERSONATION if p in text)
        bait_hits    = sum(1 for p in FORM_BAIT_PHRASES if p in text)
        benign_hits  = sum(1 for p in BENIGN_SIGNALS if p in text)

        score += min(urgency_hits * 0.08, 0.32)
        score += min(cred_hits    * 0.12, 0.36)
        score += min(brand_hits   * 0.10, 0.20)
        score += min(bait_hits    * 0.08, 0.24)
        # Benign deduction — capped at 0.15 so real threats aren't cancelled out
        score -= min(benign_hits  * 0.03, 0.15)

        # Structural hard penalties
        if page.get("has_login_form"):          score += 0.25  # password+email = credential harvest
        elif page.get("has_password_field"):    score += 0.20  # pw field alone
        if page.get("has_credit_card_field"):   score += 0.25
        if page.get("hidden_iframe_count",0) > 0: score += 0.15
        if page.get("external_form_action_count", 0) > 0: score += 0.18
        if page.get("hidden_input_count", 0) >= 4: score += 0.08
        if page.get("external_script_count",0) > 5: score += 0.08
        if page.get("redirect_count",0) > 2:   score += 0.08
        if page.get("form_count",0) > 4:        score += 0.05
        if page.get("input_count", 0) >= 8 and page.get("submit_count", 0) >= 1:
            score += 0.07

        return max(0.0, min(score, 1.0))

    def _high_risk_floor(self, page: dict, text: str) -> float:
        urgency_hits = sum(1 for p in URGENCY_PHRASES if p in text)
        cred_hits = sum(1 for p in CREDENTIAL_PHRASES if p in text)
        bait_hits = sum(1 for p in FORM_BAIT_PHRASES if p in text)

        if page.get("has_credit_card_field") and cred_hits >= 1:
            return 0.82
        if page.get("has_login_form") and (urgency_hits + cred_hits + bait_hits) >= 2:
            return 0.78
        if page.get("external_form_action_count", 0) > 0 and page.get("has_password_field"):
            return 0.80
        return 0.0

    def _detect_flags(self, page: dict, text: str) -> list:
        flags = []
        urgency_hits = [p for p in URGENCY_PHRASES if p in text]
        cred_hits    = [p for p in CREDENTIAL_PHRASES if p in text]
        brand_hits   = [p for p in BRAND_IMPERSONATION if p in text]
        bait_hits    = [p for p in FORM_BAIT_PHRASES if p in text]

        if urgency_hits:  flags.append(f"Urgency language detected: '{urgency_hits[0]}'")
        if len(urgency_hits) > 2: flags.append(f"{len(urgency_hits)} urgency phrases total")
        if cred_hits:     flags.append(f"Credential harvesting phrase: '{cred_hits[0]}'")
        if len(cred_hits) > 1: flags.append(f"{len(cred_hits)} credential-related phrases found")
        if brand_hits:    flags.append(f"Brand impersonation phrase: '{brand_hits[0]}'")
        if bait_hits:     flags.append(f"Conversion/bait phrase detected: '{bait_hits[0]}'")

        if page.get("has_login_form"):           flags.append("Login form detected (password + email fields)")
        elif page.get("has_password_field"):     flags.append("Password input field on page")
        if page.get("has_credit_card_field"):    flags.append("Credit/debit card input field detected")
        if page.get("external_form_action_count", 0) > 0:
            flags.append(f"{page['external_form_action_count']} form(s) submit to an external domain")
        if page.get("hidden_input_count", 0) >= 4:
            flags.append(f"{page['hidden_input_count']} hidden input fields detected")
        if page.get("hidden_iframe_count",0) > 0:
            flags.append(f"{page['hidden_iframe_count']} hidden iframe(s) on page")
        if page.get("external_script_count",0) > 5:
            flags.append(f"{page['external_script_count']} external scripts loaded")
        if page.get("redirect_count",0) > 2:
            flags.append(f"Multiple HTTP redirects ({page['redirect_count']}) before landing")
        if page.get("form_count",0) > 4:
            flags.append(f"Unusually many forms on page ({page['form_count']})")
        return flags

    # ── Model ──────────────────────────────────────────────────────────────────
    def _load_or_train(self):
        if os.path.exists(NLP_MODEL_PATH):
            bundle = joblib.load(NLP_MODEL_PATH)
            return bundle
        if os.path.exists(ALT_NLP_MODEL_PATH):
            bundle = joblib.load(ALT_NLP_MODEL_PATH)
            return bundle
        if os.getenv("ALLOW_MODEL_TRAINING", "0") == "1":
            return self._train()
        raise FileNotFoundError(
            "NLP model file is missing. Add backend/models/nlp_model.joblib to the deployment package "
            "or set ALLOW_MODEL_TRAINING=1 only for local regeneration."
        )

    def _train(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        # ── Much richer training texts than original 8-text version ─────────
        benign_texts = [
            "welcome to our website privacy policy terms of service cookie policy sitemap careers about us contact",
            "latest news articles technology science health sports entertainment all rights reserved copyright",
            "shop now free shipping easy returns customer service faq help center account orders tracking wishlist",
            "explore features download app available ios android learn more documentation api reference",
            "our mission quality services worldwide established 2005 trusted by millions of customers globally",
            "breaking news headlines world politics economy stock market weather forecast live updates",
            "open source project contributors license mit apache github pull request issue tracker wiki",
            "university academic research paper journal published peer reviewed methodology results conclusion",
            "recipe ingredients instructions cooking time servings nutritional information calories",
            "product specifications technical details warranty support knowledge base troubleshooting guide",
            "blog post author published date category tags share subscribe newsletter rss feed",
            "video tutorial watch subscribe like comment share playlist channel creator content",
            "forum discussion community members post reply quote moderator rules guidelines",
            "travel destination hotel booking flight search itinerary reviews rating stars",
            "job listing salary experience required skills apply now linkedin indeed glassdoor",
            "sports scores standings fixtures results league table transfer news injury update",
            "movie review cast director genre runtime streaming rental buy tickets showtimes",
            "software update version changelog bug fix performance improvement security patch release notes",
            "weather forecast sunny cloudy rain temperature humidity wind speed uv index",
            "stock price market cap dividend earnings report quarterly annual revenue profit",
        ] * 300

        phishing_texts = [
            "urgent your account has been suspended verify identity immediately click here confirm now",
            "security alert unusual activity detected enter password username unlock account immediately",
            "credit card information required update billing within 24 hours or account disabled permanently",
            "warning unauthorized login detected confirm social security number date of birth identity",
            "act now account expires update credit card number cvv expiry routing number bank account",
            "enter bank account pin security question mother maiden name restore access now urgent",
            "failure respond permanent suspension verify identity upload government id confirm password",
            "paypal account locked enter card number ssn regain access immediately urgent action required",
            "dear valued customer your apple id has been compromised verify account information now",
            "microsoft security alert your account will be terminated update payment method immediately",
            "amazon order suspended verify your billing address credit card information within 48 hours",
            "netflix payment failed update credit card information to continue subscription service",
            "dear account holder unusual sign in detected confirm identity social security number",
            "your password has expired reset now enter current password new password confirm immediately",
            "congratulations you have been selected claim your reward enter personal information now",
            "bank account access suspended verify identity routing number account number pin number",
            "limited time verify your account now or lose access permanently enter credentials below",
            "we noticed suspicious activity your account confirm billing credit card expiry cvv urgent",
            "your tax refund is pending verify identity social security number date of birth bank account",
            "dear customer your debit card has been blocked enter card number cvv to unblock now",
            "google account suspended verify phone number password recovery email identity confirmation",
            "facebook account disabled confirm identity government issued id driver license passport",
            "whatsapp account banned verify phone number enter verification code personal information",
            "crypto wallet compromised enter seed phrase private key restore access immediately urgent",
            "prize winner claim now enter name address phone number credit card processing fee required",
            "icloud storage full verify payment method credit card update billing information apple id",
            "dhl package held customs clearance pay import fee credit card number required immediately",
            "your beneficiary payment transfer blocked verify identity bank account routing number swift",
            "webscr paypal confirm email address password security question verify account information",
            "login signin verify account secure update banking credential reset unlock recover authorize",
            "action required your account will be closed within 24 hours click verify identity now",
            "important notice billing information outdated update payment credit card cvv expiry date",
            "security verification required confirm account details password username social security",
            "final warning account suspended violation terms update information restore access now",
            "account recovery enter email password security question mother maiden name date birth",
            "unauthorized transaction detected verify bank account routing number card number cvv",
            "your order cannot be processed update payment method credit card billing address now",
            "identity verification required upload photo id passport driver license social security",
            "ebay account suspended verify identity enter payment card number expiry cvv billing address",
            "chase bank unusual activity confirm identity account number routing number pin urgent",
        ] * 300

        texts  = benign_texts + phishing_texts
        labels = [0]*len(benign_texts) + [1]*len(phishing_texts)

        vec = TfidfVectorizer(max_features=4500, ngram_range=(1,3),
                              stop_words="english", sublinear_tf=True)
        X   = vec.fit_transform(texts)
        clf = LogisticRegression(max_iter=1200, C=2.8, random_state=42, class_weight="balanced")
        clf.fit(X, labels)

        bundle = {"vectorizer": vec, "clf": clf}
        joblib.dump(bundle, NLP_MODEL_PATH)
        return bundle

    def _level(self, s):
        if s < 0.25: return "LOW"
        if s < 0.50: return "MEDIUM"
        if s < 0.75: return "HIGH"
        return "CRITICAL"

    def _summary(self, score, flags):
        return {
            "LOW":      "Page content appears legitimate with no notable threat indicators.",
            "MEDIUM":   f"Page content shows {len(flags)} concern(s) worth investigating.",
            "HIGH":     "Page content contains multiple threat indicators and suspicious elements.",
            "CRITICAL": "Page strongly resembles a credential-harvesting or phishing page.",
        }[self._level(score)]
