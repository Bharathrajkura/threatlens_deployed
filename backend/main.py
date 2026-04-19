from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
from modules.ml_analyzer import MLAnalyzer
from modules.nlp_analyzer import NLPAnalyzer
from modules.api_analyzer import APIAnalyzer
from modules.score_normalizer import ScoreNormalizer

app = FastAPI(title="ThreatLens API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ml_analyzer = MLAnalyzer()
nlp_analyzer = NLPAnalyzer()
api_analyzer = APIAnalyzer()
normalizer = ScoreNormalizer()


class URLRequest(BaseModel):
    url: str
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""


@app.post("/analyze")
async def analyze_url(request: URLRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Run all 3 analyzers
    ml_result = ml_analyzer.analyze(url)
    nlp_result = await nlp_analyzer.analyze(url)
    api_result = await api_analyzer.analyze(
        url,
        request.virustotal_api_key,
        request.abuseipdb_api_key
    )

    # Normalize and combine
    final = normalizer.combine(ml_result, nlp_result, api_result)

    return {
        "url": url,
        "ml_analysis": ml_result,
        "nlp_analysis": nlp_result,
        "api_analysis": api_result,
        "final_result": final
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "ThreatLens"}
