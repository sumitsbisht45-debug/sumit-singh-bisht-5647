
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI(title="ScamShield AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

class ScanRequest(BaseModel):
    text: str

def analyse(text, mode):
    content = text.lower()
    score = 0
    reasons = []

    suspicious_words = [
        "urgent", "verify", "password",
        "otp", "free prize", "click here",
        "account blocked", "bank details"
    ]

    for word in suspicious_words:
        if word in content:
            score += 12
            reasons.append(
                f"Suspicious indicator detected: {word}"
            )

    if re.search(r"pay|registration fee|security deposit", content):
        score += 25
        reasons.append("Possible payment request detected")

    if mode == "url":
        if not content.startswith("https://"):
            score += 15
            reasons.append("URL does not use HTTPS")

        if re.search(r"\d+\.\d+\.\d+\.\d+", content):
            score += 25
            reasons.append("URL contains an IP address")

    score = min(score, 100)

    if score >= 65:
        level = "High"
        verdict = "Potential scam detected"
    elif score >= 30:
        level = "Medium"
        verdict = "Suspicious content detected"
    else:
        level = "Low"
        verdict = "No major warning signs detected"

    if not reasons:
        reasons.append(
            "No known suspicious patterns were detected."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": verdict,
        "reasons": reasons
    }

@app.get("/")
def home():
    return {"message": "ScamShield AI Backend Running"}

@app.get("/api/health")
def health():
    return {"status": "online"}

@app.post("/api/scan/url")
def scan_url(data: ScanRequest):
    return analyse(data.text, "url")

@app.post("/api/scan/message")
def scan_message(data: ScanRequest):
    return analyse(data.text, "message")

@app.post("/api/scan/job")
def scan_job(data: ScanRequest):
    return analyse(data.text, "job")
