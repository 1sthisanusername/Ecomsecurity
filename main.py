# pip install fastapi uvicorn

"""
main.py — E-Commerce Risk & Threat Monitoring — FastAPI Backend
Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from parser import parse_logs

# ------------------------------------------------------------------ #
# App Initialisation
# ------------------------------------------------------------------ #

app = FastAPI(
    title="E-Commerce Risk & Threat Monitoring API",
    description="Parses NGINX access logs and surfaces security threat metrics.",
    version="1.0.0",
)

# ------------------------------------------------------------------ #
# CORS — allow all origins for local MVP development
# ------------------------------------------------------------------ #

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------ #
# Routes
# ------------------------------------------------------------------ #

@app.get("/api/metrics")
def get_metrics():
    """
    Trigger log parsing and return the full threat metrics dictionary.

    Returns:
        {
            "failed_logins":       {ip: count},
            "suspicious_requests": {"SQLi": count, "XSS": count},
            "bot_activity":        {ip: count},
        }
    """
    try:
        metrics = parse_logs()
        return metrics
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Internal parser error: {exc}",
        )


@app.get("/health")
def health_check():
    return {"status": "ok"}


# ------------------------------------------------------------------ #
# Entry Point
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
