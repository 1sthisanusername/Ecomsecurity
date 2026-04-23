# pip install fastapi uvicorn python-multipart supabase

"""
main.py — E-Commerce Risk & Threat Monitoring — FastAPI Backend
Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from parser import parse_logs, parse_uploaded_file, parse_supabase_db

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

@app.post("/api/metrics")
async def get_metrics(
    file: UploadFile = File(None),
    supabase_url: str = Form(None),
    supabase_key: str = Form(None)
):
    """
    Trigger log parsing and return the full threat metrics dictionary.

    Accepts either:
    - An uploaded log file (UploadFile)
    - Supabase credentials (supabase_url and supabase_key)

    Returns:
        {
            "failed_logins":       {ip: count},
            "suspicious_requests": {"SQLi": count, "XSS": count},
            "bot_activity":        {ip: count},
        }
    """
    try:
        if file:
            # Handle uploaded file
            file_content = await file.read()
            metrics = parse_uploaded_file(file_content)
        elif supabase_url and supabase_key:
            # Handle Supabase database
            metrics = parse_supabase_db(supabase_url, supabase_key)
        else:
            raise HTTPException(
                status_code=400,
                detail="Either upload a log file or provide Supabase credentials (supabase_url and supabase_key)"
            )
        
        return metrics
    
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        )
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(
            status_code=400,
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
