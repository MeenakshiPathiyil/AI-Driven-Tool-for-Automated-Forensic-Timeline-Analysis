from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import pandas as pd
import os
import shutil
import uuid
import json
from analyze_logs import run_analysis

app = FastAPI()

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

latest_uploaded_file = {"path": None}  

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename)[-1]
    if ext.lower() != '.csv':
        return {"error": "Please upload a CSV file."}
    file_id = str(uuid.uuid4())[:8]
    saved_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")

    with open(saved_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    latest_uploaded_file["path"] = saved_path
    return {"filename": file.filename, "id": file_id, "path": saved_path}

@app.post("/analyze")
async def analyze_logs(payload: dict):
    log_path = latest_uploaded_file.get("path")
    if not log_path or not os.path.exists(log_path):
        return {"error": "No log file found. Please upload first."}

    iocs = payload.get("iocs", [])
    output_file = os.path.join(UPLOAD_DIR, f"analysis_{os.path.basename(log_path).split('.')[0]}.json")

    try:
        raw_df = pd.read_csv(log_path, low_memory=False)
        result = run_analysis(raw_df, iocs=iocs, output_file=output_file)
        return {
            "summary": result["summary"],
            "anomalies": result["anomalies"],
            "output_file": output_file
        }
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}

@app.get("/download/{file_path:path}")
async def download_file(file_path: str):
    file_path = os.path.join(UPLOAD_DIR, os.path.basename(file_path))  # Prevent directory traversal
    if not os.path.exists(file_path):
        return {"error": "File not found."}
    return FileResponse(file_path, filename=os.path.basename(file_path))




