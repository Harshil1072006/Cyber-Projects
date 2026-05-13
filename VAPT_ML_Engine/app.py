import uuid
import os
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from predictor_fast import FastVAPTPredictor

app = FastAPI(title="VulneraSense ML API", version="1.1.1")

# Mount the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# We will initialize the predictor when the app starts.
predictor = None

@app.on_event("startup")
async def startup_event():
    global predictor
    print("🚀 Initializing VulneraSense ML API (v1.1.1)")
    try:
        predictor = FastVAPTPredictor(model_path="./models/vapt_rf_model.pkl", vec_path="./models/vapt_rf_vectorizer.pkl")
        print("✅ Fast ML Predictor Engine Loaded into Memory.")
    except Exception as e:
        print(f"⚠️ Predictor could not be loaded: {e}")
        print("⚠️ Ensure you have run 'python train_fast.py' to generate the model first.")

@app.get("/")
def read_root():
    # Return the nice UI instead of raw JSON
    return FileResponse("static/index.html")

@app.get("/api/status")
def get_status():
    status = "Active" if predictor else "Model Not Trained"
    return {"name": "VAPT_ML_Engine", "version": "1.1.1", "model_status": status}

class CodeSnippet(BaseModel):
    code: str

@app.post("/api/predict/snippet")
async def predict_snippet(payload: CodeSnippet):
    """Predict vulnerability for a raw code string."""
    if not predictor:
        raise HTTPException(status_code=503, detail="ML Model not trained or loaded yet.")
    
    prob = predictor.scan_code(payload.code)
    is_vulnerable = prob > 0.5
    
    return {
        "vulnerability_probability": round(prob * 100, 2),
        "is_vulnerable": is_vulnerable,
        "risk_level": "High" if prob > 0.7 else "Medium" if prob > 0.4 else "Low"
    }

@app.post("/api/predict/file")
async def predict_file(file: UploadFile = File(...)):
    """Upload a file and predict vulnerability."""
    if not predictor:
        raise HTTPException(status_code=503, detail="ML Model not trained or loaded yet.")
        
    content = await file.read()
    try:
        code_str = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Only UTF-8 text/source files are supported.")
        
    prob = predictor.scan_code(code_str)
    
    return {
        "filename": file.filename,
        "vulnerability_probability": round(prob * 100, 2),
        "is_vulnerable": prob > 0.5
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8585)
