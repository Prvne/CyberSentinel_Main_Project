from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.ml_api import router as ml_router

app = FastAPI(title="CyberSentinelAI ML Defender")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok"}

app.include_router(ml_router)
