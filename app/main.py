import asyncio
import time
from collections import deque, defaultdict
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header, Depends
from pydantic import BaseModel
import os
from datetime import datetime, timedelta
from bson import ObjectId
from fastapi.middleware.cors import CORSMiddleware
from odoo_connector import OdooConnector
from logs import LogIngest, LogEntry
from sim_runner import run_simulation_async
from anomaly import AnomalyService
import logging
from urllib.parse import urlparse
app = FastAPI(title="CyberSentinelAI API - Phase1 Extended")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"]
    ,allow_headers=["*"]
)
odoo = OdooConnector(host=os.getenv("ODOO_HOST", "localhost"), port=int(os.getenv("ODOO_PORT", "8069")))
log_ingest = LogIngest()
anomaly_service = AnomalyService()
logger = logging.getLogger("cybersentinel")
logging.basicConfig(level=logging.INFO)

# Simple in-memory rate limiting: max 5 simulation requests per IP per minute
RATE_LIMIT_WINDOW_S = 60
RATE_LIMIT_MAX = 5
_rate_buckets = defaultdict(lambda: deque())

@app.on_event('startup')
async def on_startup():
    # Ensure Mongo indexes exist for performant queries
    await log_ingest.ensure_indexes()

@app.get('/health')
def health():
    logger.info({"event":"health"})
    return {'status':'ok'}

@app.get('/health/ready')
async def health_ready():
    try:
        # ping Mongo to ensure connectivity
        await log_ingest.db.command('ping')
        return {'ready': True}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f'ready:false: {e}')

# Optional API key protection (only enforced if API_KEY env var is set)
API_KEY = os.getenv('API_KEY')

async def require_api_key(x_api_key: str | None = Header(default=None)):
    if not API_KEY:
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid or missing API key')

@app.post('/logs', dependencies=[Depends(require_api_key)])
async def ingest_log(entry: LogEntry):
    logger.info({"event":"ingest_log","source":entry.source,"event_type":entry.event_type})
    await log_ingest.insert(entry.dict())
    return {'ingested': True}

@app.get('/odoo/users')
def list_users(db: str = None):
    try:
        users = odoo.list_users(db_name=db)
        return {'count': len(users), 'users': users[:50]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class SimRequest(BaseModel):
    target: str
    db: str
    user: str
    wordlist: list[str] = []
    delay: float = 1.0
    sandbox: bool = True

@app.post('/run-simulation', dependencies=[Depends(require_api_key)])
async def run_sim(sim: SimRequest, background_tasks: BackgroundTasks, request: Request):
    if not sim.sandbox:
        raise HTTPException(status_code=403, detail="Simulations allowed only in sandbox mode")
    parsed = urlparse(sim.target)
    allowed_hosts = {"odoo", "localhost", "127.0.0.1"}
    allowed_ports = {8069}
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="invalid target scheme")
    if parsed.hostname not in allowed_hosts:
        raise HTTPException(status_code=400, detail="target not allowed")
    if parsed.port and parsed.port not in allowed_ports:
        raise HTTPException(status_code=400, detail="target port not allowed")
    if sim.wordlist and len(sim.wordlist) > 50:
        raise HTTPException(status_code=400, detail="wordlist too large (max 50)")
    if sim.delay < 0.05 or sim.delay > 5.0:
        raise HTTPException(status_code=400, detail="delay must be between 0.05 and 5.0 seconds")
    if not sim.db:
        raise HTTPException(status_code=400, detail="db is required")
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = _rate_buckets[client_ip]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_S:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many simulation requests, please try later")
    bucket.append(now)
    logger.info({"event":"run_simulation","client_ip":client_ip,"db":sim.db,"target":sim.target,"attempts":len(sim.wordlist or [])})
    asyncio.create_task(run_simulation_async(sim.dict()))
    return {'started': True, 'note': 'Simulation running in background'}

@app.get('/alerts/latest')
async def latest_alerts(limit: int = 20):
    # simple retrieval of recent logs flagged as alerts
    docs = await log_ingest.get_latest(limit)
    return {'count': len(docs), 'results': docs}

@app.get('/anomalies/latest')
async def anomalies_latest(limit: int = 20):
    result = await anomaly_service.latest_anomalies(limit)
    return result

@app.get('/metrics')
async def metrics():
    # total logs
    total = await log_ingest.db.logs.count_documents({})
    # last hour using ObjectId timestamp
    cutoff = datetime.utcnow() - timedelta(hours=1)
    oid_cutoff = ObjectId.from_datetime(cutoff)
    last_hour = await log_ingest.db.logs.count_documents({"_id": {"$gte": oid_cutoff}})
    return {
        "total_logs": int(total),
        "logs_last_hour": int(last_hour)
    }
