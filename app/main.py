import asyncio
import time
import psutil
import platform
from collections import deque, defaultdict
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header, Depends
from pydantic import BaseModel
from enum import Enum
import os
from datetime import datetime, timedelta
from bson import ObjectId
from fastapi.middleware.cors import CORSMiddleware
from odoo_connector import OdooConnector
from logs import LogIngest, LogEntry
from sim_runner import run_simulation_async
from detections import DetectionService
from anomaly import AnomalyService
from rl_agent import AnomalyRLAgent
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

# Track application start time
start_time = time.time()

odoo = OdooConnector(host=os.getenv("ODOO_HOST", "localhost"), port=int(os.getenv("ODOO_PORT", "8069")))
log_ingest = LogIngest()
anomaly_service = AnomalyService()
detect_service = DetectionService()
anomaly_rl = AnomalyRLAgent()
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
    
    # Initialize ML defending system
    try:
        from app.ml_init import initialize_ml_system
        success = await initialize_ml_system()
        if success:
            logger.info(" ML defending system initialized successfully")
        else:
            logger.warning(" ML system initialization failed, continuing without ML features")
    except Exception as e:
        logger.error(f" ML system initialization error: {e}")
    
    # Schedule RL training if configured
    try:
        interval_min = float(os.getenv('ANOMALY_RL_INTERVAL_MINUTES', '0'))
    except Exception:
        interval_min = 0.0
    if interval_min and interval_min > 0:
        async def _rl_loop():
            while True:
                try:
                    await anomaly_rl.train_step(window_minutes=int(max(5, interval_min)))
                except Exception as e:
                    logger.warning({"event":"anomaly_rl_error","error":str(e)})
                # sleep interval
                await asyncio.sleep(int(interval_min * 60))
        asyncio.create_task(_rl_loop())

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

@app.get('/server/status')
async def server_status():
    """Comprehensive server status monitoring endpoint"""
    try:
        # System information
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Load averages
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        
        # Temperature (if available)
        temps = {}
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temp_sensors = psutil.sensors_temperatures()
                for name, entries in temp_sensors.items():
                    temps[name] = [{'label': entry.label or 'unknown', 'current': entry.current} for entry in entries]
        except:
            temps = {'error': 'Temperature sensors not available'}
        
        # Boot time
        boot_time = datetime.fromtimestamp(psutil.boot_time()).isoformat()
        
        # Process count
        process_count = len(psutil.pids())
        
        # Service health
        services_status = {}
        
        # MongoDB
        try:
            mongo_stats = await log_ingest.db.command('serverStatus')
            services_status['mongodb'] = {
                'status': 'healthy',
                'version': mongo_stats.get('version'),
                'uptime': mongo_stats.get('uptime'),
                'connections': mongo_stats.get('connections', {}).get('current')
            }
        except Exception as e:
            services_status['mongodb'] = {'status': 'unhealthy', 'error': str(e)}
        
        # Odoo
        try:
            users = odoo.list_users('test')
            services_status['odoo'] = {
                'status': 'healthy',
                'user_count': len(users) if users else 0
            }
        except Exception as e:
            services_status['odoo'] = {'status': 'unhealthy', 'error': str(e)}
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'uptime': {
                'seconds': int(time.time() - start_time),
                'human_readable': str(timedelta(seconds=int(time.time() - start_time)))
            },
            'system': {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'boot_time': boot_time
            },
            'performance': {
                'cpu': {
                    'percent': cpu_percent,
                    'count': psutil.cpu_count(),
                    'load_average': {
                        '1min': load_avg[0],
                        '5min': load_avg[1],
                        '15min': load_avg[2]
                    }
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'percent': memory.percent,
                    'swap': psutil.swap_memory()._asdict() if psutil.swap_memory().total > 0 else None
                },
                'disk': {
                    'total_gb': round(disk.total / (1024**3), 2),
                    'free_gb': round(disk.free / (1024**3), 2),
                    'used_gb': round(disk.used / (1024**3), 2),
                    'percent': round((disk.used / disk.total) * 100, 2)
                },
                'temperature': temps,
                'processes': {
                    'total': process_count,
                    'running': len([p for p in psutil.process_iter(['status']) if p.info['status'] == 'running']),
                    'sleeping': len([p for p in psutil.process_iter(['status']) if p.info['status'] == 'sleeping'])
                }
            },
            'services': services_status,
            'application': {
                'pid': os.getpid(),
                'memory_mb': round(psutil.Process().memory_info().rss / (1024**2), 2),
                'threads': psutil.Process().num_threads(),
                'status': 'running'
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Status check failed: {str(e)}')

# Optional API key protection (only enforced if API_KEY env var is set)
API_KEY = os.getenv('API_KEY')

async def require_api_key(x_api_key: str | None = Header(default=None)):
    # Temporarily disabled for testing
    return

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

class SimType(str, Enum):
    brute_force = "brute_force"
    port_scan = "port_scan"
    sql_injection = "sql_injection"
    phishing = "phishing"
    ddos = "ddos"
    xss_probe = "xss_probe"
    data_exfiltration = "data_exfiltration"
    ransomware = "ransomware"
    lateral_movement = "lateral_movement"
    malware_beacon = "malware_beacon"
    password_spray = "password_spray"
    directory_traversal = "directory_traversal"
    csrf_probe = "csrf_probe"
    command_injection = "command_injection"
    file_upload_probe = "file_upload_probe"
    ssrf_probe = "ssrf_probe"
    jwt_tamper = "jwt_tamper"
    credential_stuffing = "credential_stuffing"
    web_cache_deception = "web_cache_deception"

class SimRequest(BaseModel):
    target: str
    db: str
    user: str
    wordlist: list[str] = []
    delay: float = 1.0
    sandbox: bool = True
    sim_type: SimType = SimType.brute_force  # validated enum of supported simulations
    attempts: int = 5  # used by some sim types when no explicit list is provided
    scan_ports: list[int] = []  # for port_scan
    payloads: list[str] = []  # for sql_injection or other payload-driven sims
    hosts: list[str] = []  # for lateral_movement
    data_size_kb: int = 100  # for data_exfiltration
    chunk_size_kb: int = 10  # for data_exfiltration
    users: list[str] = []  # for password_spray
    password: str | None = None  # for password_spray
    paths: list[str] = []  # for directory_traversal

@app.post('/run-simulation')
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
    if sim.attempts < 1 or sim.attempts > 100:
        raise HTTPException(status_code=400, detail="attempts must be between 1 and 100")
    if sim.scan_ports and len(sim.scan_ports) > 100:
        raise HTTPException(status_code=400, detail="too many ports (max 100)")
    if sim.hosts and len(sim.hosts) > 100:
        raise HTTPException(status_code=400, detail="too many hosts (max 100)")
    if sim.data_size_kb < 1 or sim.data_size_kb > 100000:
        raise HTTPException(status_code=400, detail="data_size_kb must be between 1 and 100000")
    if sim.chunk_size_kb < 1 or sim.chunk_size_kb > sim.data_size_kb:
        raise HTTPException(status_code=400, detail="chunk_size_kb must be between 1 and data_size_kb")
    if sim.users and len(sim.users) > 500:
        raise HTTPException(status_code=400, detail="too many users (max 500)")
    if sim.paths and len(sim.paths) > 200:
        raise HTTPException(status_code=400, detail="too many paths (max 200)")
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
async def anomalies_latest(limit: int = 20, use_rl_threshold: bool = False, min_score: float | None = None):
    result = await anomaly_service.latest_anomalies(limit)
    # Optionally filter by RL-selected threshold or explicit min_score
    rows = result.get('results', [])
    thr = None
    if use_rl_threshold:
        try:
            thr = await anomaly_rl.get_threshold()
        except Exception:
            thr = None
    if min_score is not None:
        thr = float(min_score)
    if thr is not None:
        rows = [r for r in rows if float(r.get('anomaly_score', 0.0)) >= float(thr)]
    return { 'count': len(rows), 'results': rows, 'threshold_used': thr }

@app.get('/anomaly-rl/status')
async def anomaly_rl_status():
    return await anomaly_rl.status()

@app.post('/anomaly-rl/train-step')
async def anomaly_rl_train(window_minutes: int = 30):
    out = await anomaly_rl.train_step(window_minutes=window_minutes)
    return out

@app.get('/alerts/derived/debug')
async def derived_alerts_debug():
    """Debug endpoint to see all derived alerts without time filtering"""
    try:
        cursor = detect_service.db.derived_alerts.find({}).sort([('last_seen', -1)]).limit(10)
        out = []
        async for d in cursor:
            d['_id'] = str(d['_id'])
            out.append(d)
        return {'count': len(out), 'results': out}
    except Exception as e:
        return {'error': str(e), 'count': 0, 'results': []}

@app.get('/alerts/derived')
async def derived_alerts(limit: int = 50, window_minutes: int = 30, severity: str | None = None, type_contains: str | None = None, skip: int = 0):
    result = await detect_service.derived_alerts(limit=limit, window_minutes=window_minutes, severity=severity, type_contains=type_contains, skip=skip)
    return result

@app.get('/alerts/related')
async def related_events(alert_type: str, limit: int = 20, window_minutes: int = 60):
    # Map derived alert types to relevant raw event_types
    mapping = {
        'brute_force_detected': ['login_attempt','brute_force_attempt'],
        'port_scan_detected': ['port_scan_probe'],
        'sql_injection_detected': ['sql_injection_attempt'],
        'xss_detected': ['xss_probe'],
        'ddos_spike_detected': ['ddos_traffic'],
        'phishing_campaign_detected': ['phishing_email'],
        'ransomware_activity_detected': ['ransomware_encrypt'],
        'data_exfiltration_detected': ['data_exfiltration'],
        'lateral_movement_detected': ['lateral_movement_attempt'],
        'c2_beaconing_detected': ['malware_beacon'],
        'password_spray_detected': ['password_spray_attempt'],
        'dir_traversal_detected': ['dir_traversal_probe'],
        'csrf_detected': ['csrf_probe'],
        'cmd_injection_detected': ['cmd_injection_probe'],
        'file_upload_abuse_detected': ['file_upload_probe'],
        'ssrf_detected': ['ssrf_probe'],
        'jwt_tamper_detected': ['jwt_tamper_probe'],
        'web_cache_deception_detected': ['web_cache_deception_probe'],
        'kill_chain_progression': ['password_spray_attempt','lateral_movement_attempt']
    }
    event_types = mapping.get(alert_type, [])
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    q = {'ts': {'$gte': cutoff}}
    if event_types:
        q['event_type'] = {'$in': event_types}
    cursor = log_ingest.db.logs.find(q).sort([('_id', -1)]).limit(limit)
    out = []
    async for d in cursor:
        d['_id'] = str(d['_id'])
        out.append(d)
    return {'count': len(out), 'results': out}

@app.get('/metrics')
async def metrics():
    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Network stats
    network = psutil.net_io_counters()
    
    # Process info
    process = psutil.Process()
    process_memory = process.memory_info()
    
    # Database metrics
    total = await log_ingest.db.logs.count_documents({})
    cutoff = datetime.utcnow() - timedelta(hours=1)
    oid_cutoff = ObjectId.from_datetime(cutoff)
    last_hour = await log_ingest.db.logs.count_documents({"_id": {"$gte": oid_cutoff}})
    
    # Service health checks
    services_status = {}
    
    # MongoDB status
    try:
        await log_ingest.db.command('ping')
        services_status['mongodb'] = 'healthy'
    except Exception as e:
        services_status['mongodb'] = f'unhealthy: {str(e)}'
    
    # Odoo status
    try:
        users = odoo.list_users('test')  # Try to connect
        services_status['odoo'] = 'healthy'
    except Exception as e:
        services_status['odoo'] = f'unhealthy: {str(e)}'
    
    # RL Agent status
    try:
        rl_status = await anomaly_rl.status()
        services_status['rl_agent'] = 'healthy' if rl_status.get('status') == 'ok' else 'training'
    except Exception as e:
        services_status['rl_agent'] = f'unhealthy: {str(e)}'
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system": {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "cpu_percent": cpu_percent,
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "used_gb": round(memory.used / (1024**3), 2),
                "percent": memory.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "used_gb": round(disk.used / (1024**3), 2),
                "percent": round((disk.used / disk.total) * 100, 2)
            },
            "network": {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            },
            "process": {
                "pid": process.pid,
                "memory_mb": round(process_memory.rss / (1024**2), 2),
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads(),
                "status": process.status()
            }
        },
        "services": services_status,
        "application": {
            "total_logs": int(total),
            "logs_last_hour": int(last_hour),
            "uptime_seconds": int(time.time() - start_time) if 'start_time' in globals() else 0
        }
    }
