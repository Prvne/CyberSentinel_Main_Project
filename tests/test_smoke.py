import os
import time
import json
import requests

BASE = os.getenv("API_BASE", "http://localhost:8000")


def test_health_ok():
    r = requests.get(f"{BASE}/health", timeout=10)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_logs_and_alerts_flow():
    payload = {
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "source": "pytest",
        "event_type": "test_event",
        "payload": {"msg": "hello", "level": "info"},
    }
    r = requests.post(f"{BASE}/logs", data=json.dumps(payload), headers={"Content-Type":"application/json"}, timeout=10)
    assert r.status_code == 200
    assert r.json().get("ingested") is True

    r2 = requests.get(f"{BASE}/alerts/latest?limit=5", timeout=10)
    assert r2.status_code == 200
    data = r2.json()
    assert "count" in data and "results" in data


def test_anomalies_endpoint():
    r = requests.get(f"{BASE}/anomalies/latest?limit=5", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert "count" in data and "results" in data


def test_metrics_endpoint():
    r = requests.get(f"{BASE}/metrics", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert "total_logs" in data and "logs_last_hour" in data
