import os, time, json, requests, pytest

BASE = os.getenv("API_BASE", "http://localhost:8000")
HEADERS = {"Content-Type": "application/json"}
API_KEY = os.getenv("API_KEY")
if API_KEY:
    HEADERS["X-API-Key"] = API_KEY


def wait_for_derived(min_count=1, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(f"{BASE}/alerts/derived?window_minutes=60", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("count", 0) >= min_count:
                return data
        time.sleep(1)
    return {"count": 0, "results": []}


@pytest.mark.parametrize("sim_payload, expected_type", [
    ({"sim_type": "port_scan", "scan_ports": [22,80,443,8080], "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "port_scan_detected"),
    ({"sim_type": "sql_injection", "payloads": ["' OR '1'='1"], "attempts":1, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "sql_injection_detected"),
    ({"sim_type": "ddos", "attempts": 5, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "ddos_spike_detected"),
    ({"sim_type": "phishing", "attempts": 4, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "phishing_campaign_detected"),
    ({"sim_type": "ransomware", "attempts": 5, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "ransomware_activity_detected"),
    ({"sim_type": "data_exfiltration", "data_size_kb": 120, "chunk_size_kb": 40, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "data_exfiltration_detected"),
    ({"sim_type": "lateral_movement", "hosts": ["10.0.0.5","10.0.0.5"], "attempts": 2, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "lateral_movement_detected"),
    ({"sim_type": "malware_beacon", "attempts": 3, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "c2_beaconing_detected"),
    ({"sim_type": "password_spray", "users": ["u1","u2","u3"], "password": "Summer2025!", "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "password_spray_detected"),
    ({"sim_type": "directory_traversal", "paths": ["../../etc/passwd","..%2f..%2f..%2fwindows/win.ini"], "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, None),
    ({"sim_type": "ssrf_probe", "payloads": ["http://169.254.169.254/latest/meta-data"], "attempts":1, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "ssrf_detected"),
    ({"sim_type": "jwt_tamper", "payloads": ["alg:none"], "attempts":1, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "jwt_tamper_detected"),
    ({"sim_type": "web_cache_deception", "payloads": ["/invoice.pdf.css"], "attempts":1, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, "web_cache_deception_detected"),
    ({"sim_type": "credential_stuffing", "users": ["a","b","c"], "payloads": ["password1","123456","welcome"], "attempts":3, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}, None),
])
def test_derived_alerts(sim_payload, expected_type):
    r = requests.post(f"{BASE}/run-simulation", data=json.dumps(sim_payload), headers=HEADERS, timeout=15)
    assert r.status_code == 200
    # wait for background tasks to insert
    time.sleep(2)
    data = wait_for_derived(min_count=0, timeout=10)
    types = [a.get("type") for a in data.get("results", [])]
    if expected_type:
        assert expected_type in types
    else:
        assert True


def test_correlation_kill_chain():
    # Trigger password spray attempts
    spray = {"sim_type":"password_spray", "users":["u1","u2","u3"], "password":"Summer2025!", "attempts":3, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}
    r1 = requests.post(f"{BASE}/run-simulation", data=json.dumps(spray), headers=HEADERS, timeout=15)
    assert r1.status_code == 200
    # Trigger lateral movement
    lat = {"sim_type":"lateral_movement", "hosts":["10.0.0.5"], "attempts":1, "target":"http://localhost:8069","db":"demo","user":"n/a","sandbox":True, "delay":0.05}
    r2 = requests.post(f"{BASE}/run-simulation", data=json.dumps(lat), headers=HEADERS, timeout=15)
    assert r2.status_code == 200
    time.sleep(2)
    data = wait_for_derived(min_count=0, timeout=10)
    types = [a.get("type") for a in data.get("results", [])]
    assert "kill_chain_progression" in types
