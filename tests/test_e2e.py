import subprocess, time, requests, os, pytest

COMPOSE_FILE = os.path.join(os.path.dirname(__file__), '..', 'docker-compose.yml')

def run(cmd):
    print('RUN:', cmd)
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(res.stdout)
    print(res.stderr)
    return res.returncode, res.stdout, res.stderr

@pytest.mark.skipif(True, reason='Requires Docker to run; enable when running in CI with Docker available')
def test_e2e_simulation():
    # Start services
    rc, out, err = run(f'docker compose -f {COMPOSE_FILE} up -d --build')
    assert rc == 0
    # wait for backend to be up
    for _ in range(30):
        try:
            r = requests.get('http://localhost:8000/health', timeout=2)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(2)
    assert r.status_code == 200

    # Trigger simulation
    payload = {'target':'http://localhost:8069','db':'demo','user':'test','wordlist':['pw1','pw2'],'sandbox':True}
    r2 = requests.post('http://localhost:8000/run-simulation', json=payload, timeout=5)
    assert r2.status_code == 200

    # wait a few seconds for logs to be ingested
    time.sleep(5)
    r3 = requests.get('http://localhost:8000/alerts/latest', timeout=5)
    assert r3.status_code == 200
    data = r3.json()
    assert 'results' in data

    # Tear down
    rc2, _, _ = run(f'docker compose -f {COMPOSE_FILE} down -v --remove-orphans')
    assert rc2 == 0
