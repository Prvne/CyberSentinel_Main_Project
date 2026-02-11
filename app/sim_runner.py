import subprocess, os, json, time
from logs import LogIngest
import asyncio
import random


_CVE_KB = {
    "brute_force_attempt": {
        "cve": "CWE-307",
        "cvss": 7.5,
        "capec": "CAPEC-112",
        "summary": "Brute force / insufficient rate limiting",
        "recommendation": "Enable MFA, rate limiting, and account lockout policies."
    },
    "password_spray_attempt": {
        "cve": "CWE-307",
        "cvss": 7.2,
        "capec": "CAPEC-112",
        "summary": "Password spraying",
        "recommendation": "Enable MFA and anomaly-based login throttling; block known bad IP ranges."
    },
    "credential_stuffing_attempt": {
        "cve": "CWE-307",
        "cvss": 8.0,
        "capec": "CAPEC-114",
        "summary": "Credential stuffing",
        "recommendation": "Use breached-password checks, MFA, bot detection, and rate limiting."
    },
    "port_scan_probe": {
        "cve": "CWE-200",
        "cvss": 5.3,
        "capec": "CAPEC-300",
        "summary": "Port scanning / service enumeration",
        "recommendation": "Close unused ports, segment network, and deploy IDS/IPS with scan detection."
    },
    "sql_injection_probe": {
        "cve": "CWE-89",
        "cvss": 9.8,
        "capec": "CAPEC-66",
        "summary": "SQL injection",
        "recommendation": "Use parameterized queries, input validation, and WAF rules; patch vulnerable modules."
    },
    "xss_probe": {
        "cve": "CWE-79",
        "cvss": 6.1,
        "capec": "CAPEC-63",
        "summary": "Cross-site scripting",
        "recommendation": "Output encode, enable CSP, and sanitize untrusted input."
    },
    "ddos_traffic_sim": {
        "cve": "CAPEC-125",
        "cvss": 8.6,
        "capec": "CAPEC-125",
        "summary": "DDoS / resource exhaustion",
        "recommendation": "Use DDoS protection, rate limiting at edge, and autoscaling."
    },
}


def _enrich_with_cve(entry: dict) -> dict:
    et = entry.get('event_type')
    kb = _CVE_KB.get(et)
    if not kb:
        return entry
    payload = entry.get('payload') or {}
    if not isinstance(payload, dict):
        payload = {'raw_payload': payload}
    payload.setdefault('cve', {
        'id': kb.get('cve'),
        'cvss': kb.get('cvss'),
        'capec': kb.get('capec'),
        'summary': kb.get('summary')
    })
    payload.setdefault('recommended_fix', kb.get('recommendation'))
    entry['payload'] = payload
    return entry


class _QLearningAttacker:
    """Lightweight RL attacker policy (DQN-style behavior, tabular Q-learning).

    State is discrete and compact so we can keep it dependency-free.
    """

    def __init__(self, actions, epsilon=0.2, alpha=0.25, gamma=0.9):
        self.actions = list(actions)
        self.epsilon = float(epsilon)
        self.alpha = float(alpha)
        self.gamma = float(gamma)
        self.q = {}

    def _key(self, state):
        return str(state)

    def act(self, state):
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        sk = self._key(state)
        qs = self.q.get(sk, {})
        if not qs:
            return random.choice(self.actions)
        return max(qs.items(), key=lambda kv: kv[1])[0]

    def update(self, state, action, reward, next_state):
        sk = self._key(state)
        nk = self._key(next_state)
        self.q.setdefault(sk, {})
        self.q[sk].setdefault(action, 0.0)
        next_qs = self.q.get(nk, {})
        max_next = max(next_qs.values()) if next_qs else 0.0
        old = float(self.q[sk][action])
        self.q[sk][action] = old + self.alpha * (float(reward) + self.gamma * max_next - old)


def _severity_from_cvss(cvss: float) -> str:
    try:
        c = float(cvss)
    except Exception:
        return 'low'
    if c >= 9.0:
        return 'critical'
    if c >= 7.0:
        return 'high'
    if c >= 4.0:
        return 'medium'
    return 'low'

async def run_simulation_async(cfg: dict):
    """Async simulation that inserts events via motor within the app event loop."""
    mongo = LogIngest()
    target = cfg.get('target')
    db = cfg.get('db')
    user = cfg.get('user')
    wordlist = cfg.get('wordlist') or []
    delay = cfg.get('delay', 1.0)
    sim_type = cfg.get('sim_type', 'brute_force')
    attempts = cfg.get('attempts', 5)
    scan_ports = cfg.get('scan_ports') or []
    payloads = cfg.get('payloads') or []

    async def _emit(entry: dict, emit_recommendation: bool = False):
        entry = _enrich_with_cve(entry)
        try:
            await mongo.insert(entry)
        except Exception as e:
            print('Log ingest failed:', e)
        if emit_recommendation:
            payload = entry.get('payload') or {}
            cve = payload.get('cve') if isinstance(payload, dict) else None
            if isinstance(cve, dict):
                cvss = cve.get('cvss')
                rec = payload.get('recommended_fix')
                rec_entry = {
                    'timestamp': entry.get('timestamp'),
                    'source': 'sim_runner',
                    'event_type': 'patch_recommendation',
                    'payload': {
                        'target': payload.get('target'),
                        'event_type': entry.get('event_type'),
                        'cve': cve,
                        'cvss': cvss,
                        'severity': _severity_from_cvss(cvss),
                        'recommendation': rec,
                        'result': 'simulated'
                    }
                }
                try:
                    await mongo.insert(rec_entry)
                except Exception as e:
                    print('Log ingest failed:', e)

    if sim_type == 'brute_force':
        for i, pw in enumerate(wordlist):
            # Simulate adaptive techniques
            result = 'success' if i == len(wordlist) - 1 else 'failed'
            techniques = ['password_spray', 'credential_stuffing', 'hybrid_attack']
            technique = techniques[i % len(techniques)]
            
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'brute_force_attempt',
                'payload': {
                    'target': target, 
                    'db': db, 
                    'user': user, 
                    'password': pw, 
                    'result': result,
                    'technique': technique,
                    'source_ip': f'192.168.1.{100 + i % 155}',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'session_id': f'sess_{int(time.time())}_{i}'
                }
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'credential_stuffing':
        users_list = (cfg.get('users') or [user, f"{user}2", f"{user}3"])[:max(1, int(attempts))]
        pwlist = (cfg.get('payloads') or cfg.get('wordlist') or ['password1','123456','welcome'])
        idx = 0
        for u in users_list:
            pw = pwlist[idx % len(pwlist)] if pwlist else 'password1'
            idx += 1
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'credential_stuffing_attempt',
                'payload': {'target': target, 'db': db, 'user': u, 'password': pw, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'web_cache_deception':
        paths = payloads[:attempts] if payloads else [
            '/invoice.pdf.css', '/profile.jpg.css', '/api/export.csv.css'
        ][:attempts]
        for pth in paths:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'web_cache_deception_probe',
                'payload': {'target': target, 'db': db, 'path': pth, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'ssrf_probe':
        urls = payloads[:attempts] if payloads else [
            'http://169.254.169.254/latest/meta-data',
            'http://localhost/admin',
            'http://127.0.0.1:8080/actuator'
        ][:attempts]
        for u in urls:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ssrf_probe',
                'payload': {'target': target, 'db': db, 'url': u, 'endpoint': '/fetch', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'jwt_tamper':
        variants = payloads[:attempts] if payloads else [
            'alg:none', 'expired', 'signature_stripped'
        ][:attempts]
        for v in variants:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'jwt_tamper',
                'payload': {'target': target, 'db': db, 'variant': v, 'endpoint': '/api/auth', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'port_scan':
        ports = scan_ports[:attempts] if scan_ports else [22, 80, 443, 8080, 3306, 3389, 5432, 1433, 21, 23, 53, 135, 139, 445, 993, 995][:attempts]
        for idx, port in enumerate(ports):
            # Simulate sophisticated port scanning
            states = ['open', 'closed', 'filtered']
            state = states[idx % len(states)]
            services = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 3306: 'MySQL', 3389: 'RDP'}
            service = services.get(port, 'unknown')
            
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'port_scan_probe',
                'payload': {
                    'target': target, 
                    'db': db, 
                    'port': int(port), 
                    'state': state, 
                    'service': service,
                    'banner': f'{service} {port}/tcp' if state == 'open' else None,
                    'scan_type': 'SYN Stealth',
                    'source_ip': f'10.0.{idx % 255}.{(idx * 7) % 255}',
                    'result': 'detected'
                }
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'sql_injection':
        vectors = payloads[:attempts] if payloads else [
            "' OR '1'='1",
            "' UNION SELECT NULL,password FROM users--",
            '" OR 1=1 --',
            ") OR ('x'='x",
            "admin'--",
            "'; DROP TABLE users; --",
            "' UNION SELECT @@version--",
            "' OR 1=1#",
            "' OR (SELECT COUNT(*) FROM users) > 0--",
            "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--"
        ][:attempts]
        for i, vec in enumerate(vectors):
            # Simulate advanced SQLi techniques
            sqli_types = ['boolean_blind', 'time_blind', 'union_based', 'error_based']
            sqli_type = sqli_types[i % len(sqli_types)]
            response_time = 2.5 if sqli_type == 'time_blind' else 0.1
            
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'sql_injection_probe',
                'payload': {
                    'target': target, 
                    'db': db, 
                    'vector': vec, 
                    'endpoint': '/login', 
                    'sqli_type': sqli_type,
                    'response_time': response_time,
                    'error_message': "SQL syntax error" if sqli_type == 'error_based' else None,
                    'rows_affected': 1 if 'UNION' in vec.upper() else 0,
                    'source_ip': f'172.16.{i % 255}.{(i * 3) % 255}',
                    'result': 'vulnerable'
                }
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'phishing':
        count = max(1, int(attempts))
        for i in range(count):
            recipient = f"user{i+1}@example.com"
            status = 'blocked' if (i % 3 == 0) else 'delivered'
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'phishing_email_sim',
                'payload': {'target': target, 'recipient': recipient, 'template': 'credential_harvest', 'status': status, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'ddos':
        burst = max(1, int(attempts))
        for i in range(burst):
            # Simulate sophisticated DDoS attack
            attack_vectors = ['SYN Flood', 'UDP Flood', 'HTTP GET Flood', 'DNS Amplification', 'NTP Amplification']
            vector = attack_vectors[i % len(attack_vectors)]
            pps = 50000 + i * 10000  # Much higher rates
            gbps = round(pps * 0.0015, 2)  # Convert to Gbps
            
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ddos_traffic_sim',
                'payload': {
                    'target': target, 
                    'rate_pps': pps,
                    'rate_gbps': gbps,
                    'vector': vector,
                    'source_ips': 1000 + i * 500,  # Botnet size
                    'duration_seconds': 300,
                    'protocol': 'TCP' if 'SYN' in vector else 'UDP',
                    'impact': 'service_degraded' if pps < 100000 else 'service_down',
                    'result': 'attack_successful'
                }
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'xss_probe':
        vectors = payloads[:attempts] if payloads else [
            '<script>alert(1)</script>',
            '" onmouseover="alert(1)"',
            '<img src=x onerror=alert(1)>'
        ][:attempts]
        for vec in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'xss_probe',
                'payload': {'target': target, 'db': db, 'vector': vec, 'endpoint': '/search', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'data_exfiltration':
        total_kb = int(cfg.get('data_size_kb', 100))
        chunk_kb = int(cfg.get('chunk_size_kb', 10))
        sent = 0
        while sent < total_kb:
            chunk = min(chunk_kb, total_kb - sent)
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'data_exfil_chunk',
                'payload': {'target': target, 'protocol': 'https', 'size_kb': chunk, 'total_sent_kb': sent + chunk, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            sent += chunk
            await asyncio.sleep(delay)
    elif sim_type == 'ransomware':
        stages = ['initial_access', 'execution', 'encryption_start', 'encryption_progress', 'ransom_note']
        for i, stage in enumerate(stages[:max(1, int(attempts))]):
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ransomware_stage',
                'payload': {'target': target, 'stage': stage, 'files_affected': i * 100, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'lateral_movement':
        hosts = (cfg.get('hosts') or ["10.0.0.5", "10.0.0.7", "10.0.0.9"])[:attempts]
        for i, host in enumerate(hosts):
            method = 'smb' if i % 2 == 0 else 'winrm'
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'lateral_move_attempt',
                'payload': {'from': target, 'to': host, 'method': method, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'malware_beacon':
        for i in range(max(1, int(attempts))):
            jitter_ms = 500 + (i * 100)
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'c2_beacon',
                'payload': {'target': target, 'c2_domain': 'c2.example.net', 'jitter_ms': jitter_ms, 'status': 'alive', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'csrf_probe':
        vectors = payloads[:attempts] if payloads else [
            'missing_csrf_token',
            'stale_token',
            'origin_mismatch'
        ][:attempts]
        for v in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'csrf_probe',
                'payload': {'target': target, 'db': db, 'issue': v, 'endpoint': '/form/submit', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'command_injection':
        vectors = payloads[:attempts] if payloads else [
            '&& whoami',
            '; cat /etc/passwd',
            '`id`'
        ][:attempts]
        for v in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'cmd_injection_probe',
                'payload': {'target': target, 'db': db, 'vector': v, 'endpoint': '/report/export', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'file_upload_probe':
        files = payloads[:attempts] if payloads else [
            'shell.php', 'invoice.pdf', 'image.jsp'
        ][:attempts]
        for fname in files:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'file_upload_probe',
                'payload': {'target': target, 'db': db, 'filename': fname, 'endpoint': '/upload', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'password_spray':
        users = (cfg.get('users') or [user])[:max(1, int(attempts))]
        password = cfg.get('password') or 'Summer2025!'
        for u in users:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'password_spray_attempt',
                'payload': {'target': target, 'db': db, 'user': u, 'password': password, 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'directory_traversal':
        paths = (cfg.get('paths') or ['../../etc/passwd', '..%2f..%2f..%2fwindows/win.ini'])[:max(1, int(attempts))]
        for pth in paths:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'dir_traversal_probe',
                'payload': {'target': target, 'db': db, 'path': pth, 'endpoint': '/download', 'result': 'simulated'}
            }
            await _emit(entry, emit_recommendation=bool(cfg.get('emit_recommendations', True)))
            await asyncio.sleep(delay)
    elif sim_type == 'adaptive_rl':
        steps = int(cfg.get('steps', attempts) or attempts)
        epsilon = float(cfg.get('epsilon', 0.25))
        alpha = float(cfg.get('alpha', 0.25))
        gamma = float(cfg.get('gamma', 0.9))
        emit_recs = bool(cfg.get('emit_recommendations', True))

        actions = cfg.get('actions') or [
            'brute_force',
            'password_spray',
            'port_scan',
            'sql_injection',
            'ddos'
        ]
        agent = _QLearningAttacker(actions=actions, epsilon=epsilon, alpha=alpha, gamma=gamma)

        last_action = 'none'
        last_outcome = 'none'
        consecutive_failures = 0

        def _state():
            return {
                'last_action': last_action,
                'last_outcome': last_outcome,
                'consecutive_failures': min(5, int(consecutive_failures))
            }

        for i in range(max(1, steps)):
            state = _state()
            action = agent.act(state)

            if action == 'sql_injection':
                outcome = 'vulnerable' if (i % 3 != 0) else 'blocked'
                reward = 3.0 if outcome == 'vulnerable' else -2.0
                entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'sim_runner',
                    'event_type': 'sql_injection_probe',
                    'payload': {
                        'target': target,
                        'db': db,
                        'vector': "' OR '1'='1",
                        'endpoint': '/login',
                        'sqli_type': 'boolean_blind',
                        'source_ip': f'172.16.{i % 255}.{(i * 3) % 255}',
                        'result': outcome,
                        'rl_action': action,
                        'rl_step': i
                    }
                }
            elif action == 'ddos':
                outcome = 'attack_successful' if (i % 4 != 0) else 'mitigated'
                reward = 2.0 if outcome == 'attack_successful' else -2.5
                pps = 50000 + i * 5000
                entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'sim_runner',
                    'event_type': 'ddos_traffic_sim',
                    'payload': {
                        'target': target,
                        'rate_pps': pps,
                        'vector': 'HTTP GET Flood',
                        'source_ips': 500 + i * 50,
                        'impact': 'service_degraded' if pps < 100000 else 'service_down',
                        'result': outcome,
                        'rl_action': action,
                        'rl_step': i
                    }
                }
            elif action == 'port_scan':
                outcome = 'detected' if (i % 5 == 0) else 'simulated'
                reward = 1.0 if outcome != 'detected' else -1.5
                port = int((scan_ports[i % len(scan_ports)] if scan_ports else [22, 80, 443, 8069, 8000][i % 5]))
                entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'sim_runner',
                    'event_type': 'port_scan_probe',
                    'payload': {
                        'target': target,
                        'db': db,
                        'port': port,
                        'state': 'filtered' if outcome != 'detected' else 'open',
                        'scan_type': 'SYN Stealth',
                        'source_ip': f'10.0.{i % 255}.{(i * 7) % 255}',
                        'result': outcome,
                        'rl_action': action,
                        'rl_step': i
                    }
                }
            elif action == 'password_spray':
                outcome = 'failed'
                detected = (i % 10 == 0)
                reward = 0.8 if not detected else -1.0
                entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'sim_runner',
                    'event_type': 'password_spray_attempt',
                    'payload': {
                        'target': target,
                        'db': db,
                        'user': user,
                        'password': 'Summer2025!',
                        'result': outcome,
                        'detected': detected,
                        'rl_action': action,
                        'rl_step': i
                    }
                }
            else:
                outcome = 'failed' if (i % 7 != 0) else 'success'
                reward = 1.5 if outcome == 'success' else -1.5
                entry = {
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'sim_runner',
                    'event_type': 'brute_force_attempt',
                    'payload': {
                        'target': target,
                        'db': db,
                        'user': user,
                        'password': '***',
                        'result': outcome,
                        'technique': 'adaptive_rl',
                        'source_ip': f'192.168.1.{100 + i % 155}',
                        'rl_action': action,
                        'rl_step': i
                    }
                }

            await _emit(entry, emit_recommendation=emit_recs)

            next_outcome = 'success' if (outcome in ('success', 'vulnerable', 'attack_successful')) else 'fail'
            next_state = {
                'last_action': action,
                'last_outcome': next_outcome,
                'consecutive_failures': min(5, int(consecutive_failures + (1 if next_outcome == 'fail' else 0)))
            }
            agent.update(state, action, reward, next_state)

            last_action = action
            last_outcome = next_outcome
            consecutive_failures = next_state['consecutive_failures']
            await asyncio.sleep(delay)

    else:
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'source': 'sim_runner',
            'event_type': 'sim_error',
            'payload': {'message': f'Unknown sim_type: {sim_type}', 'result': 'simulated'}
        }
        await _emit(entry, emit_recommendation=False)
def run_simulation(cfg: dict):
    """Run the attack-sim brute_force in simulated/sandbox mode and ingest logs into MongoDB.
    This function is intended to be run as a background task by FastAPI and MUST NOT target production.
    """
    mongo = LogIngest()
    target = cfg.get('target')
    db = cfg.get('db')
    user = cfg.get('user')
    wordlist = cfg.get('wordlist') or []
    delay = cfg.get('delay', 1.0)
    sim_type = cfg.get('sim_type', 'brute_force')
    attempts = cfg.get('attempts', 5)
    scan_ports = cfg.get('scan_ports') or []
    payloads = cfg.get('payloads') or []
    results = []

    def insert_sync(entry):
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(mongo.insert(entry))
        except Exception as e:
            print('Log ingest failed:', e)

    if sim_type == 'brute_force':
        for pw in wordlist:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'brute_force_attempt',
                'payload': {'target': target, 'db': db, 'user': user, 'password': pw, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'port_scan':
        ports = scan_ports[:attempts] if scan_ports else [22, 80, 443, 8080, 3306][:attempts]
        for idx, port in enumerate(ports):
            state = 'open' if (idx % 2 == 0) else 'closed'
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'port_scan_probe',
                'payload': {'target': target, 'db': db, 'port': int(port), 'state': state, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'sql_injection':
        vectors = payloads[:attempts] if payloads else [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            '" OR 1=1 --',
            ") OR ('x'='x",
            "admin'--"
        ][:attempts]
        for vec in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'sql_injection_probe',
                'payload': {'target': target, 'db': db, 'vector': vec, 'endpoint': '/login', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'phishing':
        count = max(1, int(attempts))
        for i in range(count):
            recipient = f"user{i+1}@example.com"
            status = 'blocked' if (i % 3 == 0) else 'delivered'
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'phishing_email_sim',
                'payload': {'target': target, 'recipient': recipient, 'template': 'credential_harvest', 'status': status, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'ddos':
        burst = max(1, int(attempts))
        for i in range(burst):
            pps = 1000 + i * 250
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ddos_traffic_sim',
                'payload': {'target': target, 'rate_pps': pps, 'vector': 'syn_flood', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'xss_probe':
        vectors = payloads[:attempts] if payloads else [
            '<script>alert(1)</script>',
            '" onmouseover="alert(1)"',
            '<img src=x onerror=alert(1)>'
        ][:attempts]
        for vec in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'xss_probe',
                'payload': {'target': target, 'db': db, 'vector': vec, 'endpoint': '/search', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'data_exfiltration':
        total_kb = int(cfg.get('data_size_kb', 100))
        chunk_kb = int(cfg.get('chunk_size_kb', 10))
        sent = 0
        while sent < total_kb:
            chunk = min(chunk_kb, total_kb - sent)
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'data_exfil_chunk',
                'payload': {'target': target, 'protocol': 'https', 'size_kb': chunk, 'total_sent_kb': sent + chunk, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            sent += chunk
            time.sleep(delay)
    elif sim_type == 'ransomware':
        stages = ['initial_access', 'execution', 'encryption_start', 'encryption_progress', 'ransom_note']
        for i, stage in enumerate(stages[:max(1, int(attempts))]):
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ransomware_stage',
                'payload': {'target': target, 'stage': stage, 'files_affected': i * 100, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'lateral_movement':
        hosts = (cfg.get('hosts') or ["10.0.0.5", "10.0.0.7", "10.0.0.9"])[:attempts]
        for i, host in enumerate(hosts):
            method = 'smb' if i % 2 == 0 else 'winrm'
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'lateral_move_attempt',
                'payload': {'from': target, 'to': host, 'method': method, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'malware_beacon':
        for i in range(max(1, int(attempts))):
            jitter_ms = 500 + (i * 100)
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'c2_beacon',
                'payload': {'target': target, 'c2_domain': 'c2.example.net', 'jitter_ms': jitter_ms, 'status': 'alive', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'csrf_probe':
        vectors = payloads[:attempts] if payloads else ['missing_csrf_token','stale_token','origin_mismatch'][:attempts]
        for v in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'csrf_probe',
                'payload': {'target': target, 'db': db, 'issue': v, 'endpoint': '/form/submit', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'command_injection':
        vectors = payloads[:attempts] if payloads else ['&& whoami','; cat /etc/passwd','`id`'][:attempts]
        for v in vectors:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'cmd_injection_probe',
                'payload': {'target': target, 'db': db, 'vector': v, 'endpoint': '/report/export', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'file_upload_probe':
        files = payloads[:attempts] if payloads else ['shell.php','invoice.pdf','image.jsp'][:attempts]
        for fname in files:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'file_upload_probe',
                'payload': {'target': target, 'db': db, 'filename': fname, 'endpoint': '/upload', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'ssrf_probe':
        urls = payloads[:attempts] if payloads else ['http://169.254.169.254/latest/meta-data','http://localhost/admin','http://127.0.0.1:8080/actuator'][:attempts]
        for u in urls:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'ssrf_probe',
                'payload': {'target': target, 'db': db, 'url': u, 'endpoint': '/fetch', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'jwt_tamper':
        variants = payloads[:attempts] if payloads else ['alg:none','expired','signature_stripped'][:attempts]
        for v in variants:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'jwt_tamper',
                'payload': {'target': target, 'db': db, 'variant': v, 'endpoint': '/api/auth', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'credential_stuffing':
        users_list = (cfg.get('users') or [user, f"{user}2", f"{user}3"])[:max(1, int(attempts))]
        pwlist = (cfg.get('payloads') or cfg.get('wordlist') or ['password1','123456','welcome'])
        idx = 0
        for u in users_list:
            pw = pwlist[idx % len(pwlist)] if pwlist else 'password1'
            idx += 1
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'credential_stuffing_attempt',
                'payload': {'target': target, 'db': db, 'user': u, 'password': pw, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'web_cache_deception':
        paths = payloads[:attempts] if payloads else ['/invoice.pdf.css','/profile.jpg.css','/api/export.csv.css'][:attempts]
        for pth in paths:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'web_cache_deception_probe',
                'payload': {'target': target, 'db': db, 'path': pth, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'password_spray':
        users_list = (cfg.get('users') or [user])[:max(1, int(attempts))]
        password = cfg.get('password') or 'Summer2025!'
        for u in users_list:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'password_spray_attempt',
                'payload': {'target': target, 'db': db, 'user': u, 'password': password, 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    elif sim_type == 'directory_traversal':
        paths = (cfg.get('paths') or ['../../etc/passwd', '..%2f..%2f..%2fwindows/win.ini'])[:max(1, int(attempts))]
        for pth in paths:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'dir_traversal_probe',
                'payload': {'target': target, 'db': db, 'path': pth, 'endpoint': '/download', 'result': 'simulated'}
            }
            insert_sync(entry)
            results.append(entry)
            time.sleep(delay)
    else:
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'source': 'sim_runner',
            'event_type': 'sim_error',
            'payload': {'message': f'Unknown sim_type: {sim_type}', 'result': 'simulated'}
        }
        insert_sync(entry)
        results.append(entry)

    return {'attempts': len(results)}
