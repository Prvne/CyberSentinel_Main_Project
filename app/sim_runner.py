import subprocess, os, json, time
from logs import LogIngest
import asyncio

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

    if sim_type == 'brute_force':
        for pw in wordlist:
            entry = {
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'sim_runner',
                'event_type': 'brute_force_attempt',
                'payload': {'target': target, 'db': db, 'user': user, 'password': pw, 'result': 'simulated'}
            }
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
            await asyncio.sleep(delay)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
            await asyncio.sleep(delay)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
            await asyncio.sleep(delay)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
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
            try:
                await mongo.insert(entry)
            except Exception as e:
                print('Log ingest failed:', e)
            await asyncio.sleep(delay)
    else:
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'source': 'sim_runner',
            'event_type': 'sim_error',
            'payload': {'message': f'Unknown sim_type: {sim_type}', 'result': 'simulated'}
        }
        try:
            await mongo.insert(entry)
        except Exception as e:
            print('Log ingest failed:', e)
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
