import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient
import os

class DetectionService:
    def __init__(self, mongo_uri: str = None, db_name: str = 'cybersentinel'):
        uri = mongo_uri or os.getenv('MONGO_URI', 'mongodb://localhost:27017')
        self.client = AsyncIOMotorClient(uri)
        self.db = self.client[db_name]

    async def latest_logs(self, limit: int = 200, window_minutes: int = 30) -> List[Dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        cursor = self.db.logs.find({'ts': {'$gte': cutoff}}).sort([('_id', -1)]).limit(limit)
        docs = []
        async for d in cursor:
            d['_id'] = str(d['_id'])
            docs.append(d)
        return docs

    async def derived_alerts(self, limit: int = 50, window_minutes: int = 30, severity: str | None = None, type_contains: str | None = None, skip: int = 0) -> Dict[str, Any]:
        docs = await self.latest_logs(limit=500, window_minutes=window_minutes)
        alerts: List[Dict[str, Any]] = []

        # Counters
        brute_counts = {}
        portscan_targets = {}
        sqli_vectors = []
        xss_vectors = []
        ddos_rates = []
        phishing_stats = {'delivered': 0, 'blocked': 0}
        ransomware_stages = set()
        exfil_total = 0
        lateral_attempts = {}
        c2_count = 0
        spray_count = 0
        csrf_issues = []
        cmd_vectors = []
        upload_files = []
        traversal_paths = []
        ssrf_urls = []
        jwt_issues = []

        for d in docs:
            et = d.get('event_type')
            p = d.get('payload', {}) or {}
            if et == 'brute_force_attempt':
                key = (p.get('db'), p.get('user'))
                brute_counts[key] = brute_counts.get(key, 0) + 1
            elif et == 'port_scan_probe':
                tgt = p.get('target')
                prt = p.get('port')
                if tgt:
                    portscan_targets.setdefault(tgt, set()).add(prt)
            elif et == 'sql_injection_probe':
                sqli_vectors.append(str(p.get('vector', '')))
            elif et == 'xss_probe':
                xss_vectors.append(str(p.get('vector', '')))
            elif et == 'ddos_traffic_sim':
                try:
                    ddos_rates.append(float(p.get('rate_pps', 0)))
                except Exception:
                    pass
            elif et == 'phishing_email_sim':
                status = p.get('status')
                if status in phishing_stats:
                    phishing_stats[status] += 1
            elif et == 'password_spray_attempt':
                spray_count += 1
            elif et == 'ransomware_stage':
                stage = p.get('stage')
                if stage:
                    ransomware_stages.add(stage)
            elif et == 'data_exfil_chunk':
                try:
                    exfil_total += int(p.get('size_kb', 0))
                except Exception:
                    pass
            elif et == 'lateral_move_attempt':
                dst = p.get('to')
                lateral_attempts[dst] = lateral_attempts.get(dst, 0) + 1
            elif et == 'c2_beacon':
                c2_count += 1
            elif et == 'csrf_probe':
                csrf_issues.append(p.get('issue'))
            elif et == 'cmd_injection_probe':
                cmd_vectors.append(str(p.get('vector','')))
            elif et == 'file_upload_probe':
                upload_files.append(str(p.get('filename','')))
            elif et == 'dir_traversal_probe':
                traversal_paths.append(str(p.get('path','')))
            elif et == 'ssrf_probe':
                ssrf_urls.append(str(p.get('url','')))
            elif et == 'jwt_tamper':
                jwt_issues.append(str(p.get('variant','')))
            elif et == 'credential_stuffing_attempt':
                # Track similarly to brute force but across users
                key = (p.get('db'), p.get('user'))
                brute_counts[key] = brute_counts.get(key, 0) + 1
            elif et == 'web_cache_deception_probe':
                traversal_paths.append(str(p.get('path','')))

        # Rules
        # Brute force threshold
        for (db, user), cnt in brute_counts.items():
            if cnt >= 5:
                alerts.append({
                    'severity': 'medium',
                    'type': 'brute_force_detected',
                    'detail': {'db': db, 'user': user, 'attempts': cnt},
                    'mitre': ['T1110']
                })
        # Port scan unique ports
        for tgt, ports in portscan_targets.items():
            if len([p for p in ports if p is not None]) >= 4:
                alerts.append({
                    'severity': 'low',
                    'type': 'port_scan_detected',
                    'detail': {'target': tgt, 'unique_ports': len(ports)},
                    'mitre': ['T1046']
                })
        # SQLi signature presence
        for v in sqli_vectors:
            sigs = ["' OR ", 'UNION SELECT', '1=1', '" OR '] 
            if any(s in v.upper() for s in [s.upper() for s in sigs]):
                alerts.append({
                    'severity': 'medium',
                    'type': 'sql_injection_detected',
                    'detail': {'vector': v, 'cwe': ['CWE-89'], 'cve_candidates': ['CVE-2019-14322']},
                    'mitre': ['T1190']
                })
                break
        # XSS signatures
        for v in xss_vectors:
            if any(tok in v.lower() for tok in ['<script', 'onerror=', 'onmouseover=']):
                alerts.append({
                    'severity': 'medium',
                    'type': 'xss_detected',
                    'detail': {'vector': v, 'cwe': ['CWE-79'], 'cve_candidates': ['CVE-2020-11022']},
                    'mitre': ['T1059']
                })
                break
        # DDoS rate spike
        if any(r > 2000 for r in ddos_rates):
            alerts.append({
                'severity': 'high',
                'type': 'ddos_spike_detected',
                'detail': {'max_rate_pps': max(ddos_rates) if ddos_rates else 0},
                'mitre': ['T1498']
            })
        # Phishing volume
        if phishing_stats['delivered'] >= 3:
            alerts.append({
                'severity': 'low',
                'type': 'phishing_campaign_detected',
                'detail': phishing_stats,
                'mitre': ['T1566']
            })
        # Password spray campaign
        if spray_count >= 3:
            alerts.append({
                'severity': 'medium',
                'type': 'password_spray_detected',
                'detail': {'attempts': spray_count},
                'mitre': ['T1110']
            })
        # Ransomware stage seen
        if any(s in ransomware_stages for s in ['encryption_start', 'encryption_progress', 'ransom_note']):
            alerts.append({
                'severity': 'high',
                'type': 'ransomware_activity_detected',
                'detail': {'stages': sorted(list(ransomware_stages))},
                'mitre': ['T1486']
            })
        # Data exfiltration volume
        if exfil_total >= 100:
            alerts.append({
                'severity': 'high',
                'type': 'data_exfiltration_detected',
                'detail': {'total_kb': exfil_total},
                'mitre': ['T1041']
            })
        # Lateral movement attempts
        if any(c >= 2 for c in lateral_attempts.values()):
            alerts.append({
                'severity': 'medium',
                'type': 'lateral_movement_detected',
                'detail': lateral_attempts,
                'mitre': ['T1021']
            })
        # C2 beaconing
        if c2_count >= 2:
            alerts.append({
                'severity': 'medium',
                'type': 'c2_beaconing_detected',
                'detail': {'count': c2_count},
                'mitre': ['T1071']
            })
        # CSRF issues
        if csrf_issues:
            sev = 'low' if 'stale_token' in csrf_issues else 'medium'
            alerts.append({
                'severity': sev,
                'type': 'csrf_weakness_detected',
                'detail': {'issues': csrf_issues, 'cwe': ['CWE-352']},
                'mitre': ['T1190']
            })
        # Command injection vectors
        for v in cmd_vectors:
            if any(sym in v for sym in ['&&',';','`']):
                alerts.append({
                    'severity': 'high',
                    'type': 'command_injection_detected',
                    'detail': {'vector': v, 'cwe': ['CWE-77'], 'cve_candidates': ['CVE-2021-41773']},
                    'mitre': ['T1059']
                })
                break
        # Suspicious file uploads (possible webshell)
        if any(name.lower().endswith(('.php','.jsp','.asp')) for name in upload_files):
            alerts.append({
                'severity': 'medium',
                'type': 'malicious_file_upload_detected',
                'detail': {'filenames': upload_files, 'cwe': ['CWE-434'], 'cve_candidates': ['CVE-2019-6340']},
                'mitre': ['T1505']
            })
        # Directory traversal
        if traversal_paths:
            if any(tok in p for p in traversal_paths for tok in ['..','%2f']):
                alerts.append({
                    'severity': 'medium',
                    'type': 'path_traversal_detected',
                    'detail': {'paths': traversal_paths, 'cwe': ['CWE-22']},
                    'mitre': ['T1105']
                })
        # Cache deception (look for .css appended to sensitive)
        if any(p.endswith('.css') for p in traversal_paths):
            alerts.append({
                'severity': 'low',
                'type': 'web_cache_deception_detected',
                'detail': {'paths': traversal_paths, 'cwe': ['CWE-525']},
                'mitre': ['T1190']
            })
        # SSRF indicators (access to metadata/localhost)
        if any('169.254.169.254' in u or 'localhost' in u or '127.0.0.1' in u for u in ssrf_urls):
            alerts.append({
                'severity': 'high',
                'type': 'ssrf_detected',
                'detail': {'urls': ssrf_urls, 'cwe': ['CWE-918']},
                'mitre': ['T1190']
            })
        # JWT tamper
        if jwt_issues:
            sev = 'high' if any(v in ['alg:none','signature_stripped'] for v in jwt_issues) else 'medium'
            alerts.append({
                'severity': sev,
                'type': 'jwt_tamper_detected',
                'detail': {'variants': jwt_issues, 'cwe': ['CWE-345']},
                'mitre': ['T1606']
            })
        # Correlation: spray/stuffing + lateral movement -> kill chain progression
        has_lateral = any(c >= 1 for c in lateral_attempts.values())
        total_spray = spray_count
        if has_lateral and total_spray >= 3:
            alerts.append({
                'severity': 'high',
                'type': 'kill_chain_progression',
                'detail': {'stages': ['password_spray', 'lateral_movement'], 'spray_attempts': total_spray},
                'mitre': ['T1110','T1021']
            })

        # Persist alerts with dedup/suppression (5 minutes)
        now = datetime.now(timezone.utc)
        suppress_delta = timedelta(minutes=5)
        for a in alerts:
            key = {
                'type': a.get('type'),
                'detail': a.get('detail')
            }
            existing = await self.db.derived_alerts.find_one(key)
            if existing:
                last_seen = existing.get('last_seen')
                update = {
                    '$set': {
                        'severity': a.get('severity'),
                        'mitre': a.get('mitre'),
                        'last_seen': now
                    },
                    '$inc': {'occurrences': 1}
                }
                await self.db.derived_alerts.update_one({'_id': existing['_id']}, update)
            else:
                doc = {
                    **key,
                    'severity': a.get('severity'),
                    'mitre': a.get('mitre'),
                    'first_seen': now,
                    'last_seen': now,
                    'occurrences': 1
                }
                await self.db.derived_alerts.insert_one(doc)

        # Read back persisted alerts in window and after suppression
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        query: Dict[str, Any] = {'last_seen': {'$gte': cutoff}}
        if severity:
            query['severity'] = severity.lower()
        if type_contains:
            query['type'] = { '$regex': type_contains, '$options': 'i' }
        cursor = self.db.derived_alerts.find(query).sort([('last_seen', -1)]).skip(int(max(0, skip))).limit(limit)
        out: List[Dict[str, Any]] = []
        async for d in cursor:
            d['_id'] = str(d['_id'])
            out.append(d)

        return {'count': len(out), 'results': out}
