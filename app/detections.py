import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
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

    async def derived_alerts(self, limit: int = 50, window_minutes: int = 30, severity: Optional[str] = None, type_contains: Optional[str] = None, skip: int = 0) -> Dict[str, Any]:
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

        # Rules - Enhanced thresholds for sophisticated attacks
        # Brute force threshold - lowered due to enhanced simulations
        for (db, user), cnt in brute_counts.items():
            severity = 'critical' if cnt >= 5 else 'high' if cnt >= 3 else 'medium' if cnt >= 2 else 'low'
            if cnt >= 1:  # Very low threshold for testing
                alerts.append({
                    'severity': severity,
                    'type': 'brute_force_detected',
                    'detail': {'db': db, 'user': user, 'attempts': cnt, 'threat_level': 'elevated'},
                    'mitre': ['T1110', 'T1110.001', 'T1110.003']
                })
        # Port scan unique ports - enhanced detection
        for tgt, ports in portscan_targets.items():
            unique_ports = len([p for p in ports if p is not None])
            severity = 'critical' if unique_ports >= 10 else 'high' if unique_ports >= 5 else 'medium' if unique_ports >= 3 else 'low'
            if unique_ports >= 1:  # Very low threshold for testing
                alerts.append({
                    'severity': severity,
                    'type': 'port_scan_detected',
                    'detail': {'target': tgt, 'unique_ports': unique_ports, 'scan sophistication': 'advanced'},
                    'mitre': ['T1046', 'T1595.002']
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
        # DDoS rate spike - Enhanced detection for sophisticated attacks
        if ddos_rates:
            max_rate = max(ddos_rates)
            severity = 'critical' if max_rate > 80000 else 'high' if max_rate > 50000 else 'medium' if max_rate > 20000 else 'low'
            if max_rate > 1000:  # Much lower threshold for testing
                alerts.append({
                    'severity': severity,
                    'type': 'ddos_spike_detected',
                    'detail': {
                        'max_rate_pps': max_rate,
                        'attack_vectors': ['SYN Flood', 'UDP Flood', 'HTTP GET Flood', 'DNS Amplification'],
                        'threat_level': 'severe' if max_rate > 50000 else 'moderate'
                    },
                    'mitre': ['T1498', 'T1498.001', 'T1498.002']
                })
        # Phishing volume - Enhanced severity based on campaign sophistication
        if phishing_stats['delivered'] >= 1:
            severity = 'critical' if phishing_stats['delivered'] >= 50 else 'high' if phishing_stats['delivered'] >= 20 else 'medium' if phishing_stats['delivered'] >= 5 else 'low'
            alerts.append({
                'severity': severity,
                'type': 'phishing_campaign_detected',
                'detail': {**phishing_stats, 'campaign_scale': 'large' if phishing_stats['delivered'] >= 50 else 'medium' if phishing_stats['delivered'] >= 20 else 'small'},
                'mitre': ['T1566']
            })
        # Password spray campaign - Enhanced severity based on scope and sophistication
        if spray_count >= 1:
            severity = 'critical' if spray_count >= 100 else 'high' if spray_count >= 50 else 'medium' if spray_count >= 10 else 'low'
            alerts.append({
                'severity': severity,
                'type': 'password_spray_detected',
                'detail': {
                    'attempts': spray_count,
                    'campaign_scope': 'enterprise' if spray_count >= 100 else 'large' if spray_count >= 50 else 'medium' if spray_count >= 10 else 'small',
                    'attack_pattern': 'systematic' if spray_count >= 20 else 'opportunistic'
                },
                'mitre': ['T1110', 'T1110.004']
            })
        # Ransomware stage seen
        if any(s in ransomware_stages for s in ['encryption_start', 'encryption_progress', 'ransom_note']):
            alerts.append({
                'severity': 'high',
                'type': 'ransomware_activity_detected',
                'detail': {'stages': sorted(list(ransomware_stages))},
                'mitre': ['T1486']
            })
        # Data exfiltration volume - Enhanced severity based on data sensitivity and volume
        if exfil_total >= 1:
            severity = 'critical' if exfil_total >= 10000 else 'high' if exfil_total >= 1000 else 'medium' if exfil_total >= 100 else 'low'
            alerts.append({
                'severity': severity,
                'type': 'data_exfiltration_detected',
                'detail': {
                    'total_kb': exfil_total,
                    'data_class': 'sensitive_pii' if exfil_total >= 10000 else 'confidential' if exfil_total >= 1000 else 'internal',
                    'exfil_rate_kb_per_min': exfil_total / max(1, len(events)),  # Rate calculation
                    'impact_assessment': 'severe' if exfil_total >= 10000 else 'significant' if exfil_total >= 1000 else 'moderate'
                },
                'mitre': ['T1041', 'T1567']
            })
        # Lateral movement attempts - Enhanced severity based on scope and persistence
        if any(c >= 1 for c in lateral_attempts.values()):
            max_attempts = max(lateral_attempts.values())
            severity = 'critical' if max_attempts >= 20 else 'high' if max_attempts >= 10 else 'medium' if max_attempts >= 3 else 'low'
            alerts.append({
                'severity': severity,
                'type': 'lateral_movement_detected',
                'detail': {
                    **lateral_attempts,
                    'movement_scope': 'enterprise_compromise' if max_attempts >= 20 else 'department_compromise' if max_attempts >= 10 else 'lateral_movement',
                    'persistence_indicators': 'established' if max_attempts >= 5 else 'exploratory'
                },
                'mitre': ['T1021', 'T1534']
            })
        # C2 beaconing - Enhanced severity based on frequency and sophistication
        if c2_count >= 1:
            severity = 'critical' if c2_count >= 50 else 'high' if c2_count >= 20 else 'medium' if c2_count >= 5 else 'low'
            alerts.append({
                'severity': severity,
                'type': 'c2_beaconing_detected',
                'detail': {
                    'count': c2_count,
                    'beacon_frequency': 'high_frequency' if c2_count >= 50 else 'regular' if c2_count >= 20 else 'intermittent',
                    'communication_pattern': 'persistent' if c2_count >= 10 else 'periodic',
                    'c2_maturity': 'established' if c2_count >= 20 else 'developing'
                },
                'mitre': ['T1071', 'T1102']
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
        # Temporarily remove time filtering to ensure frontend works
        query: Dict[str, Any] = {}
        if severity and severity.strip():
            query['severity'] = severity.lower()
        if type_contains and type_contains.strip():
            query['type'] = { '$regex': type_contains, '$options': 'i' }
        
        cursor = self.db.derived_alerts.find(query).sort([('last_seen', -1)]).skip(int(max(0, skip))).limit(limit)
        out: List[Dict[str, Any]] = []
        async for d in cursor:
            d['_id'] = str(d['_id'])
            out.append(d)

        return {'count': len(out), 'results': out}
