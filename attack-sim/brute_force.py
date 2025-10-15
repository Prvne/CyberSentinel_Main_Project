"""Safe brute-force template for sandbox Odoo login.
REQUIREMENTS / SAFETY:
- Must run only against sandbox (confirm --sandbox flag)
- Respect rate limits and do not target production systems
Usage example:
    python brute_force.py --target http://localhost:8069 --db demo --user test --wordlist small.txt --sandbox
"""
import argparse
import time
import requests
import json

def attempt_login(target, db, user, password):
    # This is a minimal demonstration: Odoo login via XML-RPC / JSON-RPC would be used in production.
    # For safety, we only simulate attempts and print them.
    print(f"SIMULATED attempt user={user} pass={password} against db={db} @ {target}")
    return {'success': False, 'status': 'simulated'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--db', required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--wordlist', required=True)
    parser.add_argument('--sandbox', action='store_true', help='Must be set to run')
    parser.add_argument('--delay', type=float, default=1.0, help='seconds between attempts')
    args = parser.parse_args()

    if not args.sandbox:
        print('ERROR: sandbox flag not set. Exiting.')
        return

    with open(args.wordlist) as fh:
        for line in fh:
            pw = line.strip()
            res = attempt_login(args.target, args.db, args.user, pw)
            # optionally POST to backend logs endpoint if available
            try:
                requests.post('http://localhost:8000/logs', json={
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                    'source': 'attack-sim/brute_force',
                    'event_type': 'brute_force_attempt',
                    'payload': {'target': args.target, 'db': args.db, 'user': args.user, 'password': pw, 'result': res}
                }, timeout=2)
            except Exception:
                pass
            time.sleep(args.delay)

if __name__ == '__main__':
    main()
