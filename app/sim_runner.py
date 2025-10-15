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
    # For Phase1 we simulate attempts locally instead of executing external commands.
    results = []
    for pw in wordlist:
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'source': 'sim_runner',
            'event_type': 'brute_force_attempt',
            'payload': {'target': target, 'db': db, 'user': user, 'password': pw, 'result': 'simulated'}
        }
        # insert into mongo
        try:
            # run synchronously in background loop
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(mongo.insert(entry))
        except Exception as e:
            print('Log ingest failed:', e)
        results.append(entry)
        time.sleep(delay)
    return {'attempts': len(results)}
