from __future__ import annotations
import random
from typing import Dict, Any
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorClient
import os

from detections import DetectionService
from logs import LogIngest

class AnomalyRLAgent:
    """
    Minimal epsilon-greedy bandit that tunes an anomaly score threshold used by AnomalyService.
    - Actions are discrete thresholds from a small candidate set.
    - Reward proxy: number of derived alerts in the same time window (higher is better),
      minus a small penalty proportional to fraction of anomalies above threshold (to limit noise).
    This is a placeholder RL scaffold; can be swapped with Stable-Baselines3 later.
    """
    def __init__(self, mongo_uri: str | None = None, db_name: str = 'cybersentinel'):
        uri = mongo_uri or os.getenv('MONGO_URI', 'mongodb://localhost:27017')
        self.client = AsyncIOMotorClient(uri)
        self.db = self.client[db_name]
        # Discrete action space of thresholds
        self.thresholds = [0.2, 0.5, 0.8, 1.0, 1.5, 2.0]
        self.epsilon = 0.2

    async def _get_state(self) -> Dict[str, Any]:
        doc = await self.db.settings.find_one({'_key': 'anomaly_rl'})
        if not doc:
            doc = {
                '_key': 'anomaly_rl',
                'q_values': {str(t): 0.0 for t in self.thresholds},
                'counts': {str(t): 0 for t in self.thresholds},
                'current_threshold': 1.0,
                'updated_at': datetime.now(timezone.utc)
            }
            await self.db.settings.update_one({'_key': 'anomaly_rl'}, {'$set': doc}, upsert=True)
        return doc

    async def status(self) -> Dict[str, Any]:
        st = await self._get_state()
        return {
            'thresholds': self.thresholds,
            'current_threshold': st.get('current_threshold', 1.0),
            'q_values': st.get('q_values', {}),
            'counts': st.get('counts', {}),
        }

    async def choose_action(self) -> float:
        st = await self._get_state()
        if random.random() < self.epsilon:
            return random.choice(self.thresholds)
        q_values = st.get('q_values', {})
        # argmax over thresholds
        best = max(self.thresholds, key=lambda t: float(q_values.get(str(t), 0.0)))
        return best

    async def train_step(self, window_minutes: int = 30) -> Dict[str, Any]:
        # Choose threshold (action)
        action = await self.choose_action()

        # Compute reward proxy
        detect = DetectionService()
        derived = await detect.derived_alerts(limit=50, window_minutes=window_minutes)
        alerts_count = int(derived.get('count', 0))

        # Estimate anomaly density above threshold
        ingest = LogIngest()
        # reuse anomaly scoring features by counting docs in the window
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        total_recent = await ingest.db.logs.count_documents({'ts': {'$gte': cutoff}})
        # use heuristic: higher threshold -> fewer anomalies; approximate fraction
        approx_frac_above = max(0.0, min(1.0, 1.5 / (action + 1e-6)))  # decreasing with action

        reward = alerts_count - 0.5 * approx_frac_above * max(1, total_recent / 100.0)

        # Update Q values (incremental average)
        st = await self._get_state()
        q = st['q_values']; c = st['counts']
        key = str(action)
        old_q = float(q.get(key, 0.0))
        n = int(c.get(key, 0)) + 1
        new_q = old_q + (reward - old_q) / n
        q[key] = new_q
        c[key] = n

        # Greedy set current threshold to best
        best = max(self.thresholds, key=lambda t: float(q.get(str(t), 0.0)))
        await self.db.settings.update_one({'_key': 'anomaly_rl'}, {'$set': {
            'q_values': q,
            'counts': c,
            'current_threshold': best,
            'updated_at': datetime.now(timezone.utc)
        }}, upsert=True)

        return {
            'action_threshold': action,
            'reward': reward,
            'alerts_in_window': alerts_count,
            'approx_frac_above': approx_frac_above,
            'new_current_threshold': best
        }

    async def get_threshold(self) -> float:
        st = await self._get_state()
        return float(st.get('current_threshold', 1.0))
