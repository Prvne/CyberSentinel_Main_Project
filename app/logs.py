from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import os
from datetime import datetime, timezone

class LogEntry(BaseModel):
    timestamp: str
    source: str
    event_type: str
    payload: dict

class LogIngest:
    def __init__(self, mongo_uri: str = None, db_name: str = 'cybersentinel'):
        uri = mongo_uri or os.getenv('MONGO_URI', 'mongodb://localhost:27017')
        self.client = AsyncIOMotorClient(uri)
        self.db = self.client[db_name]
    async def ensure_indexes(self):
        # Index timestamp (string ISO) descending for recency queries
        await self.db.logs.create_index([('timestamp', -1)])
        # TTL index on datetime field 'ts' (expire after 3 days)
        try:
            await self.db.logs.create_index('ts', expireAfterSeconds=3*24*60*60)
        except Exception:
            # Ignore if index already exists with different options
            pass
    async def insert(self, doc: dict):
        # Add a proper datetime field for TTL and queries
        ts = doc.get('timestamp')
        dt = None
        if isinstance(ts, str):
            try:
                ts_norm = ts.replace('Z', '+00:00') if ts.endswith('Z') else ts
                dt = datetime.fromisoformat(ts_norm)
            except Exception:
                dt = None
        doc['ts'] = dt or datetime.now(timezone.utc)
        await self.db.logs.insert_one(doc)
    async def get_latest(self, limit: int = 20):
        cursor = self.db.logs.find().sort([('_id', -1)]).limit(limit)
        docs = []
        async for d in cursor:
            d['_id'] = str(d['_id'])
            docs.append(d)
        return docs
