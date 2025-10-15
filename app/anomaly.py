from __future__ import annotations
import asyncio
from typing import List, Dict, Any
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from logs import LogIngest


class AnomalyService:
    """
    Simple anomaly detector using IsolationForest over aggregated features
    derived from recent `logs` documents.
    """

    def __init__(self, lookback_minutes: int = 60, max_docs: int = 2000):
        self.lookback_minutes = lookback_minutes
        self.max_docs = max_docs

    async def _load_recent_logs(self, ingest: LogIngest) -> List[Dict[str, Any]]:
        """
        Pull most-recent documents (by _id) and filter to last N minutes by timestamp when possible.
        Note: timestamps are stored as ISO strings; if parsing fails we still include docs.
        """
        cursor = ingest.db.logs.find().sort([("_id", -1)]).limit(self.max_docs)
        docs: List[Dict[str, Any]] = []
        async for d in cursor:
            d["_id"] = str(d["_id"])  # stringify for JSON
            docs.append(d)
        if not docs:
            return []

        # Filter by timestamp window if parseable
        cutoff = datetime.utcnow() - timedelta(minutes=self.lookback_minutes)
        filtered: List[Dict[str, Any]] = []
        for d in docs:
            ts = d.get("timestamp")
            if ts:
                try:
                    # Incoming timestamps appear like 2025-10-13T15:31:06Z or ISO with offset
                    # Normalize trailing Z
                    ts_norm = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
                    dt = datetime.fromisoformat(ts_norm)
                    if dt >= cutoff:
                        filtered.append(d)
                except Exception:
                    # keep if unparsable; rely on recency by _id sort
                    filtered.append(d)
            else:
                filtered.append(d)
        return filtered

    @staticmethod
    def _pw_entropy(s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        counts = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * log2(c / n) for c in counts.values())

    def _build_features(self, docs: List[Dict[str, Any]]) -> pd.DataFrame:
        if not docs:
            return pd.DataFrame()
        rows = []
        for d in docs:
            payload = d.get("payload") or {}
            user = payload.get("user") or d.get("user") or "unknown"
            target = payload.get("target") or d.get("target") or "unknown"
            pw = payload.get("password") or ""
            ts = d.get("timestamp")
            rows.append({
                "user": user,
                "target": target,
                "password": pw,
                "event_type": d.get("event_type", ""),
                "source": d.get("source", "unknown"),
                "timestamp": ts,
            })
        df = pd.DataFrame(rows)
        if df.empty:
            return df
        # Parse timestamp to datetime
        df["dt"] = pd.to_datetime(df["timestamp"].str.replace("Z", "+00:00", regex=False), errors="coerce")
        now = pd.Timestamp.utcnow()
        df["age_s"] = (now - df["dt"]).dt.total_seconds()
        # Feature: per-minute burstiness (std/mean of per-minute counts)
        df["minute"] = df["dt"].dt.floor("min")
        per_min_counts = df.groupby(["user", "target", "minute"], dropna=False).size().rename("cnt").reset_index()
        burst = per_min_counts.groupby(["user", "target"], dropna=False).agg(
            burst_mean=("cnt", "mean"), burst_std=("cnt", "std")
        ).reset_index()
        burst["burstiness"] = burst["burst_std"].fillna(0) / (burst["burst_mean"].fillna(0) + 1e-6)

        # Aggregate features per (user, target)
        grp = df.groupby(["user", "target"], dropna=False)
        feats = grp.agg(
            total_attempts=("event_type", "count"),
            unique_passwords=("password", pd.Series.nunique),
            mean_age_s=("age_s", "mean"),
            unique_sources=("source", pd.Series.nunique),
            unique_event_types=("event_type", pd.Series.nunique),
            min_dt=("dt", "min"),
            max_dt=("dt", "max"),
        ).reset_index()

        # Rate per minute across observed span
        span_min = (feats["max_dt"] - feats["min_dt"]).dt.total_seconds() / 60.0
        span_min = span_min.fillna(0.0).clip(lower=0.0)
        feats["rate_per_min"] = feats["total_attempts"] / (span_min.where(span_min > 0, 1.0))

        # Password entropy average per group
        df["pw_entropy"] = df["password"].astype(str).map(self._pw_entropy)
        pw_stats = df.groupby(["user", "target"], dropna=False).agg(pw_entropy_avg=("pw_entropy", "mean")).reset_index()

        # Merge burstiness and pw stats
        feats = feats.merge(burst[["user", "target", "burstiness"]], on=["user", "target"], how="left")
        feats = feats.merge(pw_stats, on=["user", "target"], how="left")

        # Fill NaNs
        feats = feats.fillna({
            "mean_age_s": 0.0,
            "burstiness": 0.0,
            "pw_entropy_avg": 0.0,
            "rate_per_min": 0.0,
        })
        # Drop helper datetime cols
        feats = feats.drop(columns=["min_dt", "max_dt"], errors="ignore")
        return feats

    def _score_iforest(self, feats: pd.DataFrame) -> pd.DataFrame:
        if feats.empty:
            return feats
        feature_cols = [
            "total_attempts",
            "unique_passwords",
            "mean_age_s",
            "unique_sources",
            "unique_event_types",
            "rate_per_min",
            "burstiness",
            "pw_entropy_avg",
        ]
        X = feats[feature_cols].to_numpy(dtype=float)
        # IsolationForest: higher anomaly if lower score_samples -> we convert to positive anomaly score
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        model.fit(X)
        scores = -model.score_samples(X)
        feats = feats.copy()
        feats["anomaly_score"] = scores
        feats = feats.sort_values("anomaly_score", ascending=False)
        return feats

    async def latest_anomalies(self, limit: int = 20) -> Dict[str, Any]:
        ingest = LogIngest()
        docs = await self._load_recent_logs(ingest)
        feats = self._build_features(docs)
        if feats.empty:
            return {"count": 0, "results": []}
        scored = self._score_iforest(feats)
        # Convert top rows to dicts
        out = scored.head(limit).to_dict(orient="records")
        return {
            "count": len(out),
            "results": out,
        }
