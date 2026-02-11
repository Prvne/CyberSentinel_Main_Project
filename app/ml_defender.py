import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from collections import defaultdict, deque
import json

logger = logging.getLogger(__name__)

class ThreatPredictor:
    """ML-based threat prediction and anomaly detection system"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.models = {}
        self.label_encoders = {}
        self.attack_history = deque(maxlen=1000)
        self.feature_cache = {}
        
    async def initialize_models(self, db: AsyncIOMotorClient):
        """Initialize ML models with historical data"""
        try:
            # Load historical attack data
            cursor = db.logs.find({
                "event_type": {"$exists": True},
                "timestamp": {"$gte": datetime.utcnow() - timedelta(days=30)}
            }).sort("timestamp", -1).limit(10000)
            
            feature_rows: List[Dict] = []
            labels: List[str] = []
            async for doc in cursor:
                feature_rows.append(self._extract_features(doc))
                labels.append(str(doc.get('event_type', '')))
            
            if len(feature_rows) < 100:
                logger.warning("Insufficient training data, using default models")
                self._create_default_models()
                return
            
            feature_df = pd.DataFrame(feature_rows).fillna(0)
            label_series = pd.Series(labels, name='event_type')
            
            # Train attack prediction model
            X, y = self._prepare_training_data(feature_df, label_series)
            self._train_attack_predictor(X, y)
            
            # Train anomaly detection models
            self._train_anomaly_detectors(feature_df)
            
            logger.info(f"Models trained on {len(feature_rows)} historical events")
            
        except Exception as e:
            logger.error(f"Model initialization failed: {e}")
            self._create_default_models()
    
    def _extract_features(self, event: Dict) -> Dict:
        """Extract ML features from security event"""
        features = {}
        
        # Time-based features
        if 'timestamp' in event:
            ts = pd.to_datetime(event['timestamp'])
            features['hour'] = ts.hour
            features['day_of_week'] = ts.dayofweek
            features['is_weekend'] = 1 if ts.dayofweek >= 5 else 0
        
        # Source-based features
        if 'source' in event:
            features['source_sim_runner'] = 1 if event['source'] == 'sim_runner' else 0
        
        # Event type features
        event_type = event.get('event_type', '')
        features['is_brute_force'] = 1 if 'brute_force' in event_type else 0
        features['is_port_scan'] = 1 if 'port_scan' in event_type else 0
        features['is_ddos'] = 1 if 'ddos' in event_type else 0
        features['is_sqli'] = 1 if 'sql' in event_type else 0
        features['is_xss'] = 1 if 'xss' in event_type else 0
        
        # Payload-based features
        if 'payload' in event:
            payload = event['payload']
            if isinstance(payload, dict):
                features['payload_size'] = len(str(payload))
                features['has_admin_target'] = 1 if 'admin' in str(payload).lower() else 0
                features['has_sql_keywords'] = 1 if any(kw in str(payload).lower() for kw in ['select', 'union', 'drop']) else 0
                
                # Rate-based features
                if 'rate_pps' in payload:
                    features['attack_rate'] = payload['rate_pps']
                if 'attempts' in payload:
                    features['attempt_count'] = payload['attempts']
                if 'ports' in payload:
                    features['port_count'] = len(payload['ports']) if isinstance(payload['ports'], list) else 1
        
        # Network features
        if 'source_ip' in event:
            ip = event['source_ip']
            features['is_internal_ip'] = 1 if ip.startswith(('192.168.', '10.', '172.')) else 0
        
        return features
    
    def _prepare_training_data(self, feature_df: pd.DataFrame, event_types: pd.Series) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare data for supervised learning.

        We learn a binary target: whether an event belongs to a high-frequency attack type.
        """
        attack_types = event_types.value_counts()
        target_attacks = attack_types[attack_types >= 10].index.tolist()

        X = feature_df.fillna(0).values
        y = event_types.apply(lambda x: 1 if x in target_attacks else 0).values
        return X, y
    
    def _train_attack_predictor(self, X: np.ndarray, y: np.ndarray):
        """Train Random Forest for attack prediction"""
        # Handle missing values
        X = pd.DataFrame(X).fillna(0).values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        rf.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = rf.predict(X_test_scaled)
        accuracy = rf.score(X_test_scaled, y_test)
        
        logger.info(f"Attack predictor trained with accuracy: {accuracy:.3f}")
        
        # Save model
        self.models['attack_predictor'] = rf
        joblib.dump(rf, f"{self.model_path}/attack_predictor.pkl")
        joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
    
    def _train_anomaly_detectors(self, feature_df: pd.DataFrame):
        """Train Isolation Forest for anomaly detection"""
        feature_data = feature_df.fillna(0)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        iso_forest.fit(feature_data)
        
        self.models['anomaly_detector'] = iso_forest
        joblib.dump(iso_forest, f"{self.model_path}/anomaly_detector.pkl")
        
        logger.info("Anomaly detector trained with Isolation Forest")
    
    def _create_default_models(self):
        """Create baseline models when insufficient data"""
        logger.warning("Creating baseline models - limited training data")
        # Models will be trained as more data becomes available
        self.models = {
            'attack_predictor': None,
            'anomaly_detector': None
        }
    
    async def predict_attack_probability(self, current_events: List[Dict]) -> Dict:
        """Predict probability of upcoming attacks"""
        if 'attack_predictor' not in self.models or self.models['attack_predictor'] is None:
            return {"error": "Attack predictor not trained"}
        
        try:
            # Extract features from recent events
            recent_features = []
            for event in current_events[-50:]:  # Last 50 events
                features = self._extract_features(event)
                recent_features.append(features)
            
            if not recent_features:
                return {"error": "No recent events for prediction"}
            
            # Prepare prediction data
            X_pred = pd.DataFrame(recent_features).fillna(0).values
            X_pred_scaled = self.scaler.transform(X_pred)
            
            # Make predictions
            model = self.models['attack_predictor']
            attack_prob = model.predict_proba(X_pred_scaled)
            
            # Calculate average probabilities
            avg_prob = np.mean(attack_prob[:, 1])  # Probability of attack
            
            # Predict likely next attack types
            recent_attacks = [e.get('event_type', '') for e in current_events[-20:]]
            attack_counts = defaultdict(int)
            for attack in recent_attacks:
                attack_counts[attack] += 1
            
            # Get most likely attacks
            likely_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                "attack_probability": float(avg_prob),
                "confidence_level": "high" if avg_prob > 0.7 else "medium" if avg_prob > 0.4 else "low",
                "likely_next_attacks": [{"type": k, "probability": v/len(recent_attacks)} for k, v in likely_attacks],
                "prediction_window": "next 2 hours",
                "based_on_events": len(recent_features)
            }
            
        except Exception as e:
            logger.error(f"Attack prediction failed: {e}")
            return {"error": str(e)}
    
    async def detect_anomalies(self, current_events: List[Dict]) -> Dict:
        """Detect anomalous patterns in current events"""
        if 'anomaly_detector' not in self.models or self.models['anomaly_detector'] is None:
            return {"error": "Anomaly detector not trained"}
        
        try:
            # Extract features from recent events
            recent_features = []
            for event in current_events[-100:]:  # Last 100 events
                features = self._extract_features(event)
                recent_features.append(features)
            
            if not recent_features:
                return {"error": "No recent events for anomaly detection"}
            
            # Detect anomalies
            X = pd.DataFrame(recent_features).fillna(0).values
            model = self.models['anomaly_detector']
            
            anomaly_scores = model.decision_function(X)
            anomaly_labels = model.predict(X)
            
            # Find anomalous events
            anomalous_indices = np.where(anomaly_labels == -1)[0]
            anomalies = []
            
            for idx in anomalous_indices:
                if idx < len(current_events):
                    anomaly_event = current_events[-100:][idx]
                    anomalies.append({
                        "event": anomaly_event,
                        "anomaly_score": float(anomaly_scores[idx]),
                        "anomaly_type": self._classify_anomaly_type(anomaly_event, anomaly_scores[idx]),
                        "severity": self._assess_anomaly_severity(anomaly_scores[idx])
                    })
            
            return {
                "anomalies_detected": len(anomalies),
                "anomaly_events": anomalies,
                "anomaly_rate": len(anomalies) / len(current_events),
                "analysis_window": "last 100 events",
                "threshold_used": 0.1  # Contamination parameter
            }
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return {"error": str(e)}
    
    def _classify_anomaly_type(self, event: Dict, score: float) -> str:
        """Classify the type of anomaly"""
        event_type = event.get('event_type', '')
        
        if score < -0.5:
            return "severe_anomaly"
        elif score < -0.2:
            return "moderate_anomaly"
        else:
            return "mild_anomaly"
    
    def _assess_anomaly_severity(self, score: float) -> str:
        """Assess severity based on anomaly score"""
        if score < -0.5:
            return "critical"
        elif score < -0.2:
            return "high"
        elif score < 0:
            return "medium"
        else:
            return "low"
    
    async def update_models(self, new_events: List[Dict]):
        """Update models with new events"""
        # Add to history
        self.attack_history.extend(new_events)
        
        # Retrain models periodically (every 100 new events)
        if len(self.attack_history) % 100 == 0:
            logger.info("Retraining models with new data")
            # In production, this would trigger background retraining
            # For now, just log the update
            pass
    
    async def get_defensive_recommendations(self, current_threats: List[Dict]) -> Dict:
        """Generate defensive recommendations based on current threats"""
        recommendations = []
        
        # Analyze current threat patterns
        threat_types = [t.get('type', '') for t in current_threats]
        
        # Brute force recommendations
        if any('brute_force' in t for t in threat_types):
            recommendations.append({
                "type": "brute_force_defense",
                "priority": "high",
                "actions": [
                    "Implement account lockout after 5 failed attempts",
                    "Enable multi-factor authentication",
                    "Use IP-based rate limiting",
                    "Monitor for credential stuffing patterns"
                ],
                "tools": ["Fail2Ban", "Google Authenticator", "Rate Limiting"]
            })
        
        # DDoS recommendations
        if any('ddos' in t for t in threat_types):
            recommendations.append({
                "type": "ddos_defense",
                "priority": "critical",
                "actions": [
                    "Enable DDoS protection service",
                    "Implement rate limiting at edge",
                    "Configure traffic scrubbing",
                    "Prepare incident response plan"
                ],
                "tools": ["Cloudflare", "AWS Shield", "Akamai Kona Site Defender"]
            })
        
        # SQL Injection recommendations
        if any('sql' in t for t in threat_types):
            recommendations.append({
                "type": "sqli_defense",
                "priority": "high",
                "actions": [
                    "Implement input validation",
                    "Use parameterized queries",
                    "Deploy Web Application Firewall",
                    "Regular security testing"
                ],
                "tools": ["OWASP ESAPI", "ModSecurity", "SQLMap"]
            })
        
        # Port scan recommendations
        if any('port_scan' in t for t in threat_types):
            recommendations.append({
                "type": "port_scan_defense",
                "priority": "medium",
                "actions": [
                    "Close unnecessary ports",
                    "Implement port knocking",
                    "Use network segmentation",
                    "Deploy intrusion detection"
                ],
                "tools": ["Nmap", "Fail2Ban", "Snort"]
            })
        
        return {
            "recommendations": recommendations,
            "total_recommendations": len(recommendations),
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "threat_summary": self._summarize_threats(threat_types)
        }
    
    def _summarize_threats(self, threat_types: List[str]) -> Dict:
        """Summarize current threat landscape"""
        summary = {
            "total_unique_threats": len(set(threat_types)),
            "most_common": "",
            "threat_distribution": {},
            "risk_level": "low"
        }
        
        # Count threat types
        threat_counts = defaultdict(int)
        for threat in threat_types:
            threat_counts[threat] += 1
        
        if threat_counts:
            summary["most_common"] = max(threat_counts.items(), key=lambda x: x[1])[0]
            summary["threat_distribution"] = dict(threat_counts)
            
            # Assess overall risk level
            high_risk_threats = ['ddos', 'sql_injection', 'ransomware']
            medium_risk_threats = ['brute_force', 'port_scan', 'xss']
            
            high_risk_count = sum(1 for t in threat_types if any(hrt in t for hrt in high_risk_threats))
            medium_risk_count = sum(1 for t in threat_types if any(mrt in t for mrt in medium_risk_threats))
            
            if high_risk_count > 0:
                summary["risk_level"] = "critical"
            elif medium_risk_count > 2:
                summary["risk_level"] = "high"
            elif len(threat_types) > 5:
                summary["risk_level"] = "medium"
            else:
                summary["risk_level"] = "low"
        
        return summary
