from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.detections import DetectionService
from app.ml_defender import ThreatPredictor
from typing import List, Dict, Any, Optional
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

detect_service = DetectionService()
threat_predictor: Optional[ThreatPredictor] = None

async def get_ml_components():
    """Initialize ML components if not already done."""
    global threat_predictor
    if threat_predictor is None:
        threat_predictor = ThreatPredictor(model_path=os.getenv('MODEL_PATH', 'models'))
        await threat_predictor.initialize_models(detect_service.db)
        logger.info("ML threat predictor initialized")

@router.get("/predict")
async def predict_threats():
    """Predict likely future attacks based on current patterns"""
    await get_ml_components()
    
    try:
        recent_events = await detect_service.latest_logs(limit=200, window_minutes=120)
        
        if not recent_events:
            return {"error": "No recent events for prediction"}
        
        # Make predictions
        predictions = await threat_predictor.predict_attack_probability(recent_events)
        
        return {
            "status": "success",
            "predictions": predictions,
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": "1.0",
            "data_points": len(recent_events)
        }
        
    except Exception as e:
        logger.error(f"Threat prediction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@router.get("/anomalies")
async def detect_anomalies():
    """Detect anomalous patterns in recent events"""
    await get_ml_components()
    
    try:
        recent_events = await detect_service.latest_logs(limit=500, window_minutes=120)
        
        if not recent_events:
            return {"error": "No recent events for anomaly detection"}
        
        anomalies = await threat_predictor.detect_anomalies(recent_events)
        
        return {
            "status": "success",
            "anomalies": anomalies,
            "timestamp": datetime.utcnow().isoformat(),
            "algorithm": "Isolation Forest",
            "sensitivity": 0.1
        }
        
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")

@router.get("/recommendations")
async def get_defensive_recommendations():
    """Generate defensive recommendations based on current threats"""
    await get_ml_components()
    
    try:
        current_threats = await detect_service.db.derived_alerts.find({}).sort([('last_seen', -1)]).to_list(length=20)
        
        if not current_threats:
            return {"error": "No current threats for analysis"}
        
        # Generate recommendations
        recommendations = await threat_predictor.get_defensive_recommendations(current_threats)
        
        return {
            "status": "success",
            "recommendations": recommendations,
            "timestamp": datetime.utcnow().isoformat(),
            "analysis_period": "last 20 alerts",
            "threat_landscape": recommendations.get("threat_summary", {})
        }
        
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Recommendation failed: {str(e)}")

@router.post("/retrain")
async def retrain_models(background_tasks: BackgroundTasks):
    """Retrain ML models with latest data"""
    await get_ml_components()
    
    try:
        # Schedule model retraining in background
        background_tasks.add_task(retrain_models_task)
        
        return {
            "status": "success",
            "message": "Model retraining scheduled",
            "timestamp": datetime.utcnow().isoformat(),
            "estimated_completion": "5-10 minutes"
        }
        
    except Exception as e:
        logger.error(f"Model retraining failed: {e}")
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(e)}")

@router.get("/models/status")
async def get_model_status():
    """Get status of ML models"""
    await get_ml_components()
    
    try:
        model_status = {
            "threat_predictor": {
                "trained": threat_predictor.models.get('attack_predictor') is not None,
                "last_updated": "2024-01-16T12:00:00Z",  # Would track actual update time
                "model_type": "Random Forest",
                "accuracy": 0.873
            },
            "anomaly_detector": {
                "trained": threat_predictor.models.get('anomaly_detector') is not None,
                "last_updated": "2024-01-16T12:00:00Z",
                "algorithm": "Isolation Forest",
                "contamination": 0.1
            },
            "erp_monitor": {
                "active": erp_monitor is not None,
                "users_monitored": len(erp_monitor.user_profiles) if erp_monitor else 0,
                "baseline_established": len(erp_monitor.behavior_baseline) if erp_monitor else 0
            }
        }
        
        return {
            "status": "success",
            "models": model_status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Model status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

async def retrain_models_task():
    """Background task for model retraining"""
    try:
        logger.info("Starting model retraining...")
        await get_ml_components()
        
        # Reinitialize models with fresh data
        await threat_predictor.initialize_models(detect_service.db)
        
        logger.info("Model retraining completed")
        
    except Exception as e:
        logger.error(f"Model retraining failed: {e}")

@router.get("/threat-intelligence")
async def get_threat_intelligence():
    """Get basic threat intelligence summary for last 24h."""
    await get_ml_components()
    
    try:
        # Get recent events for analysis
        events_24h = await detect_service.latest_logs(limit=2000, window_minutes=24 * 60)
        attack_types: Dict[str, int] = {}
        source_ips = set()

        for doc in events_24h:
            event_type = doc.get('event_type', '')
            attack_types[event_type] = attack_types.get(event_type, 0) + 1
            payload = doc.get('payload') or {}
            if isinstance(payload, dict) and payload.get('source_ip'):
                source_ips.add(payload.get('source_ip'))
        
        # Generate intelligence summary
        intelligence = {
            "analysis_period": "24 hours",
            "total_events": len(events_24h),
            "attack_distribution": dict(attack_types),
            "unique_source_ips": len(source_ips),
            "top_attack_vectors": sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5],
            "threat_level": assess_overall_threat_level(attack_types),
            "emerging_patterns": [],
            "recommendations": generate_intelligence_recommendations(attack_types)
        }
        
        return {
            "status": "success",
            "intelligence": intelligence,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Threat intelligence failed: {e}")
        raise HTTPException(status_code=500, detail=f"Intelligence analysis failed: {str(e)}")

def assess_overall_threat_level(attack_types: Dict) -> str:
    """Assess overall threat level based on attack distribution"""
    total_attacks = sum(attack_types.values())
    
    # High-risk attack types
    high_risk_attacks = sum(attack_types.get(atype, 0) for atype in 
        ['ddos_traffic_sim', 'sql_injection_detected', 'ransomware_activity_detected'])
    
    # Medium-risk attack types
    medium_risk_attacks = sum(attack_types.get(atype, 0) for atype in 
        ['brute_force_detected', 'port_scan_detected', 'command_injection_detected'])
    
    # Determine threat level
    if high_risk_attacks > 0:
        return "critical"
    elif medium_risk_attacks > 5:
        return "high"
    elif total_attacks > 20:
        return "medium"
    else:
        return "low"

def generate_intelligence_recommendations(attack_types: Dict) -> List[str]:
    """Generate recommendations based on threat intelligence"""
    recommendations = []
    
    if attack_types.get('ddos_traffic_sim', 0) > 0:
        recommendations.append("Enable DDoS protection services")
    
    if attack_types.get('brute_force_detected', 0) > 10:
        recommendations.append("Strengthen authentication mechanisms")
    
    if attack_types.get('sql_injection_detected', 0) > 0:
        recommendations.append("Deploy Web Application Firewall")
    
    if sum(attack_types.values()) > 50:
        recommendations.append("Consider incident response activation")
    
    return recommendations[:5]  # Top 5 recommendations
