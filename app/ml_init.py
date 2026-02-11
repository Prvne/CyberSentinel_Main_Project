import asyncio
import logging
from app.ml_defender import ThreatPredictor
from app.erp_monitor import ERPMonitor
from app.main import detect_service
from datetime import datetime

logger = logging.getLogger(__name__)

async def initialize_ml_system():
    """Initialize ML components for defending agent"""
    try:
        logger.info("Initializing ML defending system...")
        
        # Initialize threat predictor
        threat_predictor = ThreatPredictor()
        await threat_predictor.initialize_models(detect_service.db)
        logger.info("✅ Threat predictor initialized")
        
        # Initialize ERP monitor
        erp_monitor = ERPMonitor(detect_service.db)
        await erp_monitor.initialize_monitoring()
        logger.info("✅ ERP monitor initialized")
        
        # Store components globally for API access
        # In production, these would be managed by a dependency injection system
        import app.ml_api
        app.ml_api.threat_predictor = threat_predictor
        app.ml_api.erp_monitor = erp_monitor
        
        logger.info("🤖 ML defending system fully initialized")
        return True
        
    except Exception as e:
        logger.error(f"❌ ML system initialization failed: {e}")
        return False

async def run_ml_training_cycle():
    """Periodic ML model retraining"""
    try:
        logger.info("Starting ML training cycle...")
        
        # Reinitialize models with fresh data
        success = await initialize_ml_system()
        
        if success:
            logger.info("🔄 ML training cycle completed successfully")
        else:
            logger.error("❌ ML training cycle failed")
            
    except Exception as e:
        logger.error(f"❌ ML training cycle error: {e}")

if __name__ == "__main__":
    # Run initialization
    asyncio.run(initialize_ml_system())
