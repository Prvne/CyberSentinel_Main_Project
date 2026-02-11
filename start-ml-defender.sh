#!/bin/bash

# CyberSentinelAI - ML Defending Agent Startup Script
# This script starts the ML defending agent with proper configuration

set -e

echo "🤖 CyberSentinelAI - ML Defending Agent Startup"
echo "=========================================="

# Configuration
ML_MODE="${ML_MODE:-production}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
PREDICTION_INTERVAL="${PREDICTION_INTERVAL:-30}"
ANOMALY_THRESHOLD="${ANOMALY_THRESHOLD:-0.1}"
MAX_USERS="${MAX_USERS:-1000}"
TRAINING_INTERVAL="${TRAINING_INTERVAL:-3600}"

echo "📊 Configuration:"
echo "  ML Mode: $ML_MODE"
echo "  Log Level: $LOG_LEVEL"
echo "  Prediction Interval: ${PREDICTION_INTERVAL}s"
echo "  Anomaly Threshold: $ANOMALY_THRESHOLD"
echo "  Max Users: $MAX_USERS"
echo "  Training Interval: ${TRAINING_INTERVAL}s"
echo ""

# Check if Docker is running
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "🐳 Checking Docker Compose configuration..."

# Check if ml-defender compose file exists
if [ ! -f "docker-compose.ml-defender.yml" ]; then
    echo "❌ docker-compose.ml-defender.yml not found"
    exit 1
fi

echo "🚀 Starting ML Defending Agent services..."

# Start the ML defending agent stack
docker-compose -f docker-compose.ml-defender.yml up -d

echo ""
echo "📊 Service URLs:"
echo "  🤖 ML Defending API: http://localhost:8001"
echo "  📊 Health Check: http://localhost:8001/health"
echo "  🔍 Model Status: http://localhost:8001/api/models/status"
echo "  📈 Threat Predictions: http://localhost:8001/api/ml/predict"
echo "  👁 Anomaly Detection: http://localhost:8001/api/ml/anomalies"
echo "  🛡️ Recommendations: http://localhost:8001/api/ml/recommendations"
echo ""

echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service health
echo "🔍 Checking service health..."
for i in {1..5}; do
    if curl -s http://localhost:8001/health > /dev/null; then
        echo "✅ ML Defending Agent is ready!"
        echo ""
        echo "🎯 Services Status:"
        docker-compose -f docker-compose.ml-defender.yml ps
        echo ""
        echo "📊 Access the ML Defending Dashboard:"
        echo "  Main API: http://localhost:8000 (existing services)"
        echo "  ML API: http://localhost:8001 (new ML defending agent)"
        echo "  Dashboard: http://localhost:3000 (updated to use ML services)"
        echo ""
        echo "🔍 To view logs:"
        echo "  docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender"
        echo ""
        echo "🛑 To stop services:"
        echo "  docker-compose -f docker-compose.ml-defender.yml down"
        break
    else
        echo "⏳ Waiting for services... ($i/5)"
        sleep 5
done

echo "❌ Failed to start ML Defending Agent"
echo "🔍 Check logs with: docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender"
exit 1
