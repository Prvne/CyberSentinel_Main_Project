# CyberSentinelAI - ML Defending Agent

## Overview

The ML Defending Agent can be deployed as a **separate, scalable container** for enterprise environments. This provides isolation, resource management, and independent scaling of the ML components.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Sufficient system resources (4GB+ RAM recommended)
- Network access to MongoDB and Redis

### Option 1: Docker Compose (Recommended)
```bash
# Make startup script executable
chmod +x start-ml-defender.sh

# Start the ML defending agent
./start-ml-defender.sh
```

### Option 2: Manual Docker Commands
```bash
# Build and start ML defending agent
docker-compose -f docker-compose.ml-defender.yml up -d --build

# View logs
docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender

# Stop services
docker-compose -f docker-compose.ml-defender.yml down
```

## 📊 Service Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 CyberSentinelAI Stack                │
├─────────────────────────────────────────────────────────────────┤
│  MongoDB (mongo:27017)                              │
│  Redis (redis:6379)                                 │
│  Main Backend (localhost:8000)                        │
│  ML Defending Agent (localhost:8001)                   │
│  Odoo ERP (localhost:8069)                           │
│  Dashboard (localhost:3000)                             │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Services

### ML Defending Agent Container
- **Purpose**: Predictive threat analysis and automated defense
- **Port**: 8001 (separate from main backend)
- **Features**: 
  - Attack prediction (Random Forest)
  - Anomaly detection (Isolation Forest)
  - User behavior monitoring
  - Defensive recommendations
- **Resources**: Dedicated CPU/Memory allocation
- **Scaling**: Horizontal scaling via Docker Compose

### Integration Points
- **MongoDB**: Shared with main backend for event data
- **Redis**: Shared for caching and session management
- **API**: RESTful endpoints for ML capabilities
- **Dashboard**: Updated to consume ML API endpoints

## 📡 API Endpoints

### ML Defending Agent (Port 8001)
```
GET  /health                          # Service health check
GET  /api/models/status               # ML model status
GET  /api/ml/predict                 # Attack predictions
GET  /api/ml/anomalies              # Anomaly detection
GET  /api/ml/recommendations          # Defensive recommendations
GET  /api/erp/monitoring             # User behavior monitoring
POST /api/ml/retrain                 # Model retraining
```

### Main Backend (Port 8000)
```
GET  /health                          # Existing health endpoint
GET  /alerts/derived                  # Existing derived alerts
POST /run-simulation                   # Existing simulation endpoint
```

### Dashboard (Port 3000)
```
- Updated to connect to ML API endpoints
- Real-time threat intelligence display
- User behavior monitoring dashboard
- Anomaly detection visualization
```

## ⚙️ Configuration

### Environment Variables
Create `.env.ml-defender` with your settings:

```bash
# Core Configuration
ML_MODE=production
LOG_LEVEL=INFO
PREDICTION_INTERVAL=30
ANOMALY_THRESHOLD=0.1
MAX_USERS=1000

# Database Connections
MONGO_URI=mongodb://mongo:27017
REDIS_URL=redis://redis:6379

# Security
API_KEY=your-secure-api-key-here
```

### Docker Compose Override
```bash
# Development mode
docker-compose -f docker-compose.ml-defender.yml --env-file .env.dev up -d

# Custom resource limits
docker-compose -f docker-compose.ml-defender.yml up -d --scale ml-defender=3
```

## 🔍 Monitoring & Troubleshooting

### Health Checks
```bash
# Service health
curl http://localhost:8001/health

# Detailed status
curl http://localhost:8001/api/models/status

# Component logs
docker-compose -f docker-compose.ml-defender.yml logs -f ml-defender
```

### Performance Monitoring
```bash
# Resource usage
docker stats cybersentinel-ml-defender

# Model performance
curl http://localhost:8001/api/models/status | jq '.models.threat_predictor.accuracy'
```

### Model Management
```bash
# Retrain models
curl -X POST http://localhost:8001/api/ml/retrain

# Update configuration
docker-compose -f docker-compose.ml-defender.yml restart ml-defender
```

## 🚀 Deployment Scenarios

### Development Environment
```bash
# Start with debug logging
LOG_LEVEL=DEBUG ./start-ml-defender.sh

# Use development configuration
cp .env.dev .env.ml-defender
```

### Production Environment
```bash
# Production deployment
./start-ml-defender.sh

# Behind reverse proxy (nginx/traefik)
# Update API_URL environment variables
```

### High Availability
```bash
# Multiple instances for load balancing
docker-compose -f docker-compose.ml-defender.yml up -d --scale ml-defender=3

# With external database cluster
MONGO_URI=mongodb://mongo-cluster:27017,mongo-cluster:27018
```

## 📈 Scaling Considerations

### Horizontal Scaling
- **Load Balancer**: nginx/traefik for multiple ML instances
- **Session Affinity**: Ensure user sessions route to same ML instance
- **Database Sharding**: MongoDB cluster for high-volume environments
- **Caching**: Redis cluster for session management

### Vertical Scaling
- **Resource Allocation**: Increase CPU/Memory limits
- **GPU Acceleration**: For deep learning model training
- **Model Optimization**: Use larger training datasets

### Monitoring at Scale
- **Distributed Tracing**: Jaeger/Zipkin for request tracking
- **Metrics Collection**: Prometheus + Grafana for performance monitoring
- **Log Aggregation**: ELK stack for centralized logging

## 🔒 Security Best Practices

### Container Security
```bash
# Use non-root user
USER app
# Read-only filesystem
RUN addgroup -r mlapp && user -r mlapp app
# Minimal attack surface
EXPOSE 8001
```

### Network Security
```yaml
# Isolated network
networks:
  cybersentinel-network:
    driver: bridge
    internal: true
```

### API Security
```bash
# Rate limiting
# API key authentication
# HTTPS termination at reverse proxy
# Input validation and sanitization
```

## 🎯 Use Cases

### Enterprise Security Operations
1. **SOC Integration**: Feed threat intelligence to SIEM systems
2. **Threat Hunting**: Use predictions for proactive threat hunting
3. **Incident Response**: Automated recommendations for security teams
4. **Compliance Reporting**: Automated audit and compliance reporting

### Managed Security Services
1. **MSSP Integration**: Deploy as managed security service
2. **Multi-tenant**: Serve multiple organizations from single deployment
3. **API Gateway**: Provide ML defense as API service
4. **Hybrid Cloud**: On-premises + cloud ML scaling

---

## 📚 Documentation

- **API Documentation**: Auto-generated OpenAPI specs at `/docs`
- **Model Documentation**: Training data, feature importance, performance metrics
- **Operations Guide**: Step-by-step deployment and troubleshooting
- **Security Guide**: Hardening guidelines and best practices

For detailed architecture documentation, see `DEFENDING_AGENT_DOCUMENTATION.md`
