import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque
import numpy as np
from motor.motor_asyncio import AsyncIOMotorClient
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

logger = logging.getLogger(__name__)

class ERPMonitor:
    """ERP system monitoring for user behavior analysis and anomaly detection"""
    
    def __init__(self, db: AsyncIOMotorClient):
        self.db = db
        self.user_profiles = {}
        self.behavior_baseline = {}
        self.anomaly_history = deque(maxlen=500)
        self.risk_scores = defaultdict(float)
        
    async def initialize_monitoring(self):
        """Initialize ERP monitoring with historical data"""
        try:
            # Load user activity from logs
            cursor = self.db.logs.find({
                "source": "odoo",
                "timestamp": {"$gte": datetime.utcnow() - timedelta(days=7)}
            }).sort("timestamp", -1).limit(5000)
            
            user_activities = defaultdict(list)
            async for doc in cursor:
                if 'payload' in doc and 'user' in doc['payload']:
                    user = doc['payload']['user']
                    user_activities[user].append(doc)
            
            # Build user behavior profiles
            for user, activities in user_activities.items():
                self.user_profiles[user] = await self._build_user_profile(user, activities)
                self.behavior_baseline[user] = await self._establish_baseline(user, activities)
            
            logger.info(f"ERP monitoring initialized for {len(self.user_profiles)} users")
            
        except Exception as e:
            logger.error(f"ERP monitoring initialization failed: {e}")
    
    async def _build_user_profile(self, user: str, activities: List[Dict]) -> Dict:
        """Build comprehensive user behavior profile"""
        if not activities:
            return {}
        
        profile = {
            "user": user,
            "total_activities": len(activities),
            "activity_types": defaultdict(int),
            "time_patterns": {},
            "access_patterns": defaultdict(int),
            "risk_indicators": []
        }
        
        # Analyze activity types
        for activity in activities:
            event_type = activity.get('event_type', '')
            profile["activity_types"][event_type] += 1
            
            # Time-based analysis
            if 'timestamp' in activity:
                hour = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).hour
                profile["time_patterns"][hour] = profile["time_patterns"].get(hour, 0) + 1
        
        # Calculate risk indicators
        profile["risk_indicators"] = await self._assess_user_risk(user, activities)
        
        return profile
    
    async def _establish_baseline(self, user: str, activities: List[Dict]) -> Dict:
        """Establish behavioral baseline for user"""
        if len(activities) < 10:
            return {"status": "insufficient_data"}
        
        baseline = {
            "user": user,
            "avg_daily_activities": len(activities) / 7,  # Assume 7 days
            "typical_hours": self._calculate_typical_hours(activities),
            "common_actions": self._get_common_actions(activities),
            "access_frequency": self._calculate_access_frequency(activities),
            "data_access_patterns": self._analyze_data_access(activities),
            "established": datetime.utcnow().isoformat()
        }
        
        return baseline
    
    def _calculate_typical_hours(self, activities: List[Dict]) -> List[int]:
        """Calculate typical working hours for user"""
        hours = []
        for activity in activities:
            if 'timestamp' in activity:
                hour = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).hour
                hours.append(hour)
        
        if not hours:
            return [9, 10, 11, 14, 15, 16]  # Business hours default
        
        # Find most common hours (top 80%)
        hours.sort()
        return hours[:int(len(hours) * 0.8)]
    
    def _get_common_actions(self, activities: List[Dict]) -> List[str]:
        """Get most common user actions"""
        actions = []
        for activity in activities:
            if 'event_type' in activity:
                actions.append(activity['event_type'])
        
        if not actions:
            return ["login", "logout"]
        
        # Return top 5 most common
        from collections import Counter
        action_counts = Counter(actions)
        return [action for action, _ in action_counts.most_common(5)]
    
    def _calculate_access_frequency(self, activities: List[Dict]) -> Dict:
        """Calculate access frequency patterns"""
        daily_access = defaultdict(int)
        weekly_access = defaultdict(int)
        
        for activity in activities:
            if 'timestamp' in activity:
                date = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).date()
                daily_access[str(date)] += 1
                week = date.isocalendar()[1]
                weekly_access[f"week_{week}"] += 1
        
        return {
            "avg_daily": np.mean(list(daily_access.values())) if daily_access else 0,
            "max_daily": max(daily_access.values()) if daily_access else 0,
            "avg_weekly": np.mean(list(weekly_access.values())) if weekly_access else 0,
            "access_regularity": self._calculate_regularity(daily_access)
        }
    
    def _analyze_data_access(self, activities: List[Dict]) -> Dict:
        """Analyze data access patterns"""
        data_access = {
            "modules_accessed": set(),
            "records_created": 0,
            "records_modified": 0,
            "sensitive_access": 0,
            "export_activities": 0
        }
        
        for activity in activities:
            if 'payload' in activity:
                payload = activity['payload']
                
                # Track module access
                if 'model' in payload:
                    data_access["modules_accessed"].add(payload['model'])
                
                # Track record operations
                if 'operation' in payload:
                    op = payload['operation']
                    if op in ['create', 'add']:
                        data_access["records_created"] += 1
                    elif op in ['write', 'update', 'modify']:
                        data_access["records_modified"] += 1
                
                # Track sensitive data access
                if 'model' in payload and any(sensitive in payload['model'].lower() 
                    for sensitive in ['user', 'employee', 'salary', 'payroll', 'customer']):
                    data_access["sensitive_access"] += 1
                
                # Track export activities
                if 'operation' in payload and 'export' in payload['operation'].lower():
                    data_access["export_activities"] += 1
        
        data_access["modules_accessed"] = list(data_access["modules_accessed"])
        return data_access
    
    def _calculate_regularity(self, daily_access: Dict) -> float:
        """Calculate access regularity score"""
        if not daily_access:
            return 0.0
        
        access_counts = list(daily_access.values())
        if len(access_counts) < 2:
            return 0.0
        
        # Calculate coefficient of variation (lower = more regular)
        mean_access = np.mean(access_counts)
        std_access = np.std(access_counts)
        
        if mean_access == 0:
            return 0.0
        
        cv = std_access / mean_access
        # Convert to regularity score (inverse of CV)
        regularity = 1 / (1 + cv)
        return regularity
    
    async def _assess_user_risk(self, user: str, activities: List[Dict]) -> List[Dict]:
        """Assess risk indicators for user"""
        risks = []
        
        # Check for unusual access times
        unusual_times = await self._detect_unusual_times(user, activities)
        if unusual_times:
            risks.append({
                "type": "unusual_access_times",
                "severity": "medium",
                "description": f"Access detected at unusual times: {unusual_times}",
                "recommendation": "Verify user identity and schedule"
            })
        
        # Check for excessive access
        excessive_access = await self._detect_excessive_access(user, activities)
        if excessive_access:
            risks.append({
                "type": "excessive_access",
                "severity": "high",
                "description": f"Excessive system access: {excessive_access} activities/day",
                "recommendation": "Review access permissions and necessity"
            })
        
        # Check for sensitive data access
        sensitive_access = await self._detect_sensitive_data_access(user, activities)
        if sensitive_access:
            risks.append({
                "type": "sensitive_data_access",
                "severity": "high",
                "description": f"Access to sensitive data: {sensitive_access}",
                "recommendation": "Review data access authorization"
            })
        
        # Check for mass operations
        mass_operations = await self._detect_mass_operations(user, activities)
        if mass_operations:
            risks.append({
                "type": "mass_operations",
                "severity": "critical",
                "description": f"Mass data operations detected: {mass_operations}",
                "recommendation": "Immediate security review required"
            })
        
        return risks
    
    async def _detect_unusual_times(self, user: str, activities: List[Dict]) -> List[str]:
        """Detect access at unusual times"""
        if user not in self.behavior_baseline:
            return []
        
        baseline = self.behavior_baseline[user]
        typical_hours = baseline.get('typical_hours', [9, 10, 11, 14, 15, 16])
        
        unusual_times = []
        for activity in activities:
            if 'timestamp' in activity:
                hour = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).hour
                if hour not in typical_hours and hour not in [6, 7, 8]:  # Exclude early morning
                    unusual_times.append(f"{hour:02d}:00")
        
        return list(set(unusual_times))[:5]  # Return top 5 unusual times
    
    async def _detect_excessive_access(self, user: str, activities: List[Dict]) -> Optional[int]:
        """Detect excessive access patterns"""
        if not activities:
            return None
        
        # Group activities by date
        daily_counts = defaultdict(int)
        for activity in activities:
            if 'timestamp' in activity:
                date = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).date()
                daily_counts[date] += 1
        
        if len(daily_counts) < 2:
            return None
        
        # Calculate threshold (3x average)
        avg_daily = np.mean(list(daily_counts.values()))
        threshold = avg_daily * 3
        
        # Find days exceeding threshold
        excessive_days = [count for count in daily_counts.values() if count > threshold]
        
        return max(excessive_days) if excessive_days else None
    
    async def _detect_sensitive_data_access(self, user: str, activities: List[Dict]) -> List[str]:
        """Detect access to sensitive data"""
        sensitive_modules = ['hr.employee', 'hr.contract', 'account.invoice', 'sale.order', 'purchase.order']
        
        sensitive_access = []
        for activity in activities:
            if 'payload' in activity and 'model' in activity['payload']:
                model = activity['payload']['model']
                if any(sens in model.lower() for sens in sensitive_modules):
                    sensitive_access.append(model)
        
        return list(set(sensitive_access))[:5]  # Return top 5
    
    async def _detect_mass_operations(self, user: str, activities: List[Dict]) -> List[str]:
        """Detect mass data operations"""
        mass_operations = []
        
        # Look for rapid successive operations
        for i, activity in enumerate(activities):
            if 'payload' in activity and 'operation' in activity['payload']:
                op = activity['payload']['operation']
                
                # Check for multiple operations in short time
                recent_ops = []
                for j in range(max(0, i-5), i):
                    if j < len(activities) and 'payload' in activities[j] and 'operation' in activities[j]['payload']:
                        recent_ops.append(activities[j]['payload']['operation'])
                
                if len(recent_ops) >= 10:  # 10+ operations in 5 events
                    mass_operations.append(f"Rapid {op} operations")
        
        return list(set(mass_operations))[:3]  # Return top 3
    
    async def monitor_real_time(self, event: Dict) -> Dict:
        """Real-time monitoring of new events"""
        if 'payload' not in event or 'user' not in event['payload']:
            return {"status": "no_user_data"}
        
        user = event['payload']['user']
        current_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
        
        analysis = {
            "user": user,
            "event": event,
            "timestamp": current_time.isoformat(),
            "anomaly_detected": False,
            "risk_level": "normal",
            "alerts": []
        }
        
        # Check against baseline
        if user in self.behavior_baseline:
            baseline = self.behavior_baseline[user]
            
            # Time-based anomaly check
            typical_hours = baseline.get('typical_hours', [])
            if current_time.hour not in typical_hours and current_time.hour not in [6, 7, 8]:
                analysis["anomaly_detected"] = True
                analysis["risk_level"] = "medium"
                analysis["alerts"].append({
                    "type": "unusual_time_access",
                    "message": f"Access at unusual time: {current_time.hour:02d}:00",
                    "severity": "medium"
                })
            
            # Frequency anomaly check
            avg_daily = baseline.get('avg_daily_activities', 10)
            today_count = await self._get_today_activity_count(user)
            if today_count > avg_daily * 2:
                analysis["anomaly_detected"] = True
                analysis["risk_level"] = "high"
                analysis["alerts"].append({
                    "type": "excessive_daily_access",
                    "message": f"Excessive access: {today_count} vs baseline {avg_daily}",
                    "severity": "high"
                })
        
        # Update risk score
        self.risk_scores[user] = self._calculate_dynamic_risk_score(user, analysis)
        
        return analysis
    
    async def _get_today_activity_count(self, user: str) -> int:
        """Get today's activity count for user"""
        today = datetime.utcnow().date()
        cursor = self.db.logs.find({
            "source": "odoo",
            "payload.user": user,
            "timestamp": {"$gte": datetime.combine(today, datetime.min.time())}
        })
        
        count = 0
        async for _ in cursor:
            count += 1
        
        return count
    
    def _calculate_dynamic_risk_score(self, user: str, analysis: Dict) -> float:
        """Calculate dynamic risk score based on current analysis"""
        base_score = self.risk_scores.get(user, 0.0)
        
        # Add anomaly penalties
        if analysis.get("anomaly_detected", False):
            base_score += 0.3
        
        # Add risk level penalties
        risk_level = analysis.get("risk_level", "normal")
        if risk_level == "high":
            base_score += 0.4
        elif risk_level == "medium":
            base_score += 0.2
        elif risk_level == "critical":
            base_score += 0.6
        
        # Decay score over time (recovery factor)
        return min(1.0, base_score * 0.95)  # 5% decay per cycle
    
    async def generate_user_report(self, user: str, days: int = 7) -> Dict:
        """Generate comprehensive user behavior report"""
        if user not in self.user_profiles:
            return {"error": "User profile not found"}
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        cursor = self.db.logs.find({
            "source": "odoo",
            "payload.user": user,
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }).sort("timestamp", -1)
        
        activities = []
        async for doc in cursor:
            activities.append(doc)
        
        profile = self.user_profiles[user]
        baseline = self.behavior_baseline.get(user, {})
        
        report = {
            "user": user,
            "report_period": f"{days} days",
            "generated_at": end_date.isoformat(),
            "summary": {
                "total_activities": len(activities),
                "risk_score": self.risk_scores.get(user, 0.0),
                "anomaly_count": len([a for a in activities if self._was_anomalous(user, a)]),
                "compliance_status": self._assess_compliance(profile, activities)
            },
            "profile": profile,
            "baseline": baseline,
            "recommendations": await self._generate_user_recommendations(user, activities),
            "detailed_activities": activities[-50:]  # Last 50 activities
        }
        
        return report
    
    def _was_anomalous(self, user: str, activity: Dict) -> bool:
        """Check if activity was flagged as anomalous"""
        # This would integrate with anomaly detection results
        # For now, use simple heuristics
        return False  # Would be populated by anomaly detector
    
    def _assess_compliance(self, profile: Dict, activities: List[Dict]) -> str:
        """Assess user compliance status"""
        if not profile or not activities:
            return "unknown"
        
        # Check for policy violations
        violations = 0
        
        # Check for unusual access times
        recent_activities = activities[-20:]  # Last 20 activities
        for activity in recent_activities:
            if 'timestamp' in activity:
                hour = datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')).hour
                if hour < 6 or hour > 18:  # Outside business hours
                    violations += 1
        
        # Check for excessive access
        if len(recent_activities) > 50:  # More than 50 recent activities
            violations += 1
        
        # Determine compliance status
        if violations == 0:
            return "compliant"
        elif violations <= 2:
            return "minor_violations"
        elif violations <= 5:
            return "moderate_violations"
        else:
            return "major_violations"
    
    async def _generate_user_recommendations(self, user: str, activities: List[Dict]) -> List[Dict]:
        """Generate personalized security recommendations"""
        recommendations = []
        
        # Analyze recent patterns
        recent_activities = activities[-20:]
        
        # Check for password security
        if any('login' in a.get('event_type', '') for a in recent_activities):
            recommendations.append({
                "type": "password_security",
                "priority": "high",
                "action": "Enable multi-factor authentication",
                "reason": "Login-based access detected"
            })
        
        # Check for access patterns
        access_times = [datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')).hour 
                      for a in recent_activities if 'timestamp' in a]
        
        if access_times:
            night_access = len([t for t in access_times if t < 6 or t > 22])
            if night_access > len(access_times) * 0.3:
                recommendations.append({
                    "type": "access_schedule",
                    "priority": "medium",
                    "action": "Review access schedule",
                    "reason": f"{night_access} night accesses detected"
                })
        
        return recommendations
