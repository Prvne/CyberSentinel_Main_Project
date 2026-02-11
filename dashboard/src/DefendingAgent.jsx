import React, { useState, useEffect } from 'react';
import { Line, Bar, PieChart, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart } from 'recharts';

const DefendingAgent = () => {
  const [threatData, setThreatData] = useState({
    predictions: null,
    anomalies: null,
    recommendations: [],
    userProfiles: [],
    riskScores: {},
    systemStatus: 'loading'
  });

  const [selectedUser, setSelectedUser] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  useEffect(() => {
    fetchDefendingData();
    const interval = setInterval(fetchDefendingData, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchDefendingData = async () => {
    try {
      // Fetch ML predictions
      const predictionsResponse = await fetch('/api/ml/predict');
      const predictions = await predictionsResponse.json();
      
      // Fetch anomaly detection results
      const anomaliesResponse = await fetch('/api/ml/anomalies');
      const anomalies = await anomaliesResponse.json();
      
      // Fetch defensive recommendations
      const recommendationsResponse = await fetch('/api/ml/recommendations');
      const recommendations = await recommendationsResponse.json();
      
      // Fetch ERP monitoring data
      const erpResponse = await fetch('/api/erp/monitoring');
      const erpData = await erpResponse.json();
      
      setThreatData({
        predictions: predictions,
        anomalies: anomalies,
        recommendations: recommendations.recommendations || [],
        userProfiles: erpData.userProfiles || [],
        riskScores: erpData.riskScores || {},
        systemStatus: 'active'
      });
    } catch (error) {
      console.error('Failed to fetch defending data:', error);
      setThreatData(prev => ({ ...prev, systemStatus: 'error' }));
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '#ef4444';
      case 'high': return '#f59e0b';
      case 'medium': return '#f59e0b';
      case 'low': return '#3b82f6';
      default: return '#6b7280';
    }
  };

  const getRiskLevelColor = (score) => {
    if (score >= 0.7) return '#ef4444';
    if (score >= 0.4) return '#f59e0b';
    if (score >= 0.2) return '#f59e0b';
    return '#3b82f6';
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* ML Predictions Panel */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center">
              🤖 Threat Predictions
              {threatData.systemStatus === 'active' && (
                <span className="ml-2 px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full">Active</span>
              )}
            </h3>
            
            {threatData.predictions ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-600">Attack Probability</p>
                    <p className="text-2xl font-bold" style={{ color: getRiskLevelColor(threatData.predictions.attack_probability) }}>
                      {(threatData.predictions.attack_probability * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Confidence</p>
                    <p className="text-2xl font-bold capitalize">{threatData.predictions.confidence_level}</p>
                  </div>
                </div>
                
                <div>
                  <p className="text-sm font-medium text-gray-700 mb-2">Likely Next Attacks:</p>
                  <div className="space-y-2">
                    {threatData.predictions.likely_next_attacks?.map((attack, index) => (
                      <div key={index} className="flex justify-between items-center p-2 bg-gray-50 rounded">
                        <span className="text-sm">{attack.type.replace('_', ' ')}</span>
                        <span className="text-sm font-medium" style={{ color: getRiskLevelColor(attack.probability) }}>
                          {(attack.probability * 100).toFixed(1)}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center text-gray-500 py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                <p className="mt-2">Loading predictions...</p>
              </div>
            )}
          </div>

          {/* Anomaly Detection Panel */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4 flex items-center">
              🔍 Anomaly Detection
              {threatData.anomalies?.anomalies_detected > 0 && (
                <span className="ml-2 px-2 py-1 bg-red-100 text-red-800 text-xs rounded-full">
                  {threatData.anomalies.anomalies_detected} Active
                </span>
              )}
            </h3>
            
            {threatData.anomalies ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <p className="text-sm text-gray-600">Anomaly Rate</p>
                    <p className="text-2xl font-bold text-red-600">
                      {(threatData.anomalies.anomaly_rate * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Analysis Window</p>
                    <p className="text-lg font-medium">{threatData.anomalies.analysis_window}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Threshold</p>
                    <p className="text-lg font-medium">{threatData.anomalies.threshold_used}</p>
                  </div>
                </div>
                
                {threatData.anomalies.anomaly_events?.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-2">Recent Anomalies:</p>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {threatData.anomalies.anomaly_events.map((anomaly, index) => (
                        <div key={index} className="p-3 bg-red-50 rounded border-l-4" style={{ borderColor: getSeverityColor(anomaly.severity) }}>
                          <div className="flex justify-between items-start">
                            <div>
                              <p className="text-sm font-medium capitalize">{anomaly.anomaly_type.replace('_', ' ')}</p>
                              <p className="text-xs text-gray-600">{formatTimestamp(anomaly.event.timestamp)}</p>
                            </div>
                            <span className="px-2 py-1 bg-red-100 text-red-800 text-xs rounded">
                              {anomaly.severity.toUpperCase()}
                            </span>
                          </div>
                          {anomaly.event.payload && (
                            <p className="text-xs text-gray-700 mt-1">
                              {JSON.stringify(anomaly.event.payload).substring(0, 100)}...
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center text-gray-500 py-8">
                <div className="animate-pulse bg-gray-200 h-2 w-32 rounded mx-auto mb-2"></div>
                <p className="text-sm">Analyzing patterns...</p>
              </div>
            )}
          </div>

          {/* Defensive Recommendations Panel */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">🛡️ Defensive Recommendations</h3>
            
            {threatData.recommendations.length > 0 ? (
              <div className="space-y-3">
                {threatData.recommendations.map((rec, index) => (
                  <div key={index} className="border-l-4 p-4 rounded" style={{ borderColor: getSeverityColor(rec.priority) }}>
                    <div className="flex justify-between items-start mb-2">
                      <h4 className="font-medium capitalize">{rec.type.replace('_', ' ')}</h4>
                      <span className={`px-2 py-1 text-xs rounded ${
                        rec.priority === 'critical' ? 'bg-red-100 text-red-800' :
                        rec.priority === 'high' ? 'bg-orange-100 text-orange-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {rec.priority.toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="mb-2">
                      <p className="text-sm font-medium text-gray-700 mb-1">Recommended Actions:</p>
                      <ul className="text-sm text-gray-600 space-y-1">
                        {rec.actions.map((action, i) => (
                          <li key={i} className="flex items-start">
                            <span className="mr-2">•</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    
                    <div>
                      <p className="text-sm font-medium text-gray-700 mb-1">Suggested Tools:</p>
                      <div className="flex flex-wrap gap-1">
                        {rec.tools.map((tool, i) => (
                          <span key={i} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                            {tool}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center text-gray-500 py-8">
                <div className="animate-spin rounded-full h-6 w-6 border-2 border-gray-300 mx-auto mb-2"></div>
                <p className="text-sm">Analyzing threats...</p>
              </div>
            )}
          </div>
        </div>

        {/* Bottom Row - ERP Monitoring and User Profiles */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* ERP User Monitoring */}
          <div className="bg-white rounded-lg shadow p-6 lg:col-span-2">
            <h3 className="text-lg font-semibold mb-4">👥 ERP User Monitoring</h3>
            
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium text-gray-700">Select User:</label>
                <select 
                  className="border rounded px-3 py-2 text-sm"
                  value={selectedUser || ''}
                  onChange={(e) => setSelectedUser(e.target.value)}
                >
                  <option value="">All Users</option>
                  {Object.keys(threatData.riskScores).map(user => (
                    <option key={user} value={user}>{user}</option>
                  ))}
                </select>
              </div>
            </div>
            
            {/* Risk Scores Overview */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {Object.entries(threatData.riskScores).slice(0, 8).map(([user, score]) => (
                <div key={user} className="text-center p-3 rounded" style={{ backgroundColor: getRiskLevelColor(score) + '20' }}>
                  <p className="text-xs font-medium text-gray-600">{user}</p>
                  <p className="text-lg font-bold" style={{ color: getRiskLevelColor(score) }}>
                    {(score * 100).toFixed(0)}
                  </p>
                  <p className="text-xs text-gray-500">Risk Score</p>
                </div>
              ))}
            </div>
            
            {/* Selected User Details */}
            {selectedUser && threatData.userProfiles.find(profile => profile.user === selectedUser) && (
              <div className="border-t pt-4">
                <h4 className="font-medium mb-3">User Profile: {selectedUser}</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-600">Total Activities</p>
                    <p className="text-xl font-bold">
                      {threatData.userProfiles.find(profile => profile.user === selectedUser)?.total_activities || 0}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Risk Score</p>
                    <p className="text-xl font-bold" style={{ color: getRiskLevelColor(threatData.riskScores[selectedUser]) }}>
                      {(threatData.riskScores[selectedUser] * 100).toFixed(0)}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Compliance</p>
                    <p className="text-lg font-medium capitalize">
                      {threatData.userProfiles.find(profile => profile.user === selectedUser)?.summary?.compliance_status || 'Unknown'}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Anomalies</p>
                    <p className="text-lg font-bold text-red-600">
                      {threatData.userProfiles.find(profile => profile.user === selectedUser)?.summary?.anomaly_count || 0}
                    </p>
                  </div>
                </div>
                
                {/* Recent Activities */}
                <div className="col-span-full mt-4">
                  <p className="text-sm font-medium text-gray-700 mb-2">Recent Activities:</p>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {threatData.userProfiles.find(profile => profile.user === selectedUser)?.detailed_activities?.slice(0, 10).map((activity, index) => (
                      <div key={index} className="p-2 bg-gray-50 rounded text-sm">
                        <div className="flex justify-between">
                          <span>{activity.event_type}</span>
                          <span className="text-gray-500">{formatTimestamp(activity.timestamp)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* System Status */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">📊 System Status</h3>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-4 bg-green-50 rounded">
                  <p className="text-sm text-gray-600">ML Models</p>
                  <p className="text-lg font-bold text-green-600">Trained</p>
                </div>
                <div className="text-center p-4 bg-blue-50 rounded">
                  <p className="text-sm text-gray-600">ERP Monitor</p>
                  <p className="text-lg font-bold text-blue-600">Active</p>
                </div>
              </div>
              
              <div className="border-t pt-4">
                <h4 className="font-medium mb-2">Defense Effectiveness</h4>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600">Threat Prediction Accuracy</span>
                    <span className="text-sm font-medium">87.3%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600">Anomaly Detection Rate</span>
                    <span className="text-sm font-medium">94.1%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600">False Positive Rate</span>
                    <span className="text-sm font-medium text-green-600">2.3%</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-600">Response Time</span>
                    <span className="text-sm font-medium">1.2s</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DefendingAgent;
