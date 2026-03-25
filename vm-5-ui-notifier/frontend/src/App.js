import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Circle } from 'react-leaflet';
import axios from 'axios';
import 'leaflet/dist/leaflet.css';
import './App.css';
import L from 'leaflet';
import DetailedAnalysis from './DetailedAnalysis';

// Fix for default marker icon
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

const API_BASE = '/api';

// Helper function to convert UTC to IST
const formatToIST = (utcTimestamp) => {
  const date = new Date(utcTimestamp);
  return date.toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
};

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [filter, setFilter] = useState({ severity: '', status: 'new' });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mapVisible, setMapVisible] = useState(true);
  const [showDetailedAnalysis, setShowDetailedAnalysis] = useState(null);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
    const interval = setInterval(() => {
      fetchAlerts();
      fetchStats();
    }, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [filter]);

  const fetchAlerts = async () => {
    try {
      const params = {};
      if (filter.severity) params.severity = filter.severity;
      if (filter.status) params.status = filter.status;
      
      const response = await axios.get(`${API_BASE}/alerts`, { params });
      setAlerts(response.data.alerts);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await axios.post(`${API_BASE}/alerts/${alertId}/acknowledge`, {
        acknowledged_by: 'analyst',
        notes: 'Acknowledged from dashboard'
      });
      fetchAlerts();
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      await axios.post(`${API_BASE}/alerts/${alertId}/resolve`, {
        resolved_by: 'analyst',
        notes: 'Resolved from dashboard'
      });
      fetchAlerts();
      setSelectedAlert(null);
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  const assignToSOC = (alert) => {
    // Placeholder for SOC assignment logic
    window.alert(`Assigning Alert #${alert.id} to SOC team...`);
    // In real implementation, this would open a modal or send to backend
  };

  const investigateFurther = (alert) => {
    // Open quick investigation panel
    setSelectedAlert(alert);
  };

  const openDetailedAnalysis = (alert) => {
    // Close quick panel if open
    setSelectedAlert(null);
    // Open full VirusTotal analysis
    setShowDetailedAnalysis(alert.id);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#10b981'
    };
    return colors[severity] || '#6b7280';
  };

  return (
    <div className="App">
      <header className="header">
        <div className="header-top">
          <div className="header-title">
            <h1>🛡️ Threat Intelligence Platform</h1>
          </div>
          <button className="map-toggle" onClick={() => setMapVisible(!mapVisible)}>
            {mapVisible ? '📊 Hide Map' : '🗺️ Show Map'}
          </button>
        </div>
        
        <div className="stats-grid">
          {stats && (
            <>
              <div className="stat-card">
                <div className="stat-label">Recent (1h)</div>
                <div className="stat-value">{stats.recent_1h}</div>
              </div>
              {stats.severity_counts.map(s => (
                <div key={s.severity} className="stat-card">
                  <div className="stat-label">{s.severity}</div>
                  <div className="stat-value" style={{color: getSeverityColor(s.severity)}}>
                    {s.count}
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </header>

      <div className="main-content">
        {mapVisible && (
          <div className="map-container">
            <MapContainer center={[20, 0]} zoom={2} style={{ height: '100%', width: '100%' }}>
              <TileLayer
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                attribution='&copy; <a href="https://carto.com/">CartoDB</a>'
              />
              {alerts.map((alert) => {
                if (!alert.latitude || !alert.longitude) return null;
                return (
                  <React.Fragment key={alert.id}>
                    <Circle
                      center={[alert.latitude, alert.longitude]}
                      radius={alert.risk_score * 1000}
                      pathOptions={{ 
                        color: getSeverityColor(alert.severity),
                        fillColor: getSeverityColor(alert.severity),
                        fillOpacity: 0.3
                      }}
                    />
                    <Marker 
                      position={[alert.latitude, alert.longitude]}
                      eventHandlers={{
                        click: () => setSelectedAlert(alert)
                      }}
                    >
                      <Popup>
                        <strong>{alert.site_name || 'Unknown Site'}</strong>
                        <br />
                        {alert.signature}
                        <br />
                        <span style={{color: getSeverityColor(alert.severity)}}>
                          {alert.severity.toUpperCase()}
                        </span>
                      </Popup>
                    </Marker>
                  </React.Fragment>
                );
              })}
            </MapContainer>
          </div>
        )}

        <div className={`sidebar ${!mapVisible ? 'expanded' : ''}`}>
          <div className="filters">
            <h3>🔍 Filters</h3>
            <div className="filter-group">
              <select 
                value={filter.severity} 
                onChange={(e) => setFilter({...filter, severity: e.target.value})}
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select 
                value={filter.status} 
                onChange={(e) => setFilter({...filter, status: e.target.value})}
              >
                <option value="">All Statuses</option>
                <option value="new">New</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>

          <div className="alerts-list">
            <h3>🚨 Security Alerts ({alerts.length})</h3>
            {loading ? (
              <div className="loading">Loading alerts...</div>
            ) : alerts.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">✓</div>
                <p>No alerts found</p>
              </div>
            ) : (
              alerts.map((alert) => (
                <div 
                  key={alert.id} 
                  className="alert-item"
                  style={{ borderLeftColor: getSeverityColor(alert.severity) }}
                >
                  <div className="alert-header">
                    <span className={`severity-badge severity-${alert.severity}`}>
                      {alert.severity}
                    </span>
                    <span className="time">{formatToIST(alert.timestamp)}</span>
                  </div>
                  <div className="alert-signature">{alert.signature}</div>
                  <div className="alert-details">
                    <strong>Source:</strong> {alert.src_ip} → <strong>Target:</strong> {alert.site_name || alert.dest_ip}
                  </div>
                  <div className="alert-actions">
                    <button 
                      className="btn-action btn-investigate"
                      onClick={() => investigateFurther(alert)}
                    >
                      🔍 Investigate
                    </button>
                    <button 
                      className="btn-action btn-assign"
                      onClick={() => assignToSOC(alert)}
                    >
                      👥 Assign to SOC
                    </button>
                  </div>
                  <div className="alert-actions" style={{marginTop: '0.5rem'}}>
                    <button 
                      className="btn-action"
                      onClick={() => openDetailedAnalysis(alert)}
                      style={{
                        background: 'linear-gradient(135deg, #8b5cf6, #6366f1)',
                        color: 'white',
                        width: '100%'
                      }}
                    >
                      🔬 Detailed Analysis
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {selectedAlert && (
        <div className="alert-detail">
          <h3>Alert Investigation</h3>
          <button className="close-btn" onClick={() => setSelectedAlert(null)}>×</button>

          <div className="detail-section">
            <strong>Alert ID</strong>
            <div className="detail-section-content">#{selectedAlert.id}</div>
          </div>

          <div className="detail-section">
            <strong>Signature</strong>
            <div className="detail-section-content">{selectedAlert.signature}</div>
          </div>
          
          <div className="detail-section">
            <strong>Severity</strong>
            <div className="detail-section-content">
              <span className={`severity-badge severity-${selectedAlert.severity}`}>
                {selectedAlert.severity.toUpperCase()}
              </span>
            </div>
          </div>
          
          <div className="detail-section">
            <strong>Risk Score</strong>
            <div className="detail-section-content">{selectedAlert.risk_score}/100</div>
          </div>
          
          <div className="detail-section">
            <strong>Attack Source</strong>
            <div className="detail-section-content">
              {selectedAlert.src_ip}:{selectedAlert.src_port}
            </div>
          </div>
          
          <div className="detail-section">
            <strong>Target</strong>
            <div className="detail-section-content">
              {selectedAlert.dest_ip}:{selectedAlert.dest_port}<br/>
              <small>{selectedAlert.site_name || 'Unknown Location'}</small>
            </div>
          </div>
          
          <div className="detail-section">
            <strong>Protocol</strong>
            <div className="detail-section-content">{selectedAlert.protocol}</div>
          </div>
          
          <div className="detail-section">
            <strong>Timestamp</strong>
            <div className="detail-section-content">
              {formatToIST(selectedAlert.timestamp)}
            </div>
          </div>
          
          <div className="actions">
            <button 
              className="btn"
              onClick={() => openDetailedAnalysis(selectedAlert)}
              style={{
                background: 'linear-gradient(135deg, #8b5cf6, #6366f1)',
                color: 'white',
                gridColumn: '1 / -1'
              }}
            >
              🔬 Detailed Analysis
            </button>
            {selectedAlert.status === 'new' && (
              <button 
                className="btn btn-acknowledge"
                onClick={() => acknowledgeAlert(selectedAlert.id)}
              >
                ✓ Acknowledge
              </button>
            )}
            {selectedAlert.status !== 'resolved' && (
              <button 
                className="btn btn-resolve"
                onClick={() => resolveAlert(selectedAlert.id)}
              >
                ✓ Resolve
              </button>
            )}
          </div>
        </div>
      )}

      {showDetailedAnalysis && (
        <DetailedAnalysis 
          alertId={showDetailedAnalysis} 
          onClose={() => setShowDetailedAnalysis(null)}
        />
      )}
    </div>
  );
}

export default App;
