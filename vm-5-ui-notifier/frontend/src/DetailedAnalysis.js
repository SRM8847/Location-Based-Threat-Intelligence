import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './DetailedAnalysis.css';

function DetailedAnalysis({ alertId, onClose }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAnalysis();
  }, [alertId]);

  const fetchAnalysis = async () => {
    try {
      const response = await axios.get(`/api/alerts/${alertId}/detailed-analysis`);
      setAnalysis(response.data);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const getThreatLevel = (malicious, suspicious) => {
    const total = malicious + suspicious;
    if (total === 0) return { level: 'Safe', color: '#10b981' };
    if (malicious > 5) return { level: 'Critical Threat', color: '#dc2626' };
    if (malicious > 0) return { level: 'Malicious', color: '#ea580c' };
    if (suspicious > 0) return { level: 'Suspicious', color: '#f59e0b' };
    return { level: 'Unknown', color: '#6b7280' };
  };

  if (loading) {
    return (
      <div className="analysis-overlay">
        <div className="analysis-container">
          <div className="loading-spinner">🔄 Loading detailed analysis...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="analysis-overlay">
        <div className="analysis-container">
          <button className="close-analysis" onClick={onClose}>×</button>
          <div className="error-message">❌ Error: {error}</div>
        </div>
      </div>
    );
  }

  const threat = getThreatLevel(
    analysis.reputation?.malicious_count || 0,
    analysis.reputation?.suspicious_count || 0
  );

  return (
    <div className="analysis-overlay">
      <div className="analysis-container">
        <button className="close-analysis" onClick={onClose}>×</button>
        
        <div className="analysis-header">
          <h1>🔬 Detailed Threat Analysis</h1>
          <div className="threat-indicator" style={{ background: threat.color }}>
            {threat.level}
          </div>
        </div>

        {/* IP Overview */}
        <div className="analysis-section">
          <h2>🌐 IP Address Information</h2>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Source IP</span>
              <span className="info-value">{analysis.src_ip}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Destination IP</span>
              <span className="info-value">{analysis.dest_ip}</span>
            </div>
          </div>
        </div>

        {/* Geolocation */}
        <div className="analysis-section">
          <h2>📍 Geolocation</h2>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Country</span>
              <span className="info-value">{analysis.geolocation?.country || 'Unknown'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Continent</span>
              <span className="info-value">{analysis.geolocation?.continent || 'Unknown'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">RIR</span>
              <span className="info-value">{analysis.geolocation?.regional_internet_registry || 'Unknown'}</span>
            </div>
          </div>
        </div>

        {/* Network Information */}
        <div className="analysis-section">
          <h2>🌐 Network Information</h2>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">ASN</span>
              <span className="info-value">{analysis.network?.asn || 'N/A'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">AS Owner</span>
              <span className="info-value">{analysis.network?.as_owner || 'Unknown'}</span>
            </div>
            <div className="info-item full-width">
              <span className="info-label">Network Range</span>
              <span className="info-value">{analysis.network?.network || 'Unknown'}</span>
            </div>
          </div>
        </div>

        {/* Reputation Analysis */}
        <div className="analysis-section">
          <h2>⚠️ Threat Reputation</h2>
          <div className="reputation-score">
            <div className="score-circle" style={{ borderColor: threat.color }}>
              <span className="score-value">{analysis.reputation?.reputation_score || 0}</span>
              <span className="score-label">Reputation</span>
            </div>
          </div>
          
          <div className="detection-stats">
            <div className="stat-item critical">
              <span className="stat-number">{analysis.reputation?.malicious_count || 0}</span>
              <span className="stat-label">Malicious</span>
            </div>
            <div className="stat-item warning">
              <span className="stat-number">{analysis.reputation?.suspicious_count || 0}</span>
              <span className="stat-label">Suspicious</span>
            </div>
            <div className="stat-item safe">
              <span className="stat-number">{analysis.reputation?.harmless_count || 0}</span>
              <span className="stat-label">Harmless</span>
            </div>
            <div className="stat-item neutral">
              <span className="stat-number">{analysis.reputation?.undetected_count || 0}</span>
              <span className="stat-label">Undetected</span>
            </div>
          </div>
        </div>

        {/* Tags */}
        {analysis.tags && analysis.tags.length > 0 && (
          <div className="analysis-section">
            <h2>🏷️ Tags</h2>
            <div className="tags-container">
              {analysis.tags.map((tag, idx) => (
                <span key={idx} className="tag">{tag}</span>
              ))}
            </div>
          </div>
        )}

        {/* WHOIS */}
        <div className="analysis-section">
          <h2>📋 WHOIS Information</h2>
          <div className="whois-container">
            <pre>{analysis.whois || 'No WHOIS data available'}</pre>
          </div>
        </div>

        {/* Our Enrichment */}
        {analysis.our_enrichment && (
          <div className="analysis-section">
            <h2>🔍 Our Enrichment Data</h2>
            <div className="json-container">
              <pre>{JSON.stringify(analysis.our_enrichment, null, 2)}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default DetailedAnalysis;
