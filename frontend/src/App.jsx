
import { useCallback, useEffect, useState } from "react";
import "./App.css";

const API = "http://localhost:5000";

// Support common IP field names returned by different APIs.
function getIp(threat) {
  return (
    threat.ip_address ??
    threat.source_ip ??
    threat.src_ip ??
    threat.client_ip ??
    threat.remote_ip ??
    threat.ip ??
    threat.ipAddress ??
    threat.sourceIp ??
    threat.srcIp ??
    "IP unavailable"
  );
}

// Read the threat classification from the API response.
function getThreatType(threat) {
  return (
    threat.threat_type ??
    threat.classification ??
    threat.attack_type ??
    threat.threat_classification ??
    threat.threatType ??
    "Suspicious activity"
  );
}

// Keep risk scores within the 0–100 range.
function getRisk(threat) {
  const value = Number(threat.risk_score ?? threat.riskScore ?? 0);

  return Number.isFinite(value)
    ? Math.max(0, Math.min(100, value))
    : 0;
}

function getSeverity(score) {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

function App() {
  const [threats, setThreats] = useState([]);
  const [status, setStatus] = useState("Connecting");
  const [lastUpdated, setLastUpdated] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  // Fetch threat records from the Express API.
  const loadThreats = useCallback(async () => {
    setRefreshing(true);

    try {
      const response = await fetch(`${API}/api/threats`);

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const data = await response.json();

      const records = Array.isArray(data)
        ? data
        : Array.isArray(data.threats)
          ? data.threats
          : Array.isArray(data.data)
            ? data.data
            : [];

      setThreats(records);
      setStatus("Connected");
      setError("");
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      setStatus("Backend unavailable");
      setError(err.message || "Could not connect to the API.");
    } finally {
      setRefreshing(false);
    }
  }, []);

 
  useEffect(() => {
    const initialFetch = setTimeout(() => {
      loadThreats();
    }, 0);

    const timer = setInterval(() => {
      loadThreats();
    }, 10000);

    return () => {
      clearTimeout(initialFetch);
      clearInterval(timer);
    };
  }, [loadThreats]);

  // Dashboard calculations.
  const critical = threats.filter(
    (threat) => getRisk(threat) >= 85
  ).length;

  const highRisk = threats.filter(
    (threat) =>
      getRisk(threat) >= 65 && getRisk(threat) < 85
  ).length;

  const failedLogins = threats.reduce(
    (sum, threat) =>
      sum +
      Math.max(
        0,
        Number(
          threat.failed_logins ??
            threat.failedLogins ??
            0
        )
      ),
    0
  );

  const classifications = new Set(
    threats.map(getThreatType)
  ).size;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon">◈</span>

          <div>
            <h2>Sentinel SIEM</h2>
            <small>THREAT INTELLIGENCE</small>
          </div>
        </div>

        <p className="nav-heading">WORKSPACE</p>

        <div className="nav-item active">
          <span>▦</span> Security Overview
        </div>

        <div className="nav-item">
          <span>⌁</span> Login Analytics
        </div>

        <div className="nav-item">
          <span>⚠</span> Threat Detection
        </div>

        <div className="nav-item">
          <span>▤</span> Audit Events
        </div>

        <div className="sidebar-bottom">
          <span className="status-dot" />
          Hadoop Analytics
          <small>HDFS · Spark · Hive</small>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">
              SECURITY OPERATIONS CENTER
            </p>

            <h1>Security Overview</h1>

            <p className="subtitle">
              Monitor authentication activity and suspicious login patterns.
            </p>
          </div>

          <div className="connection">
            <span
              className={`status-dot ${
                status !== "Connected" ? "offline" : ""
              }`}
            />
            {status}
          </div>
        </header>

        <section className="welcome">
          <div>
            <p className="eyebrow">
              LIVE SECURITY MONITORING
            </p>

            <h2>Threat intelligence at a glance</h2>

            <p>
              Analyze authentication patterns through your Hadoop analytics
              pipeline.
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={loadThreats}
            disabled={refreshing}
          >
            {refreshing ? "↻ Loading..." : "↻ Refresh data"}
          </button>
        </section>

        {error && (
          <div className="error-banner">
            <strong>Connection issue:</strong> {error}

            <button onClick={loadThreats}>
              Retry
            </button>
          </div>
        )}

        <section className="metrics">
          <article className="metric-card">
            <span className="metric-label">
              DETECTED THREATS
            </span>

            <strong>{threats.length}</strong>

            <span className="metric-note">
              Records returned by the API
            </span>
          </article>

          <article className="metric-card danger">
            <span className="metric-label">
              CRITICAL RISK
            </span>

            <strong>{critical}</strong>

            <span className="metric-note">
              Risk score ≥ 85
            </span>
          </article>

          <article className="metric-card warning-card">
            <span className="metric-label">
              HIGH-RISK EVENTS
            </span>

            <strong>{highRisk}</strong>

            <span className="metric-note">
              Risk score 65–84
            </span>
          </article>

          <article className="metric-card">
            <span className="metric-label">
              FAILED LOGINS
            </span>

            <strong>{failedLogins}</strong>

            <span className="metric-note">
              Sum across returned threat records
            </span>
          </article>
        </section>

        <section className="insight-row">
          <div className="insight-card">
            <span className="insight-icon">⌘</span>

            <div>
              <span className="metric-label">
                THREAT CATEGORIES
              </span>

              <strong>{classifications}</strong>

              <p>
                Distinct classifications in current results
              </p>
            </div>
          </div>

          <div className="insight-card">
            <span className="insight-icon">◷</span>

            <div>
              <span className="metric-label">
                LAST API UPDATE
              </span>

              <strong className="update-value">
                {lastUpdated || "Waiting..."}
              </strong>

              <p>Automatic refresh interval: 10 seconds</p>
            </div>
          </div>

          <div className="insight-card">
            <span className="insight-icon">⌘</span>

            <div>
              <span className="metric-label">
                ANALYTICS CONNECTION
              </span>

              <strong className="online-value">
                {status === "Connected" ? "ONLINE" : "CHECK"}
              </strong>

              <p>React → Express API → Hive results</p>
            </div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">
                THREAT INTELLIGENCE
              </p>

              <h2>Suspicious IP Activity</h2>

              <p>
                Authentication patterns returned by the analytics pipeline.
              </p>
            </div>

            <span className="table-count">
              {threats.length} records
            </span>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>SOURCE IP</th>
                  <th>THREAT CLASSIFICATION</th>
                  <th>FAILED LOGINS</th>
                  <th>RISK SCORE</th>
                  <th>SEVERITY</th>
                </tr>
              </thead>

              <tbody>
                {threats.map((threat, index) => {
                  const score = getRisk(threat);
                  const ipAddress = getIp(threat);
                  const threatType = getThreatType(threat);
                  const severity = getSeverity(score);

                  return (
                    <tr
                      key={`${ipAddress}-${threatType}-${index}`}
                    >
                      <td className="ip">
                        {ipAddress}
                      </td>

                      <td>
                        <span className="threat-type">
                          {threatType.replaceAll("_", " ")}
                        </span>
                      </td>

                      <td>
                        {Number(
                          threat.failed_logins ??
                            threat.failedLogins ??
                            0
                        )}
                      </td>

                      <td>
                        <div className="risk-cell">
                          <div className="risk-track">
                            <div
                              className={`risk-fill ${
                                score >= 85
                                  ? "high"
                                  : score >= 65
                                    ? "elevated"
                                    : ""
                              }`}
                              style={{
                                width: `${score}%`,
                              }}
                            />
                          </div>

                          <b>{score}</b>
                        </div>
                      </td>

                      <td>
                        <span
                          className={`severity ${severity.toLowerCase()}`}
                        >
                          {severity}
                        </span>
                      </td>
                    </tr>
                  );
                })}

                {threats.length === 0 && (
                  <tr>
                    <td colSpan="5" className="empty">
                      {status === "Connected"
                        ? "No threat records were returned by the API."
                        : "Waiting for the backend. Check that port 5000 is running."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <p className="footnote">
            Classifications are indicators of suspicious patterns, not proof
            of a confirmed attack. The dashboard displays records returned by
            the API and does not create additional detections by itself.
          </p>
        </section>

        <footer>
          <span>
            SIEM Login Threat &amp; Anomaly Analyzer
          </span>

          <span>React · HDFS · Spark · Hive</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
