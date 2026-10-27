import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = (
  import.meta.env.VITE_API_URL || "http://localhost:5000"
).replace(/\/$/, "");

const THREATS_ENDPOINT = `${API_BASE}/api/threats`;
const REFRESH_INTERVAL = 15000;



function firstValue(record, keys, fallback = null) {
  for (const key of keys) {
    const value = record?.[key];
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return fallback;
}

function toNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function normalizeThreat(record, index) {
  const ip = firstValue(
    record,
    ["source_ip", "sourceIp", "src_ip", "ip", "src", "client_ip"],
    "Unknown IP"
  );

  const classification = firstValue(
    record,
    [
      "classification",
      "threat_classification",
      "threat_type",
      "threatType",
      "attack_type",
      "category",
      "label",
      "event_type",
    ],
    "UNCLASSIFIED_ACTIVITY"
  );

  const risk = Math.max(
    0,
    Math.min(
      100,
      toNumber(
        firstValue(record, ["risk_score", "riskScore", "risk", "score"], 0)
      )
    )
  );

  const failedLogins = toNumber(
    firstValue(
      record,
      [
        "failed_logins",
        "failed_login_count",
        "failure_count",
        "failed_attempts",
        "failures",
      ],
      0
    )
  );

  const successfulLogins = toNumber(
    firstValue(
      record,
      ["successful_logins", "success_count", "successful_attempts"],
      0
    )
  );

  const distinctUsers = toNumber(
    firstValue(
      record,
      ["distinct_users", "unique_users", "user_count", "users_targeted"],
      0
    )
  );

  const suppliedSeverity = String(
    firstValue(record, ["severity", "risk_level", "level"], "")
  ).toUpperCase();

  let severity = suppliedSeverity;

  if (!["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity)) {
    severity =
      risk >= 85 ? "CRITICAL" : risk >= 65 ? "HIGH" : risk >= 35 ? "MEDIUM" : "LOW";
  }

  const reasons = firstValue(
    record,
    ["detection_reasons", "reasons", "evidence", "description", "details"],
    []
  );

  const reasonList = Array.isArray(reasons)
    ? reasons.map(String)
    : reasons
      ? [String(reasons)]
      : [];

  return {
    ...record,
    id: String(
      firstValue(record, ["id", "event_id", "record_id", "source_id"], `${ip}-${index}`)
    ),
    sourceIp: String(ip),
    classification: String(classification),
    riskScore: risk,
    severity,
    failedLogins,
    successfulLogins,
    distinctUsers,
    timestamp: firstValue(
      record,
      ["last_seen", "timestamp", "event_time", "last_event", "updated_at"],
      null
    ),
    reasons: reasonList,
    raw: record,
  };
}

function formatClassification(value) {
  return String(value || "Unknown")
    .replace(/_+/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function formatDate(value) {
  if (!value) return "Not provided";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}

function getSeverityClass(severity) {
  return String(severity || "LOW").toLowerCase();
}

function getConnectionMessage(loading, error) {
  if (loading) return "Connecting to API";
  if (error) return "API connection issue";
  return "Express API online";
}

function App() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [classificationFilter, setClassificationFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("riskScore");
  const [sortDirection, setSortDirection] = useState("desc");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);

  const fetchThreats = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const response = await fetch(THREATS_ENDPOINT, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}`);
      }

      const payload = await response.json();

      // Support APIs that return an array or an object containing an array.
      const records = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.threats)
          ? payload.threats
          : Array.isArray(payload?.data)
            ? payload.data
            : Array.isArray(payload?.results)
              ? payload.results
              : null;

      if (!records) {
        throw new Error(
          "Unexpected API response. Expected an array of threat records."
        );
      }

      setThreats(records.map(normalizeThreat));
      setError("");
      setLastUpdated(new Date());
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to connect to the Express API."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

 useEffect(() => {
  let cancelled = false;

  const loadData = async () => {
    if (cancelled) return;
    await fetchThreats();
  };

  void loadData();

  if (!autoRefresh) {
    return () => {
      cancelled = true;
    };
  }

  const timer = window.setInterval(() => {
    if (!cancelled) {
      void fetchThreats();
    }
  }, REFRESH_INTERVAL);

  return () => {
    cancelled = true;
    window.clearInterval(timer);
  };
}, [fetchThreats, autoRefresh]);

  const metrics = useMemo(() => {
    const detected = threats.filter(
      (threat) => threat.riskScore >= 35
    ).length;

    const critical = threats.filter(
      (threat) => threat.severity === "CRITICAL"
    ).length;

    const riskEvents = threats.filter(
      (threat) => threat.riskScore >= 65
    ).length;

    const failed = threats.reduce(
      (total, threat) => total + threat.failedLogins,
      0
    );

    return { detected, critical, riskEvents, failed };
  }, [threats]);

  const classificationCounts = useMemo(() => {
    const counts = new Map();

    threats.forEach((threat) => {
      const name = threat.classification;
      counts.set(name, (counts.get(name) || 0) + 1);
    });

    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [threats]);

  const availableClassifications = useMemo(
    () => [...new Set(threats.map((threat) => threat.classification))].sort(),
    [threats]
  );

  const filteredThreats = useMemo(() => {
    const search = query.trim().toLowerCase();

    const result = threats.filter((threat) => {
      const matchesSearch =
        !search ||
        threat.sourceIp.toLowerCase().includes(search) ||
        threat.classification.toLowerCase().includes(search) ||
        threat.severity.toLowerCase().includes(search) ||
        threat.reasons.some((reason) => reason.toLowerCase().includes(search));

      const matchesSeverity =
        severityFilter === "ALL" || threat.severity === severityFilter;

      const matchesClassification =
        classificationFilter === "ALL" ||
        threat.classification === classificationFilter;

      return matchesSearch && matchesSeverity && matchesClassification;
    });

    result.sort((a, b) => {
      let first = a[sortBy];
      let second = b[sortBy];

      if (sortBy === "timestamp") {
        first = first ? new Date(first).getTime() || 0 : 0;
        second = second ? new Date(second).getTime() || 0 : 0;
      }

      if (typeof first === "number" && typeof second === "number") {
        return sortDirection === "asc" ? first - second : second - first;
      }

      const comparison = String(first ?? "").localeCompare(
        String(second ?? ""),
        undefined,
        { numeric: true, sensitivity: "base" }
      );

      return sortDirection === "asc" ? comparison : -comparison;
    });

    return result;
  }, [
    threats,
    query,
    severityFilter,
    classificationFilter,
    sortBy,
    sortDirection,
  ]);

  function handleSort(field) {
    if (sortBy === field) {
      setSortDirection((direction) => (direction === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(field);
      setSortDirection(field === "sourceIp" || field === "classification" ? "asc" : "desc");
    }
  }

  function resetFilters() {
    setQuery("");
    setSeverityFilter("ALL");
    setClassificationFilter("ALL");
    setSortBy("riskScore");
    setSortDirection("desc");
  }

  const connectionOnline = !loading && !error;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <svg viewBox="0 0 32 32" aria-hidden="true">
              <path d="M16 3 27 7v8c0 7-4.6 11.6-11 14C9.6 26.6 5 22 5 15V7l11-4Z" />
              <path d="m10.5 16 3.5 3.5 7.5-8" />
            </svg>
          </div>
          <div>
            <div className="brand-title">SENTINEL</div>
            <div className="brand-subtitle">SECURITY INTELLIGENCE</div>
          </div>
        </div>

        <div className="nav-section-label">WORKSPACE</div>
        <nav className="sidebar-nav" aria-label="Main navigation">
          <a className="nav-link active" href="#overview">
            <span className="nav-icon">◈</span>
            Overview
          </a>
          <a className="nav-link" href="#threats">
            <span className="nav-icon">⌁</span>
            Threat explorer
            <span className="nav-count">{threats.length}</span>
          </a>
          <a className="nav-link" href="#classifications">
            <span className="nav-icon">▤</span>
            Classifications
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="environment-label">ENVIRONMENT</div>
          <div className="environment-value">
            <span className={`status-dot ${connectionOnline ? "" : "offline"}`} />
            {connectionOnline ? "Monitoring active" : loading ? "Connecting…" : "Connection issue"}
          </div>
          <p>Local analytics environment</p>
          <div className="sidebar-version">SIEM CONSOLE · V1.0</div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="breadcrumb-separator">/</span>
            <strong>Security overview</strong>
          </div>
          <div className="topbar-right">
            <span className="local-badge">
              <span className={`status-dot ${connectionOnline ? "" : "offline"}`} />
              {connectionOnline ? "SYSTEM ONLINE" : loading ? "CONNECTING" : "DEGRADED"}
            </span>
            <div className="avatar" title="Local analyst">SA</div>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>Threat monitoring</h1>
            <p className="page-subtitle">
              Authentication activity, suspicious sources and analytics insights.
            </p>
          </div>
          <button
            className="button button-primary"
            type="button"
            onClick={() => fetchThreats(true)}
            disabled={refreshing}
          >
            <span className={refreshing ? "refresh-icon spinning" : "refresh-icon"}>↻</span>
            {refreshing ? "Refreshing…" : "Refresh now"}
          </button>
        </section>

        <section className="status-strip" aria-label="Service status">
          <div className="status-item">
            <span className={`status-indicator ${connectionOnline ? "online" : "offline"}`} />
            <div>
              <span className="status-label">EXPRESS API</span>
              <strong>{getConnectionMessage(loading, error)}</strong>
            </div>
          </div>

          <div className="status-item">
            <span className="status-symbol">◷</span>
            <div>
              <span className="status-label">LAST API UPDATE</span>
              <strong>{lastUpdated ? lastUpdated.toLocaleTimeString() : "Waiting for data"}</strong>
            </div>
          </div>

          <div className="status-item">
            <span className="status-symbol">⌘</span>
            <div>
              <span className="status-label">ANALYTICS DATA</span>
              <strong>{error ? "Unavailable" : loading ? "Checking connection" : "API response received"}</strong>
            </div>
          </div>

          <label className="auto-refresh-control">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(event) => setAutoRefresh(event.target.checked)}
            />
            <span className="toggle-track" aria-hidden="true" />
            <span>
  {autoRefresh ? "Auto-refresh · 15s" : "Auto-refresh off"}
</span>
          </label>
        </section>

        {error && (
          <div className="error-banner" role="alert">
            <span className="error-icon">!</span>
            <div>
              <strong>Unable to load threat records</strong>
              <p>{error}</p>
              <small>
                Confirm that the backend is running and that {THREATS_ENDPOINT} is accessible.
              </small>
            </div>
            <button type="button" className="button button-subtle" onClick={() => fetchThreats(true)}>
              Try again
            </button>
          </div>
        )}

        <section className="metrics-grid" aria-label="Security metrics">
          <MetricCard
            label="DETECTED THREATS"
            value={loading ? "—" : metrics.detected}
            note="Records with risk score ≥ 35"
            icon="⌁"
            tone="teal"
          />
          <MetricCard
            label="CRITICAL RISK"
            value={loading ? "—" : metrics.critical}
            note="Critical-severity records"
            icon="!"
            tone="red"
          />
          <MetricCard
            label="RISK EVENTS"
            value={loading ? "—" : metrics.riskEvents}
            note="Records with risk score ≥ 65"
            icon="◈"
            tone="amber"
          />
          <MetricCard
            label="FAILED LOGINS"
            value={loading ? "—" : metrics.failed.toLocaleString()}
            note="Total across returned records"
            icon="⊘"
            tone="blue"
          />
        </section>

        <section className="content-grid">
          <div className="panel classifications-panel" id="classifications">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">THREAT INTELLIGENCE</div>
                <h2>Threat classifications</h2>
                <p>Categories present in the current API results.</p>
              </div>
              <span className="panel-icon">▤</span>
            </div>

            <div className="classification-list">
              {classificationCounts.length ? (
                classificationCounts.slice(0, 6).map(([name, count], index) => {
                  const maxCount = Math.max(...classificationCounts.map((item) => item[1]), 1);
                  return (
                    <div className="classification-row" key={name}>
                      <div className={`classification-icon class-icon-${index % 5}`}>
                        {["⌁", "◉", "⛨", "↗", "◇"][index % 5]}
                      </div>
                      <div className="classification-info">
                        <div className="classification-name">{formatClassification(name)}</div>
                        <div className="classification-track">
                          <span style={{ width: `${(count / maxCount) * 100}%` }} />
                        </div>
                      </div>
                      <strong className="classification-count">{count}</strong>
                    </div>
                  );
                })
              ) : (
                <div className="empty-classifications">
                  {loading ? "Loading classifications…" : "No classifications returned by the API."}
                </div>
              )}
            </div>

            <div className="classification-footer">
              <span className="mini-dot" />
              {classificationCounts.length} distinct classification
              {classificationCounts.length === 1 ? "" : "s"} in current results
            </div>
          </div>

          <div className="panel insights-panel">
            <div className="panel-heading">
              <div>
                <div className="eyebrow">ANALYTICS SNAPSHOT</div>
                <h2>Risk distribution</h2>
                <p>Severity of records currently returned by the API.</p>
              </div>
              <span className="panel-icon">◒</span>
            </div>

            <div className="distribution-list">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => {
                const count = threats.filter((threat) => threat.severity === level).length;
                const percentage = threats.length ? (count / threats.length) * 100 : 0;
                return (
                  <div className="distribution-row" key={level}>
                    <div className="distribution-topline">
                      <span className={`severity-dot ${getSeverityClass(level)}`} />
                      <span className="distribution-name">{level}</span>
                      <strong>{count}</strong>
                    </div>
                    <div className="distribution-track">
                      <span
                        className={`distribution-fill ${getSeverityClass(level)}`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="insights-footnote">
              <span>i</span>
              Severity is taken from the API when available; otherwise it is derived from risk score.
            </div>
          </div>
        </section>

        <section className="panel threats-panel" id="threats">
          <div className="panel-heading threats-heading">
            <div>
              <div className="eyebrow">LIVE SECURITY MONITORING</div>
              <h2>Detected threat records</h2>
              <p>Inspect suspicious sources and review the evidence returned by analytics.</p>
            </div>
            <div className="table-count">
              {filteredThreats.length} <span>of {threats.length} records</span>
            </div>
          </div>

          <div className="toolbar">
            <div className="search-box">
              <span className="search-icon">⌕</span>
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search source IP, classification, severity…"
                aria-label="Search threat records"
              />
              {query && (
                <button
                  className="clear-search"
                  type="button"
                  onClick={() => setQuery("")}
                  aria-label="Clear search"
                >
                  ×
                </button>
              )}
            </div>

            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
              aria-label="Filter by severity"
              className="filter-select"
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <select
              value={classificationFilter}
              onChange={(event) => setClassificationFilter(event.target.value)}
              aria-label="Filter by classification"
              className="filter-select classification-select"
            >
              <option value="ALL">All classifications</option>
              {availableClassifications.map((classification) => (
                <option value={classification} key={classification}>
                  {formatClassification(classification)}
                </option>
              ))}
            </select>

            <button type="button" className="button button-subtle" onClick={resetFilters}>
              Reset
            </button>
          </div>

          <div className="table-scroll">
            <table className="threat-table">
              <thead>
                <tr>
                  <SortableHeader label="SOURCE IP" field="sourceIp" sortBy={sortBy} direction={sortDirection} onSort={handleSort} />
                  <SortableHeader label="CLASSIFICATION" field="classification" sortBy={sortBy} direction={sortDirection} onSort={handleSort} />
                  <SortableHeader label="RISK SCORE" field="riskScore" sortBy={sortBy} direction={sortDirection} onSort={handleSort} />
                  <SortableHeader label="SEVERITY" field="severity" sortBy={sortBy} direction={sortDirection} onSort={handleSort} />
                  <SortableHeader label="FAILED LOGINS" field="failedLogins" sortBy={sortBy} direction={sortDirection} onSort={handleSort} />
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {loading && threats.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="table-message">
                      <span className="loading-spinner" />
                      Loading threat records…
                    </td>
                  </tr>
                ) : filteredThreats.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="table-message">
                      <div className="empty-state-icon">⌕</div>
                      <strong>No matching threat records</strong>
                      <p>Try changing your search or filters.</p>
                      <button className="button button-subtle" type="button" onClick={resetFilters}>
                        Clear filters
                      </button>
                    </td>
                  </tr>
                ) : (
                  filteredThreats.map((threat) => (
                    <tr key={threat.id}>
                      <td>
                        <span className="ip-address">{threat.sourceIp}</span>
                        <span className="cell-caption">Source address</span>
                      </td>
                      <td>
                        <span className="threat-type">
                          {formatClassification(threat.classification)}
                        </span>
                      </td>
                      <td>
                        <div className="risk-cell">
                          <strong>{threat.riskScore}</strong>
                          <div className="risk-track">
                            <span
                              className={`risk-fill ${getSeverityClass(threat.severity)}`}
                              style={{ width: `${threat.riskScore}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={`severity-badge ${getSeverityClass(threat.severity)}`}>
                          <span className="severity-dot" />
                          {threat.severity}
                        </span>
                      </td>
                      <td className="failed-count">{threat.failedLogins.toLocaleString()}</td>
                      <td>
                        <button
                          type="button"
                          className="details-button"
                          onClick={() => setSelectedThreat(threat)}
                        >
                          Details <span>↗</span>
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="table-footer">
            <span>Data source: Express API</span>
            <span>Refresh interval: {autoRefresh ? "15 seconds" : "Manual"}</span>
            <span>Last update: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"}</span>
          </div>
        </section>

        <footer className="page-footer">
          <span>SIEM · Security Analytics Console</span>
          <span>Local development environment <span className="footer-separator">•</span> Monitoring dashboard</span>
        </footer>
      </main>

      {selectedThreat && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedThreat(null);
          }}
        >
          <section
            className="detail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="detail-title"
          >
            <div className="modal-header">
              <div>
                <div className="eyebrow">THREAT INVESTIGATION</div>
                <h2 id="detail-title">Source details</h2>
              </div>
              <button
                className="modal-close"
                type="button"
                onClick={() => setSelectedThreat(null)}
                aria-label="Close threat details"
              >
                ×
              </button>
            </div>

            <div className="detail-ip">{selectedThreat.sourceIp}</div>
            <div className="detail-classification">
              {formatClassification(selectedThreat.classification)}
            </div>

            <div className="detail-score-card">
              <div>
                <span className="status-label">RISK SCORE</span>
                <strong>{selectedThreat.riskScore}<small> / 100</small></strong>
              </div>
              <span className={`severity-badge ${getSeverityClass(selectedThreat.severity)}`}>
                <span className="severity-dot" />
                {selectedThreat.severity}
              </span>
            </div>

            <div className="detail-stats">
              <DetailStat label="Failed logins" value={selectedThreat.failedLogins} />
              <DetailStat label="Successful logins" value={selectedThreat.successfulLogins} />
              <DetailStat label="Distinct users" value={selectedThreat.distinctUsers} />
            </div>

            <div className="detail-section">
              <h3>Detection evidence</h3>
              {selectedThreat.reasons.length > 0 ? (
                <ul className="evidence-list">
                  {selectedThreat.reasons.map((reason, index) => (
                    <li key={`${index}-${reason}`}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted-text">
                  The API did not provide explicit detection reasons for this record.
                </p>
              )}
            </div>

            <div className="detail-section">
              <h3>Last activity</h3>
              <p className="muted-text">{formatDate(selectedThreat.timestamp)}</p>
            </div>

            <div className="modal-note">
              Classification is an analytics result, not proof that an attack succeeded.
            </div>

            <button
              type="button"
              className="button button-primary modal-done"
              onClick={() => setSelectedThreat(null)}
            >
              Close details
            </button>
          </section>
        </div>
      )}
    </div>
  );
}

function MetricCard({ label, value, note, icon, tone }) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <span className="metric-icon">{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </article>
  );
}

function SortableHeader({ label, field, sortBy, direction, onSort }) {
  const active = sortBy === field;

  return (
    <th>
      <button
        type="button"
        className={`sort-button ${active ? "sort-active" : ""}`}
        onClick={() => onSort(field)}
        aria-label={`Sort by ${label}`}
      >
        {label}
        <span className="sort-indicator">
          {active ? (direction === "asc" ? "↑" : "↓") : "↕"}
        </span>
      </button>
    </th>
  );
}

function DetailStat({ label, value }) {
  return (
    <div className="detail-stat">
      <span>{label}</span>
      <strong>{Number(value).toLocaleString()}</strong>
    </div>
  );
}

export default App;