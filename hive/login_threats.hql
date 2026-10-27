
CREATE DATABASE IF NOT EXISTS siem;

CREATE EXTERNAL TABLE IF NOT EXISTS siem.login_threats (
    source_ip STRING,
    total_events BIGINT,
    last_seen_epoch BIGINT,
    distinct_users BIGINT,
    failed_logins BIGINT,
    successful_logins BIGINT,
    max_window_failures BIGINT,
    max_window_users BIGINT,
    threat_type STRING,
    risk_score INT
)
STORED AS PARQUET
LOCATION 'hdfs://namenode:9000/siem/processed/login_analysis';

SELECT source_ip, threat_type, risk_score, failed_logins
FROM siem.login_threats
WHERE risk_score >= 65
ORDER BY risk_score DESC;
