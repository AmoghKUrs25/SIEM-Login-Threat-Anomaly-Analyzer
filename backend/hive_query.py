
import json
import os
import subprocess
import sys

HIVE_URL = os.getenv(
    "HIVE_JDBC_URL",
    "jdbc:hive2://127.0.0.1:10000/default"
)

QUERY = """
SELECT source_ip, threat_type, risk_score, failed_logins
FROM siem.login_threats
WHERE risk_score >= 65
ORDER BY risk_score DESC
"""

def main():
    command = [
        "/opt/hive/bin/beeline",
        "-u", HIVE_URL,
        "--silent=true",
        "--outputformat=tsv2",
        "-e", QUERY
    ]

    try:
        result = subprocess.run(
            ["docker", "exec", "siem-hive"] + command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False
        )

        if result.returncode != 0:
            print(json.dumps({
                "error": "Hive query failed",
                "details": result.stderr[-2000:]
            }))
            sys.exit(1)

        # The first version of the API uses a stable, explicit
        # JSON representation of the known query output.
        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith("INFO")
        ]

        rows = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 4 and parts[2].isdigit():
                rows.append({
                    "source_ip": parts[0],
                    "threat_type": parts[1],
                    "risk_score": int(parts[2]),
                    "failed_logins": int(parts[3])
                })

        print(json.dumps({"threats": rows}))

    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
