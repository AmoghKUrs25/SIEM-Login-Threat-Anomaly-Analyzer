
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
ORDER BY risk_score DESC, source_ip
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
            ["docker", "exec", "siem-hive-recovered"] + command,
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

        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
            and not line.startswith("INFO")
            and not line.startswith("SLF4J:")
            and not line.startswith("WARN")
            and not line.startswith("[WARN]")
        ]

        rows = []

        for line in lines:
            parts = line.split("\t")

            # Skip column headers and other non-data output.
            if len(parts) >= 4 and parts[2].strip().isdigit():
                rows.append({
                    "source_ip": parts[0].strip(),
                    "threat_type": parts[1].strip(),
                    "risk_score": int(parts[2].strip()),
                    "failed_logins": int(parts[3].strip())
                })

        print(json.dumps({"threats": rows}))

    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
