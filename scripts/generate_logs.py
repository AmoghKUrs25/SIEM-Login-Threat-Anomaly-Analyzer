
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

output = Path("data/raw/login_events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

users = ["alice", "bob", "charlie", "diana", "admin"]
normal_ips = ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
attack_ip = "203.0.113.42"

events = []
start = datetime.now(timezone.utc) - timedelta(minutes=30)

def add_event(timestamp, username, ip, status):
    events.append({
        "event_id": f"EVT-{len(events) + 1:05d}",
        "timestamp": timestamp.isoformat(),
        "username": username,
        "source_ip": ip,
        "event_type": "login",
        "status": status,
        "source": "synthetic"
    })

for i in range(100):
    add_event(
        start + timedelta(seconds=i * 15),
        random.choice(users),
        random.choice(normal_ips),
        "success" if random.random() < 0.85 else "failure"
    )

# Brute-force simulation
attack_start = start + timedelta(minutes=10)

for i in range(15):
    add_event(
        attack_start + timedelta(seconds=i * 5),
        "admin",
        attack_ip,
        "failure"
    )

# Successful login after repeated failures
add_event(
    attack_start + timedelta(seconds=80),
    "admin",
    attack_ip,
    "success"
)

# Password spraying simulation
for i, username in enumerate(users):
    add_event(
        start + timedelta(minutes=20, seconds=i * 10),
        username,
        "198.51.100.25",
        "failure"
    )

events.sort(key=lambda event: event["timestamp"])

with output.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

print(f"Generated {len(events)} login events")
print(f"Saved to: {output.resolve()}")
