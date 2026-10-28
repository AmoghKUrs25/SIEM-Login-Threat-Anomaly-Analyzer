
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

output = Path("data/raw/login_events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

users = [
    "alice", "bob", "charlie", "diana", "admin",
    "emma", "frank", "grace", "henry", "irene"
]

# 10 IPs for ordinary login activity
normal_ips = [f"192.0.2.{i}" for i in range(10, 20)]

# 5 IPs simulating repeated failed logins
brute_force_ips = [f"203.0.113.{i}" for i in range(40, 45)]

# 5 IPs simulating password spraying
password_spray_ips = [f"198.51.100.{i}" for i in range(30, 35)]

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


# 1. Normal activity across 10 distinct IP addresses
for ip in normal_ips:
    for i in range(12):
        add_event(
            start + timedelta(
                seconds=random.randint(0, 1200),
                milliseconds=i
            ),
            random.choice(users),
            ip,
            "success" if random.random() < 0.90 else "failure"
        )

# 2. Brute-force activity: repeated failures from each IP
attack_start = start + timedelta(minutes=10)

for ip_index, ip in enumerate(brute_force_ips):
    ip_start = attack_start + timedelta(minutes=ip_index)

    for i in range(15):
        add_event(
            ip_start + timedelta(seconds=i * 5),
            "admin",
            ip,
            "failure"
        )

    # Simulate a success after repeated failures
    add_event(
        ip_start + timedelta(seconds=80),
        "admin",
        ip,
        "success"
    )

# 3. Password spraying: one failure against multiple accounts per IP
spray_start = start + timedelta(minutes=20)

for ip_index, ip in enumerate(password_spray_ips):
    ip_start = spray_start + timedelta(seconds=ip_index * 60)

    for user_index, username in enumerate(users[:5]):
        add_event(
            ip_start + timedelta(seconds=user_index * 10),
            username,
            ip,
            "failure"
        )

# Keep events in chronological order
events.sort(key=lambda event: event["timestamp"])

with output.open("w", encoding="utf-8") as file:
    for event in events:
        file.write(json.dumps(event) + "\n")

unique_ips = {event["source_ip"] for event in events}

print(f"Generated {len(events)} login events")
print(f"Distinct source IPs: {len(unique_ips)}")
print(f"Saved to: {output.resolve()}")
