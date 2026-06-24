```python
from elasticsearch import Elasticsearch
import smtplib
from email.mime.text import MIMEText
import time
import os


# -----------------------------
# ELASTICSEARCH CONNECTION
# -----------------------------
ELASTICSEARCH_URL = os.getenv(
    "ELASTICSEARCH_URL",
    "http://localhost:9200"
)

es = Elasticsearch(ELASTICSEARCH_URL)


# -----------------------------
# EMAIL SETTINGS
# -----------------------------
SENDER_EMAIL = os.getenv(
    "SENDER_EMAIL",
    "your_email@example.com"
)

RECEIVER_EMAIL = os.getenv(
    "RECEIVER_EMAIL",
    "analyst@example.com"
)

APP_PASSWORD = os.getenv(
    "APP_PASSWORD",
    "your_app_password"
)


# -----------------------------
# DETECTION RULES
# -----------------------------
DETECTIONS = {
    "4720": {
        "severity": "MEDIUM",
        "name": "User Account Created",
        "mitre": "T1136 - Create Account"
    },
    "4726": {
        "severity": "MEDIUM",
        "name": "User Account Deleted",
        "mitre": "T1531 - Account Access Removal"
    },
    "4732": {
        "severity": "HIGH",
        "name": "User Added to Administrators Group",
        "mitre": "T1098 - Account Manipulation"
    },
    "4672": {
        "severity": "HIGH",
        "name": "Special Privileges Assigned",
        "mitre": "T1078 - Valid Accounts"
    },
    "1102": {
        "severity": "CRITICAL",
        "name": "Audit Logs Cleared",
        "mitre": "T1070.001 - Clear Windows Event Logs"
    }
}


# -----------------------------
# TRACK PROCESSED EVENTS
# -----------------------------
processed_events = set()


def send_alert(
    alert_name,
    severity,
    event_code,
    host,
    timestamp,
    creator,
    target,
    mitre
):
    """
    Sends email alert to security analyst.
    """

    body = f"""
SOC ALERT DETECTED

Alert Name: {alert_name}
Severity: {severity}

Event ID: {event_code}
Host: {host}
Time: {timestamp}

Triggered By: {creator}
Target User: {target}

MITRE ATT&CK:
{mitre}

Please review this activity immediately.
"""

    msg = MIMEText(body)

    msg["Subject"] = (
        f"[{severity}] SOC ALERT - {alert_name}"
    )

    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    server = smtplib.SMTP(
        "smtp.gmail.com",
        587
    )

    server.starttls()

    server.login(
        SENDER_EMAIL,
        APP_PASSWORD
    )

    server.send_message(msg)
    server.quit()


print("[+] Watchtower Detection Engine Started...")
print("[+] Monitoring Security Events...")


while True:

    try:

        query = {
            "size": 20,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "query": {
                "terms": {
                    "event.code": list(
                        DETECTIONS.keys()
                    )
                }
            }
        }

        result = es.search(
            index=".ds-winlogbeat-*",
            body=query
        )

        hits = result["hits"]["hits"]

        for hit in hits:

            event_id = hit["_id"]

            if event_id in processed_events:
                continue

            processed_events.add(event_id)

            event = hit["_source"]

            event_code = str(
                event.get(
                    "event",
                    {}
                ).get(
                    "code",
                    "Unknown"
                )
            )

            if event_code not in DETECTIONS:
                continue

            rule = DETECTIONS[event_code]

            severity = rule["severity"]
            alert_name = rule["name"]
            mitre = rule["mitre"]

            host = event.get(
                "host",
                {}
            ).get(
                "name",
                "Unknown"
            )

            timestamp = event.get(
                "@timestamp",
                "Unknown"
            )

            creator = event.get(
                "user",
                {}
            ).get(
                "name",
                "Unknown"
            )

            target = (
                event.get("user", {})
                .get("target", {})
                .get("name", "N/A")
            )

            send_alert(
                alert_name,
                severity,
                event_code,
                host,
                timestamp,
                creator,
                target,
                mitre
            )

            print(
                f"[ALERT SENT] "
                f"{alert_name} "
                f"(Event ID {event_code})"
            )

        time.sleep(30)

    except Exception as e:

        print(
            f"[ERROR] {e}"
        )

        time.sleep(30)
```
