# Watchtower-AI Security Operations Detection Engineering Platform

An end-to-end, AI-powered Security Operations Center (SOC) platform built for real-time threat detection, log analysis, and automated alerting -mapped to the MITRE ATT&CK framework.

## Overview

WatchtowerAI is a Detection Engineering and Security Operations platform that collects, processes, and analyzes logs from Windows endpoints to detect malicious behavior in real time.

It leverages Sigma rules for detection logic, MITRE ATT&CK for threat classification, and Python automation to deliver actionable email alerts to security analysts.

Built as a pre final-year cybersecurity engineering project, this platform simulates a production-grade SOC pipeline using open-source tooling deployed via Docker.

---

## Architecture

```text
Windows Endpoint + Sysmon
           │
           ▼
Winlogbeat (Log Shipper)
           │
           ▼
Elasticsearch (Storage & Search)
           │
      ┌────┴────┐
      ▼         ▼
  Kibana    Python Detection Engine
(Dashboard) (Sigma Rules + Alert Automation)
                 │
                 ▼
         Email Alert (SMTP)

[Alert Name | Severity | Event ID | Host | Time | User | MITRE ATT&CK]
```

All components are containerized and orchestrated using Docker.

---

## Tech Stack

```text
┌──────────────────────────────────────────┐
│                WATCHTOWER                │
│ AI-Powered SOC & Detection Engineering   │
└──────────────────────────────────────────┘

┌──────────────────────────────────────────┐
│ Endpoint Telemetry Layer                 │
├──────────────────────────────────────────┤
│ Windows Endpoint                         │
│ Sysmon                                   │
└──────────────────────────────────────────┘
                    │
                    ▼

┌──────────────────────────────────────────┐
│ Log Collection Layer                     │
├──────────────────────────────────────────┤
│ Winlogbeat                               │
└──────────────────────────────────────────┘
                    │
                    ▼

┌──────────────────────────────────────────┐
│ Storage & Search Layer                   │
├──────────────────────────────────────────┤
│ Elasticsearch                            │
└──────────────────────────────────────────┘
                    │
                    ▼

┌──────────────────────────────────────────┐
│ Analytics & Detection Layer              │
├──────────────────────────────────────────┤
│ Kibana Dashboards                        │
│ Python Detection Engine                  │
│ Sigma Rules                              │
│ MITRE ATT&CK Mapping                     │
└──────────────────────────────────────────┘
                    │
                    ▼

┌──────────────────────────────────────────┐
│ Alerting Layer                           │
├──────────────────────────────────────────┤
│ Email (SMTP)                             │
└──────────────────────────────────────────┘
```

---

## Alert Schema

Each triggered detection sends an email alert containing:

* Alert Name — Name of the Sigma rule that fired
* Severity — Critical / High / Medium / Low
* Event ID — Windows Event ID that triggered the rule
* Host — Source endpoint hostname
* Time — Timestamp of the event
* Triggered By — Process or rule that caused the detection
* Target User — User account involved in the event
* MITRE ATT&CK — Mapped Tactic & Technique (e.g., T1059 - Command and Scripting Interpreter)

---

## Detection Engineering

Detections are written as Sigma rules and converted into Elasticsearch queries at runtime.

Rules cover common attack techniques including:

* Credential dumping (LSASS access)
* PowerShell obfuscation and abuse
* Lateral movement via PsExec / WMI
* Persistence via registry run keys / scheduled tasks
* Defense evasion (process injection, masquerading)

All rules are mapped to the MITRE ATT&CK framework for structured threat classification.

---

## Kibana Dashboards

Kibana provides visual analysis including:

* Real-time event feed from all endpoints
* Detection trigger timeline
* Top alert sources by host and user
* Severity distribution charts
* MITRE ATT&CK technique heatmap

---

## Getting Started

### Prerequisites

* Docker & Docker Compose
* Windows machine with Sysmon installed
* Python 3.x

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/watchtowerai.git

cd watchtowerai
```

### Start the Stack

```bash
docker-compose up -d
```

### Configure Winlogbeat

Edit `winlogbeat.yml` to point to your Elasticsearch instance:

```yaml
output.elasticsearch:
  hosts: ["localhost:9200"]
```

### Configure Email Alerts

Edit the alert config in `config/alert_config.yml`:

```yaml
smtp:
  host: smtp.gmail.com
  port: 587
  sender: your@email.com
  recipient: analyst@email.com
```

### Run the Detection Engine

```bash
cd detection_engine

pip install -r requirements.txt

python main.py
```

---

## Project Structure

```text
watchtowerai/
│
├── docker-compose.yml
│
├── winlogbeat/
│   └── winlogbeat.yml
│
├── elasticsearch/
│   └── elasticsearch.yml
│
├── kibana/
│   └── kibana.yml
│
├── detection_engine/
│   ├── main.py
│   ├── sigma_loader.py
│   ├── alert_mailer.py
│   └── requirements.txt
│
├── sigma_rules/
│   ├── credential_dumping.yml
│   ├── powershell_abuse.yml
│   └── ...
│
├── config/
│   └── alert_config.yml
│
└── README.md
```

---

## MITRE ATT&CK Coverage

| Detection Use Case               | Event ID / Source                 | ATT&CK Technique                  | ATT&CK ID | Tactic              |
| -------------------------------- | --------------------------------- | --------------------------------- | --------- | ------------------- |
| User Account Creation            | Windows Security Log (4720)       | Create Account                    | T1136     | Persistence         |
| Special Privilege Logon          | Windows Security Log (4672)       | Valid Accounts                    | T1078     | Defense Evasion     |
| Successful Logon Monitoring      | Windows Security Log (4624)       | Valid Accounts                    | T1078     | Initial Access      |
| Failed Logon Monitoring          | Windows Security Log (4625)       | Brute Force                       | T1110     | Credential Access   |
| Process Creation Monitoring      | Sysmon Event ID 1                 | Command and Scripting Interpreter | T1059     | Execution           |
| Command Line Execution Analysis  | Sysmon Event ID 1                 | Command and Scripting Interpreter | T1059     | Execution           |
| Network Connection Monitoring    | Sysmon Event ID 3                 | Application Layer Protocol        | T1071     | Command and Control |
| Registry Modification Monitoring | Sysmon Event ID 13                | Modify Registry                   | T1112     | Defense Evasion     |
| Service Creation Monitoring      | Windows Security Log (4697)       | Create or Modify System Process   | T1543     | Persistence         |
| Account Group Membership Changes | Windows Security Log (4732, 4733) | Account Manipulation              | T1098     | Persistence         |

```
```




          
