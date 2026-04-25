"""
EduSIEM - Attack Simulator
pages/8_🎯_Attack_Simulator.py
Built to match exact database schema from database/models.py
"""

import streamlit as st
import sqlite3
import random
import os
import json
from datetime import datetime, timedelta
import pandas as pd

st.set_page_config(page_title="Attack Simulator - EduSIEM", page_icon="🎯", layout="wide")

# ── Auth ──────────────────────────────────────
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.error("🔒 Please login first")
    st.stop()

username = st.session_state.get("username", "admin")
role     = st.session_state.get("role", "")

if role not in ["admin", "edusiem_lead"]:
    st.warning("🚫 Only Admin and EduSIEM Lead can run simulations.")
    st.stop()

# ── DB ────────────────────────────────────────
DB_PATH = "data/edusiem.db"

def get_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def table_exists(name):
    conn = get_db()
    r = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    conn.close()
    return r is not None

def get_columns(table):
    if not table_exists(table):
        return []
    conn = get_db()
    cols = [c["name"] for c in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    conn.close()
    return cols

def ensure_anomaly_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at     TEXT NOT NULL,
            source_ip       TEXT,
            anomaly_type    TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'medium',
            z_score         REAL,
            description     TEXT,
            status          TEXT NOT NULL DEFAULT 'Open',
            linked_alert_id INTEGER
        )
    """)
    conn.commit()
    conn.close()

def rnd_ext_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rnd_int_ip():
    return f"192.168.{random.randint(1,5)}.{random.randint(2,254)}"

# ── EXACT schema from models.py ───────────────
# alerts columns: id, alert_type, title, message, severity, status,
#                 source, source_ip, target_ip, user_id, rule_id, rule_name,
#                 created_by, reviewed_by, incident_id, created_at,
#                 reviewed_at, evidence

def insert_alert(alert_type, title, message, severity, source, source_ip, target_ip, rule_id, rule_name, evidence):
    if not table_exists("alerts"):
        st.error("❌ alerts table not found. Make sure the database is initialized.")
        return None
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO alerts
                (alert_type, title, message, severity, status, source,
                 source_ip, target_ip, rule_id, rule_name, created_at, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_type, title, message, severity, "new", source,
            source_ip, target_ip, rule_id, rule_name,
            datetime.utcnow().isoformat(), evidence
        ))
        conn.commit()
        aid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return aid
    except Exception as e:
        st.error(f"❌ Alert insert error: {e}")
        return None

# network_logs columns: id, source_ip, source_port, destination_ip,
#   destination_port, protocol, bytes_sent, bytes_received, packets,
#   status, threat_level, user_id, connection_state, duration,
#   timestamp, alert_id

def insert_network_logs(entries):
    if not table_exists("network_logs"):
        return 0
    valid = set(get_columns("network_logs")) - {"id"}
    conn  = get_db()
    count = 0
    for e in entries:
        row = {k: v for k, v in e.items() if k in valid}
        if not row:
            continue
        try:
            conn.execute(
                f"INSERT INTO network_logs ({','.join(row)}) VALUES ({','.join(['?']*len(row))})",
                list(row.values())
            )
            count += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return count

# firewall_logs columns: id, action, rule_name, rule_id, source_ip,
#   source_port, source_country, destination_ip, destination_port,
#   protocol, threat_type, severity, bytes_transferred, packets,
#   timestamp, alert_id

def insert_firewall_logs(entries):
    if not table_exists("firewall_logs"):
        return 0
    valid = set(get_columns("firewall_logs")) - {"id"}
    conn  = get_db()
    count = 0
    for e in entries:
        row = {k: v for k, v in e.items() if k in valid}
        if not row:
            continue
        try:
            conn.execute(
                f"INSERT INTO firewall_logs ({','.join(row)}) VALUES ({','.join(['?']*len(row))})",
                list(row.values())
            )
            count += 1
        except Exception:
            pass
    conn.commit()
    conn.close()
    return count

# simulated_attacks columns: id, attack_type, attack_name, description,
#   source_ip, target_ip, parameters, alert_generated, alert_id,
#   simulated_by, simulated_at, status

def insert_simulated_attack(attack_type, attack_name, description, source_ip, target_ip, parameters, alert_id):
    if not table_exists("simulated_attacks"):
        return
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO simulated_attacks
                (attack_type, attack_name, description, source_ip, target_ip,
                 parameters, alert_generated, alert_id, simulated_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            attack_type, attack_name, description, source_ip, target_ip,
            json.dumps(parameters), 1 if alert_id else 0, alert_id,
            datetime.utcnow().isoformat(), "success" if alert_id else "failed"
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass

def insert_anomaly(source_ip, anomaly_type, severity, description, z_score, alert_id):
    ensure_anomaly_table()
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO anomalies
                (detected_at, source_ip, anomaly_type, severity, z_score, description, status, linked_alert_id)
            VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)
        """, (datetime.utcnow().isoformat(), source_ip, anomaly_type, severity, z_score, description, alert_id))
        conn.commit()
        conn.close()
    except Exception:
        pass

# ── Attack definitions ────────────────────────

ATTACKS = [
    {
        "id": 1, "name": "🔐 Brute Force Attack",
        "attack_type": "brute_force", "severity": "high",
        "rule_id": "RULE-001", "rule_name": "Brute Force Detection",
        "source": "brute_force", "atype": "Brute Force", "z": 4.2,
        "cat": "Authentication Attack", "mitre": "T1110",
        "desc": "Repeated failed login attempts against SSH/web portal from external IP.",
    },
    {
        "id": 2, "name": "💉 SQL Injection",
        "attack_type": "sql_injection", "severity": "critical",
        "rule_id": "RULE-003", "rule_name": "SQL Injection Detection",
        "source": "sql_injection", "atype": "SQL Injection", "z": 5.1,
        "cat": "Web Application Attack", "mitre": "T1190",
        "desc": "SQL injection payloads targeting student portal database.",
    },
    {
        "id": 3, "name": "🌊 DDoS Attack",
        "attack_type": "ddos", "severity": "critical",
        "rule_id": "RULE-010", "rule_name": "DDoS Detection",
        "source": "ddos", "atype": "Traffic Volume Spike", "z": 6.8,
        "cat": "Availability Attack", "mitre": "T1498",
        "desc": "High-volume request flood targeting campus web servers.",
    },
    {
        "id": 4, "name": "🔍 Port Scan",
        "attack_type": "port_scan", "severity": "medium",
        "rule_id": "RULE-002", "rule_name": "Port Scan Detection",
        "source": "port_scan", "atype": "Port Scan", "z": 3.5,
        "cat": "Reconnaissance", "mitre": "T1046",
        "desc": "Systematic port scanning across campus network subnets.",
    },
    {
        "id": 5, "name": "🦠 Malware C2 Beacon",
        "attack_type": "malware", "severity": "critical",
        "rule_id": "RULE-007", "rule_name": "Malware Detection",
        "source": "malware", "atype": "C2 Communication", "z": 4.9,
        "cat": "Malware", "mitre": "T1071",
        "desc": "Malware beaconing to external command and control server.",
    },
    {
        "id": 6, "name": "🎣 Phishing Campaign",
        "attack_type": "phishing", "severity": "high",
        "rule_id": "RULE-009", "rule_name": "Phishing Detection",
        "source": "phishing", "atype": "Phishing", "z": 3.1,
        "cat": "Social Engineering", "mitre": "T1566",
        "desc": "Credential-harvesting phishing emails sent to faculty accounts.",
    },
    {
        "id": 7, "name": "🔑 Privilege Escalation",
        "attack_type": "privilege_escalation", "severity": "critical",
        "rule_id": "RULE-008", "rule_name": "Privilege Escalation",
        "source": "privilege_escalation", "atype": "Privilege Escalation", "z": 4.7,
        "cat": "Lateral Movement", "mitre": "T1068",
        "desc": "Student account attempting to escalate to admin privileges.",
    },
    {
        "id": 8, "name": "📤 Data Exfiltration",
        "attack_type": "data_exfiltration", "severity": "critical",
        "rule_id": "RULE-006", "rule_name": "Data Exfiltration",
        "source": "data_exfiltration", "atype": "Data Exfiltration", "z": 5.5,
        "cat": "Exfiltration", "mitre": "T1041",
        "desc": "Bulk student records transferred to external IP address.",
    },
    {
        "id": 9, "name": "🔓 Unauthorized Access",
        "attack_type": "unusual_time", "severity": "high",
        "rule_id": "RULE-005", "rule_name": "Geographic Anomaly",
        "source": "unauthorized_access", "atype": "Unauthorized Access", "z": 3.8,
        "cat": "Access Control", "mitre": "T1078",
        "desc": "Access to restricted admin panel without proper authorization.",
    },
    {
        "id": 10, "name": "🌙 Insider Threat",
        "attack_type": "unusual_time", "severity": "high",
        "rule_id": "RULE-004", "rule_name": "Unusual Time Access",
        "source": "insider_threat", "atype": "Off-Hours Activity", "z": 3.3,
        "cat": "Insider Threat", "mitre": "T1074",
        "desc": "Staff account bulk-downloading confidential files at 2 AM.",
    },
]

# ── Log generators ────────────────────────────

def make_net_logs(atk, src, alert_id):
    now  = datetime.utcnow()
    base = {"source_ip": src, "alert_id": alert_id,
            "status": "suspicious", "threat_level": atk["severity"]}
    logs = []

    if atk["id"] == 1:  # Brute force
        for i in range(20):
            logs.append({**base,
                "destination_ip": rnd_int_ip(), "destination_port": 22,
                "protocol": "TCP", "bytes_sent": 512, "bytes_received": 128,
                "packets": 3, "connection_state": "rejected",
                "timestamp": (now - timedelta(seconds=i*15)).isoformat(),
            })
    elif atk["id"] == 2:  # SQL injection
        for i in range(5):
            logs.append({**base,
                "destination_ip": rnd_int_ip(), "destination_port": 80,
                "protocol": "HTTP", "bytes_sent": random.randint(200,800),
                "bytes_received": 50, "packets": 2, "connection_state": "established",
                "timestamp": (now - timedelta(seconds=i*10)).isoformat(),
            })
    elif atk["id"] == 3:  # DDoS
        for i in range(50):
            logs.append({**base,
                "destination_ip": rnd_int_ip(), "destination_port": 80,
                "protocol": "TCP", "bytes_sent": random.randint(50,200),
                "bytes_received": 0, "packets": 1, "connection_state": "syn_sent",
                "timestamp": (now - timedelta(seconds=i*2)).isoformat(),
            })
    elif atk["id"] == 4:  # Port scan
        for port in random.sample(range(1, 9000), 25):
            logs.append({**base,
                "destination_ip": rnd_int_ip(), "destination_port": port,
                "protocol": "TCP", "bytes_sent": 40, "bytes_received": 0,
                "packets": 1, "connection_state": "syn_sent",
                "timestamp": (now - timedelta(seconds=random.randint(0,120))).isoformat(),
            })
    elif atk["id"] == 8:  # Data exfil
        logs.append({**base,
            "destination_ip": rnd_ext_ip(), "destination_port": 443,
            "protocol": "TCP", "bytes_sent": random.randint(5000000,50000000),
            "bytes_received": 1024, "packets": random.randint(1000,5000),
            "connection_state": "established", "duration": random.randint(300,1800),
            "timestamp": now.isoformat(),
        })
    elif atk["id"] == 10:  # Insider / off-hours
        off = now.replace(hour=2, minute=random.randint(0,59))
        for i in range(15):
            logs.append({**base,
                "source_ip": rnd_int_ip(),
                "destination_ip": rnd_int_ip(), "destination_port": 445,
                "protocol": "TCP", "bytes_sent": random.randint(1000,50000),
                "bytes_received": random.randint(500,25000),
                "packets": random.randint(10,100), "connection_state": "established",
                "timestamp": (off - timedelta(minutes=i*3)).isoformat(),
            })
    else:
        for i in range(5):
            logs.append({**base,
                "destination_ip": rnd_int_ip(),
                "destination_port": random.choice([80,443,22,3306,8080]),
                "protocol": random.choice(["TCP","UDP","HTTP"]),
                "bytes_sent": random.randint(100,1000),
                "bytes_received": random.randint(50,500),
                "packets": random.randint(2,20), "connection_state": "established",
                "timestamp": (now - timedelta(seconds=i*10)).isoformat(),
            })
    return logs


def make_fw_logs(atk, src, alert_id):
    now    = datetime.utcnow()
    action = "block" if atk["severity"] in ("critical","high") else "drop"
    return [{
        "source_ip": src,
        "source_port": random.randint(1024, 65535),
        "destination_ip": rnd_int_ip(),
        "destination_port": random.randint(1, 65535),
        "protocol": "TCP",
        "action": action,
        "rule_name": atk["rule_name"],
        "rule_id": atk["rule_id"],
        "threat_type": atk["attack_type"],
        "severity": atk["severity"],
        "bytes_transferred": random.randint(100,5000),
        "packets": random.randint(1,50),
        "timestamp": (now - timedelta(seconds=i*5)).isoformat(),
        "alert_id": alert_id,
    } for i in range(4)]


def run_attack(atk):
    src = rnd_ext_ip()
    tgt = rnd_int_ip()
    now = datetime.utcnow()

    evidence = json.dumps({
        "mitre_technique": atk["mitre"],
        "category": atk["cat"],
        "source_ip": src,
        "target_ip": tgt,
        "simulated_by": username,
        "simulated_at": now.isoformat(),
        "z_score": atk["z"],
    })

    # 1. Create alert using exact column names from models.py
    aid = insert_alert(
        alert_type = atk["attack_type"],
        title      = f"{atk['name']} Detected",
        message    = f"{atk['desc']} | Source IP: {src} | Target IP: {tgt} | MITRE: {atk['mitre']} | Simulated by {username} at {now.strftime('%Y-%m-%d %H:%M:%S')}",
        severity   = atk["severity"],
        source     = atk["source"],
        source_ip  = src,
        target_ip  = tgt,
        rule_id    = atk["rule_id"],
        rule_name  = atk["rule_name"],
        evidence   = evidence,
    )

    # 2. Network logs
    net_n = insert_network_logs(make_net_logs(atk, src, aid))

    # 3. Firewall logs
    fw_n = insert_firewall_logs(make_fw_logs(atk, src, aid))

    # 4. Simulated attack record
    insert_simulated_attack(
        attack_type  = atk["attack_type"],
        attack_name  = atk["name"],
        description  = atk["desc"],
        source_ip    = src,
        target_ip    = tgt,
        parameters   = {"mitre": atk["mitre"], "z_score": atk["z"]},
        alert_id     = aid,
    )

    # 5. Anomaly record
    insert_anomaly(src, atk["atype"], atk["severity"],
        f"[SIM] {atk['name']}: {atk['desc']} from {src} → {tgt}", atk["z"], aid)

    return {"aid": aid, "src": src, "tgt": tgt, "net": net_n, "fw": fw_n}


# ── UI ────────────────────────────────────────

st.title("🎯 Attack Simulator")
st.caption("Each simulated attack writes correlated data to: alerts · network_logs · firewall_logs · simulated_attacks · anomalies")

st.info("💡 After launching an attack, check **🏠 Dashboard**, **🚨 Alerts**, **🧠 Anomaly Detection**, and **🔎 Log Search** to see all correlated data.")

st.divider()
st.subheader("Select an Attack Scenario")

for i in range(0, len(ATTACKS), 2):
    pair = ATTACKS[i:i+2]
    c1, c2 = st.columns(2)
    for col, atk in zip([c1, c2], pair):
        with col:
            with st.container(border=True):
                icon = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(atk["severity"],"⚪")
                st.markdown(f"### {atk['name']}")
                st.caption(f"{icon} **{atk['severity'].title()}** &nbsp;|&nbsp; `{atk['mitre']}` &nbsp;|&nbsp; {atk['cat']}")
                st.write(atk["desc"])
                btype = "primary" if atk["severity"] == "critical" else "secondary"
                if st.button("▶ Launch", key=f"atk_{atk['id']}", use_container_width=True, type=btype):
                    with st.spinner(f"Simulating {atk['name']}..."):
                        res = run_attack(atk)
                    if res["aid"]:
                        st.success("✅ Attack simulated! Written to database:")
                        r1, r2 = st.columns(2)
                        r1.metric("Alert ID",      f"#{res['aid']}")
                        r2.metric("Source IP",     res["src"])
                        r1.metric("Network Logs",  res["net"])
                        r2.metric("Firewall Logs", res["fw"])
                        st.caption(f"🧠 Anomaly injected · 📋 SimRecord saved · Target: {res['tgt']}")
                    else:
                        st.error("Attack simulation failed — check the error above.")

st.divider()
st.subheader("📋 Recent Alerts")

try:
    if table_exists("alerts"):
        conn = get_db()
        rows = conn.execute("""
            SELECT id, title, alert_type, severity, status, source_ip, created_at
            FROM alerts ORDER BY created_at DESC LIMIT 12
        """).fetchall()
        conn.close()
        if rows:
            st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
        else:
            st.info("No alerts yet — launch a simulation above.")
    else:
        st.warning("alerts table not found.")
except Exception as e:
    st.warning(f"Could not load alerts: {e}")

with st.expander("📐 Correlation Map — what each simulation creates"):
    st.code("""
▶ Launch button clicked
  │
  ├─ alerts table          ← title, message, severity, source_ip, rule_name ...
  ├─ network_logs table    ← source_ip, destination_ip, protocol, bytes_sent ...
  ├─ firewall_logs table   ← action, threat_type, severity, rule_name ...
  ├─ simulated_attacks     ← attack_type, parameters, alert_id ...
  └─ anomalies table       ← anomaly_type, z_score, linked_alert_id ...

All records share the same source_ip and alert_id as correlation keys.
Dashboard, Alerts, Network Logs, Firewall Logs, Anomaly Detection
and Log Search all query these same tables — so everything is in sync.
    """)