"""
EduSIEM - Anomaly Detection
pages/10_🧠_Anomaly_Detection.py
Built to match exact database schema from database/models.py
"""

import streamlit as st
import sqlite3
import pandas as pd
import os
import math
from datetime import datetime, timedelta

st.set_page_config(page_title="Anomaly Detection - EduSIEM", page_icon="🧠", layout="wide")

# ── Auth ──────────────────────────────────────
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.error("🔒 Please login first")
    st.stop()

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

def safe_count(sql, params=()):
    try:
        conn = get_db()
        r = conn.execute(sql, params).fetchone()
        conn.close()
        return r[0] if r else 0
    except Exception:
        return 0

# ── Ensure anomaly tables ─────────────────────

def ensure_tables():
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavior_baselines (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip    TEXT NOT NULL,
            metric       TEXT NOT NULL,
            mean         REAL NOT NULL DEFAULT 0,
            std          REAL NOT NULL DEFAULT 1,
            sample_count INTEGER NOT NULL DEFAULT 0,
            last_updated TEXT NOT NULL,
            UNIQUE(source_ip, metric)
        )
    """)
    conn.commit()
    conn.close()

ensure_tables()

# ── Detection ─────────────────────────────────

def build_baseline(days=7):
    """Build per-IP statistical baseline from network_logs."""
    if not table_exists("network_logs"):
        return 0

    # network_logs has: source_ip, bytes_sent, status (normal/suspicious/blocked), timestamp
    cols   = get_columns("network_logs")
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn   = get_db()

    has_bytes  = "bytes_sent" in cols
    has_status = "status" in cols

    sel = "DATE(timestamp) as day, source_ip, COUNT(*) as req"
    if has_bytes:
        sel += ", SUM(COALESCE(bytes_sent,0)) as bytes"
    else:
        sel += ", 0 as bytes"
    if has_status:
        sel += ", SUM(CASE WHEN status='suspicious' THEN 1 ELSE 0 END) as suspicious"
    else:
        sel += ", 0 as suspicious"

    try:
        rows = conn.execute(
            f"SELECT {sel} FROM network_logs WHERE timestamp >= ? GROUP BY day, source_ip",
            (cutoff,)
        ).fetchall()
    except Exception as e:
        conn.close()
        return 0

    ip_data = {}
    for r in rows:
        ip = r["source_ip"] or "unknown"
        if ip not in ip_data:
            ip_data[ip] = {"req": [], "bytes": [], "suspicious": []}
        ip_data[ip]["req"].append(r["req"])
        ip_data[ip]["bytes"].append(r["bytes"])
        ip_data[ip]["suspicious"].append(r["suspicious"])

    now_str = datetime.utcnow().isoformat()
    for ip, metrics in ip_data.items():
        for mname, vals in metrics.items():
            if not vals:
                continue
            n    = len(vals)
            mean = sum(vals) / n
            std  = math.sqrt(sum((v - mean)**2 for v in vals) / n) if n > 1 else 1.0
            std  = max(std, 0.1)
            conn.execute("""
                INSERT INTO behavior_baselines (source_ip, metric, mean, std, sample_count, last_updated)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(source_ip, metric) DO UPDATE SET
                    mean=excluded.mean, std=excluded.std,
                    sample_count=excluded.sample_count, last_updated=excluded.last_updated
            """, (ip, mname, mean, std, n, now_str))

    conn.commit()
    conn.close()
    return len(ip_data)


def run_statistical_detection():
    """Z-score: flag IPs whose last-hour request count deviates from baseline."""
    if not table_exists("network_logs") or not table_exists("behavior_baselines"):
        return 0

    since = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    conn  = get_db()
    found = 0

    try:
        recent = conn.execute("""
            SELECT source_ip, COUNT(*) as req
            FROM network_logs WHERE timestamp >= ?
            GROUP BY source_ip
        """, (since,)).fetchall()

        for row in recent:
            ip  = row["source_ip"] or "unknown"
            val = row["req"]
            bl  = conn.execute(
                "SELECT mean, std FROM behavior_baselines WHERE source_ip=? AND metric='req'",
                (ip,)
            ).fetchone()
            if not bl:
                continue
            std = bl["std"] or 1.0
            z   = (val - bl["mean"]) / std
            if abs(z) >= 2.5:
                sev = "critical" if abs(z) >= 4 else ("high" if abs(z) >= 3 else "medium")
                conn.execute("""
                    INSERT INTO anomalies
                        (detected_at, source_ip, anomaly_type, severity, z_score, description, status)
                    VALUES (?,?,?,?,?,?,'Open')
                """, (
                    datetime.utcnow().isoformat(), ip, "Traffic Volume Spike", sev, round(z, 2),
                    f"IP {ip} sent {val} requests in last 1h (baseline mean={bl['mean']:.1f}, std={bl['std']:.1f}, z={z:.2f})"
                ))
                found += 1
    except Exception:
        pass

    conn.commit()
    conn.close()
    return found


def run_rule_detection():
    """Rule-based detection using patterns in network_logs and firewall_logs."""
    conn  = get_db()
    now   = datetime.utcnow()
    found = 0

    # ── Rule 1: Brute force — suspicious status count in 5 min ────
    if table_exists("network_logs") and "status" in get_columns("network_logs"):
        since = (now - timedelta(minutes=5)).isoformat()
        try:
            rows = conn.execute("""
                SELECT source_ip, COUNT(*) as cnt FROM network_logs
                WHERE timestamp >= ? AND status = 'suspicious'
                GROUP BY source_ip HAVING cnt >= 5
            """, (since,)).fetchall()
            for r in rows:
                conn.execute("""
                    INSERT INTO anomalies (detected_at, source_ip, anomaly_type, severity, description, status)
                    VALUES (?,?,?,?,?,'Open')
                """, (now.isoformat(), r["source_ip"], "Brute Force", "high",
                      f"IP {r['source_ip']} triggered {r['cnt']} suspicious events in 5 min"))
                found += 1
        except Exception:
            pass

    # ── Rule 2: Port scan — distinct destination ports in firewall_logs ─
    if table_exists("firewall_logs") and "destination_port" in get_columns("firewall_logs"):
        since = (now - timedelta(minutes=2)).isoformat()
        try:
            rows = conn.execute("""
                SELECT source_ip, COUNT(DISTINCT destination_port) as ports FROM firewall_logs
                WHERE timestamp >= ?
                GROUP BY source_ip HAVING ports >= 15
            """, (since,)).fetchall()
            for r in rows:
                conn.execute("""
                    INSERT INTO anomalies (detected_at, source_ip, anomaly_type, severity, description, status)
                    VALUES (?,?,?,?,?,'Open')
                """, (now.isoformat(), r["source_ip"], "Port Scan", "high",
                      f"IP {r['source_ip']} contacted {r['ports']} distinct ports in 2 min"))
                found += 1
        except Exception:
            pass

    # ── Rule 3: High threat_level entries in firewall_logs ────────────
    if table_exists("firewall_logs") and "threat_type" in get_columns("firewall_logs"):
        since = (now - timedelta(hours=1)).isoformat()
        try:
            rows = conn.execute("""
                SELECT source_ip, threat_type, COUNT(*) as cnt FROM firewall_logs
                WHERE timestamp >= ? AND severity IN ('critical','high')
                GROUP BY source_ip, threat_type HAVING cnt >= 3
            """, (since,)).fetchall()
            for r in rows:
                conn.execute("""
                    INSERT INTO anomalies (detected_at, source_ip, anomaly_type, severity, description, status)
                    VALUES (?,?,?,?,?,'Open')
                """, (now.isoformat(), r["source_ip"],
                      r["threat_type"].replace("_"," ").title(), "high",
                      f"IP {r['source_ip']} had {r['cnt']} high-severity {r['threat_type']} firewall events in 1h"))
                found += 1
        except Exception:
            pass

    # ── Rule 4: Data exfil — large bytes_sent in network_logs ─────────
    if table_exists("network_logs") and "bytes_sent" in get_columns("network_logs"):
        since = (now - timedelta(minutes=10)).isoformat()
        try:
            rows = conn.execute("""
                SELECT source_ip, SUM(bytes_sent) as total_bytes FROM network_logs
                WHERE timestamp >= ?
                GROUP BY source_ip HAVING total_bytes >= 5000000
            """, (since,)).fetchall()
            for r in rows:
                mb = r["total_bytes"] / 1_000_000
                conn.execute("""
                    INSERT INTO anomalies (detected_at, source_ip, anomaly_type, severity, description, status)
                    VALUES (?,?,?,?,?,'Open')
                """, (now.isoformat(), r["source_ip"], "Data Exfiltration", "critical",
                      f"IP {r['source_ip']} transferred {mb:.1f} MB outbound in 10 min"))
                found += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    return found


def get_stats():
    if not table_exists("anomalies"):
        return {"total":0,"open":0,"critical":0,"high":0,"by_type":{},"top_ips":[]}
    conn = get_db()
    stats = {
        "total":    conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0],
        "open":     conn.execute("SELECT COUNT(*) FROM anomalies WHERE status='Open'").fetchone()[0],
        "critical": conn.execute("SELECT COUNT(*) FROM anomalies WHERE severity='critical'").fetchone()[0],
        "high":     conn.execute("SELECT COUNT(*) FROM anomalies WHERE severity='high'").fetchone()[0],
    }
    by_type = conn.execute("SELECT anomaly_type, COUNT(*) as cnt FROM anomalies GROUP BY anomaly_type ORDER BY cnt DESC").fetchall()
    stats["by_type"] = {r["anomaly_type"]: r["cnt"] for r in by_type}
    top_ips = conn.execute("SELECT source_ip, COUNT(*) as cnt FROM anomalies GROUP BY source_ip ORDER BY cnt DESC LIMIT 8").fetchall()
    stats["top_ips"] = [{"ip": r["source_ip"], "count": r["cnt"]} for r in top_ips]
    conn.close()
    return stats


def get_recent(limit=200, status_f=None, sev_f=None, type_f=None):
    if not table_exists("anomalies"):
        return pd.DataFrame()
    conds, params = [], []
    if status_f and status_f != "All":
        conds.append("status=?"); params.append(status_f)
    if sev_f:
        conds.append(f"severity IN ({','.join(['?']*len(sev_f))})")
        params.extend(sev_f)
    if type_f and type_f != "All":
        conds.append("anomaly_type=?"); params.append(type_f)
    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    conn  = get_db()
    rows  = conn.execute(f"SELECT * FROM anomalies {where} ORDER BY detected_at DESC LIMIT {limit}", params).fetchall()
    conn.close()
    return pd.DataFrame([dict(r) for r in rows]) if rows else pd.DataFrame()


def update_status(aid, new_status):
    conn = get_db()
    conn.execute("UPDATE anomalies SET status=? WHERE id=?", (new_status, aid))
    conn.commit()
    conn.close()


# ── UI ────────────────────────────────────────

st.title("🧠 Anomaly & Behaviour Detection")
st.caption("Statistical baseline (Z-score) + rule-based detection across network and firewall logs")

# Action row
c1, c2, c3 = st.columns(3)

with c1:
    if st.button("🔍 Run Detection Now", type="primary", use_container_width=True):
        with st.spinner("Running detection..."):
            n1 = run_statistical_detection()
            n2 = run_rule_detection()
        total = n1 + n2
        if total:
            st.success(f"✅ {total} new anomalies found! ({n1} statistical, {n2} rule-based)")
        else:
            st.info("✅ Detection complete — no new anomalies in current window.")
        st.rerun()

with c2:
    days = st.selectbox("Baseline window", [3, 7, 14, 30], index=1, label_visibility="collapsed")
    if st.button("📊 Rebuild Baseline", use_container_width=True):
        with st.spinner("Building baseline from network logs..."):
            n = build_baseline(days)
        if n:
            st.success(f"✅ Baseline built from {n} IPs over last {days} days.")
        else:
            st.warning("No network log data found. Run some Attack Simulations first.")

with c3:
    if st.button("🔄 Refresh Page", use_container_width=True):
        st.rerun()

st.divider()

# Stats row
stats = get_stats()
s1, s2, s3, s4, s5 = st.columns(5)
s1.metric("Total Anomalies", stats["total"])
s2.metric("🔴 Open",         stats["open"])
s3.metric("🚨 Critical",     stats["critical"])
s4.metric("🟠 High",         stats["high"])
s5.metric("Types Found",     len(stats["by_type"]))

st.divider()

# Charts
cl, cr = st.columns([3, 2])

with cl:
    st.subheader("Anomalies by Type")
    if stats["by_type"]:
        df_t = pd.DataFrame(
            list(stats["by_type"].items()), columns=["Type", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(df_t.set_index("Type"))
    else:
        st.info("No anomaly data yet.\n\n**To generate data:**\n1. Go to 🎯 Attack Simulator\n2. Launch any attack\n3. Come back and click **Run Detection Now**")

with cr:
    st.subheader("🔝 Top IPs")
    if stats["top_ips"]:
        max_c = max(e["count"] for e in stats["top_ips"]) or 1
        for e in stats["top_ips"]:
            pct = int(e["count"] / max_c * 100)
            st.markdown(
                f"`{e['ip'] or 'Unknown'}` &nbsp; **{e['count']}**"
                f"<div style='background:#ef4444;width:{pct}%;height:5px;border-radius:3px;margin-top:2px'></div>",
                unsafe_allow_html=True
            )
    else:
        st.info("No IP data yet.")

st.divider()

# Filters
st.subheader("📋 Anomaly Log")
f1, f2, f3 = st.columns(3)
with f1:
    sev_f  = st.multiselect("Severity", ["critical","high","medium","low"], default=["critical","high","medium","low"])
with f2:
    stat_f = st.selectbox("Status", ["All","Open","Investigating","Resolved","False Positive"])
with f3:
    all_types = list(stats["by_type"].keys()) if stats["by_type"] else []
    type_f = st.selectbox("Type", ["All"] + all_types)

df = get_recent(200, stat_f, sev_f, type_f)

if not df.empty:
    icon_map = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}
    df["Sev"] = df["severity"].apply(lambda s: f"{icon_map.get(s,'⚪')} {s.title()}")

    show = [c for c in ["id","detected_at","source_ip","anomaly_type","Sev","z_score","description","status"] if c in df.columns or c == "Sev"]
    rename = {
        "id":"ID","detected_at":"Detected At","source_ip":"Source IP",
        "anomaly_type":"Type","Sev":"Severity","z_score":"Z-Score",
        "description":"Description","status":"Status"
    }
    st.dataframe(df[show].rename(columns=rename), use_container_width=True, height=380)

    st.subheader("🔧 Update Status")
    sel_id = st.selectbox("Select Anomaly ID", df["id"].tolist())
    new_st = st.selectbox("New Status", ["Open","Investigating","Resolved","False Positive"])
    if st.button("✅ Update Status", type="primary"):
        update_status(sel_id, new_st)
        st.success(f"Anomaly #{sel_id} updated to '{new_st}'")
        st.rerun()
else:
    st.info(
        "No anomalies match your filters.\n\n"
        "**Quick start:**\n"
        "1. Go to **🎯 Attack Simulator** → launch any attack\n"
        "2. Come back here → click **Run Detection Now**\n"
        "3. Anomalies will appear in this table"
    )

st.divider()

# Timeline
st.subheader("📈 Anomaly Timeline — Last 24 Hours")
try:
    conn  = get_db()
    df_tl = pd.read_sql_query("""
        SELECT strftime('%Y-%m-%d %H:00', detected_at) as hour,
               severity, COUNT(*) as count
        FROM anomalies
        WHERE detected_at >= datetime('now','-1 day')
        GROUP BY hour, severity ORDER BY hour
    """, conn)
    conn.close()
    if not df_tl.empty:
        pivot = df_tl.pivot_table(index="hour", columns="severity", values="count", fill_value=0)
        st.line_chart(pivot)
    else:
        st.info("No anomalies in the last 24 hours yet.")
except Exception as e:
    st.info(f"Timeline not available: {e}")

with st.expander("ℹ️ How Detection Works"):
    st.markdown("""
**Statistical (Z-Score)**
Builds a per-IP baseline from `network_logs` over N days (mean & std of daily request count).
Any IP with |Z| ≥ 2.5 in the current hour is flagged. Severity: |Z|≥4=Critical, ≥3=High, ≥2=Medium.

**Rule-Based Patterns**

| Rule | Source | Trigger |
|------|--------|---------|
| Brute Force | network_logs | ≥5 suspicious-status rows in 5 min |
| Port Scan | firewall_logs | ≥15 distinct destination ports in 2 min |
| High-Sev Events | firewall_logs | ≥3 critical/high severity rows per threat type in 1h |
| Data Exfiltration | network_logs | ≥5 MB bytes_sent in 10 min |

**Simulator Correlation**
Every Attack Simulator launch injects an anomaly row directly into this table.
    """)