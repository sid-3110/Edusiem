"""
anomaly_engine.py
-----------------
Behaviour-based & statistical anomaly detection for EduSIEM.
Drop this file in the root of your project (same level as main.py).

How it works
------------
1. build_baseline()  — reads last N days of network/firewall logs and
   computes per-IP statistics (mean, std) for request counts,
   failed-login counts, and bytes transferred.
2. score_events()    — compares today's window against the baseline
   using Z-score.  Anything |z| > threshold is flagged.
3. detect_behavioral_patterns() — rule-based patterns on top of stats:
   port-scan, brute-force burst, data-exfil spike, off-hours access.
4. persist_anomalies() — writes findings to the `anomalies` table so
   the dashboard and the log-search page can both query them.
"""

import sqlite3
import math
import json
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = "data/edusiem.db"

# ──────────────────────────────────────────────
# 1.  Database helpers
# ──────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_anomaly_table():
    """Create the anomalies table if it doesn't exist yet."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at     TEXT    NOT NULL,
            source_ip       TEXT,
            username        TEXT,
            anomaly_type    TEXT    NOT NULL,
            severity        TEXT    NOT NULL DEFAULT 'Medium',
            z_score         REAL,
            description     TEXT,
            raw_value       REAL,
            baseline_mean   REAL,
            baseline_std    REAL,
            status          TEXT    NOT NULL DEFAULT 'Open',
            linked_alert_id INTEGER,
            details_json    TEXT
        )
    """)
    # Behaviour baselines table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavior_baselines (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip       TEXT    NOT NULL,
            metric          TEXT    NOT NULL,
            mean            REAL    NOT NULL DEFAULT 0,
            std             REAL    NOT NULL DEFAULT 0,
            sample_count    INTEGER NOT NULL DEFAULT 0,
            last_updated    TEXT    NOT NULL,
            UNIQUE(source_ip, metric)
        )
    """)
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# 2.  Baseline builder
# ──────────────────────────────────────────────

def build_baseline(lookback_days: int = 7):
    """
    Reads network_logs for the last `lookback_days` days and computes
    per-IP mean/std for:
      - request_count   (rows per IP per day)
      - failed_count    (status != 200 rows per IP per day)
      - bytes_out       (sum bytes_sent per IP per day)
    Stores results in behavior_baselines.
    """
    ensure_anomaly_table()
    conn = get_db()
    cutoff = (datetime.now() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")

    # Check what columns exist in network_logs
    cols_raw = conn.execute("PRAGMA table_info(network_logs)").fetchall()
    col_names = [c["name"] for c in cols_raw] if cols_raw else []

    if not col_names:
        conn.close()
        return {}

    # Build a flexible query based on available columns
    select_parts = ["source_ip"]
    select_parts.append("COUNT(*) as request_count")

    if "status_code" in col_names:
        select_parts.append("SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END) as failed_count")
    else:
        select_parts.append("0 as failed_count")

    if "bytes_sent" in col_names:
        select_parts.append("SUM(COALESCE(bytes_sent,0)) as bytes_out")
    elif "bytes" in col_names:
        select_parts.append("SUM(COALESCE(bytes,0)) as bytes_out")
    else:
        select_parts.append("0 as bytes_out")

    ts_col = "timestamp" if "timestamp" in col_names else "created_at"
    date_expr = f"DATE({ts_col})" if ts_col in col_names else "'2024-01-01'"

    query = f"""
        SELECT {date_expr} as day, {', '.join(select_parts)}
        FROM network_logs
        WHERE {ts_col} >= ?
        GROUP BY day, source_ip
    """

    try:
        rows = conn.execute(query, (cutoff,)).fetchall()
    except Exception:
        conn.close()
        return {}

    # Aggregate per IP across days
    ip_data: dict = {}
    for row in rows:
        ip = row["source_ip"] or "unknown"
        if ip not in ip_data:
            ip_data[ip] = {"request_count": [], "failed_count": [], "bytes_out": []}
        ip_data[ip]["request_count"].append(row["request_count"])
        ip_data[ip]["failed_count"].append(row["failed_count"])
        ip_data[ip]["bytes_out"].append(row["bytes_out"])

    # Also pull from firewall_logs if available
    fw_cols_raw = conn.execute("PRAGMA table_info(firewall_logs)").fetchall()
    fw_col_names = [c["name"] for c in fw_cols_raw] if fw_cols_raw else []
    if fw_col_names and "source_ip" in fw_col_names:
        fw_ts = "timestamp" if "timestamp" in fw_col_names else "created_at"
        try:
            fw_rows = conn.execute(f"""
                SELECT source_ip, COUNT(*) as cnt,
                       DATE({fw_ts}) as day
                FROM firewall_logs
                WHERE {fw_ts} >= ?
                GROUP BY day, source_ip
            """, (cutoff,)).fetchall()
            for row in fw_rows:
                ip = row["source_ip"] or "unknown"
                if ip not in ip_data:
                    ip_data[ip] = {"request_count": [], "failed_count": [], "bytes_out": []}
        except Exception:
            pass

    # Persist baselines
    now_str = datetime.now().isoformat()
    for ip, metrics in ip_data.items():
        for metric_name, values in metrics.items():
            if not values:
                continue
            n = len(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n if n > 1 else 0
            std = math.sqrt(variance) if variance > 0 else 1.0  # avoid div-by-zero

            conn.execute("""
                INSERT INTO behavior_baselines (source_ip, metric, mean, std, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_ip, metric) DO UPDATE SET
                    mean=excluded.mean, std=excluded.std,
                    sample_count=excluded.sample_count, last_updated=excluded.last_updated
            """, (ip, metric_name, mean, std, n, now_str))

    conn.commit()
    conn.close()
    return ip_data


# ──────────────────────────────────────────────
# 3.  Z-score anomaly scorer
# ──────────────────────────────────────────────

def _zscore(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return (value - mean) / std


def _severity_from_zscore(z: float) -> str:
    az = abs(z)
    if az >= 4:
        return "Critical"
    if az >= 3:
        return "High"
    if az >= 2:
        return "Medium"
    return "Low"


def score_events(window_hours: int = 1, z_threshold: float = 2.5):
    """
    Scores events from the last `window_hours` hours against the stored
    baselines. Returns list of anomaly dicts and persists them to DB.
    """
    ensure_anomaly_table()
    conn = get_db()
    since = (datetime.now() - timedelta(hours=window_hours)).isoformat()

    # Current window counts per IP
    cols_raw = conn.execute("PRAGMA table_info(network_logs)").fetchall()
    col_names = [c["name"] for c in cols_raw] if cols_raw else []

    anomalies_found = []

    if col_names:
        ts_col = "timestamp" if "timestamp" in col_names else "created_at"
        try:
            recent = conn.execute(f"""
                SELECT source_ip, COUNT(*) as request_count
                FROM network_logs
                WHERE {ts_col} >= ?
                GROUP BY source_ip
            """, (since,)).fetchall()

            for row in recent:
                ip = row["source_ip"] or "unknown"
                val = row["request_count"]

                baseline = conn.execute("""
                    SELECT mean, std FROM behavior_baselines
                    WHERE source_ip=? AND metric='request_count'
                """, (ip,)).fetchone()

                if not baseline:
                    continue

                z = _zscore(val, baseline["mean"], baseline["std"])
                if abs(z) >= z_threshold:
                    sev = _severity_from_zscore(z)
                    desc = (f"IP {ip} made {val} requests in last {window_hours}h "
                            f"(baseline mean={baseline['mean']:.1f}, std={baseline['std']:.1f}, z={z:.2f})")
                    anomalies_found.append({
                        "source_ip": ip, "anomaly_type": "Traffic Volume Spike",
                        "severity": sev, "z_score": z, "description": desc,
                        "raw_value": val, "baseline_mean": baseline["mean"],
                        "baseline_std": baseline["std"]
                    })
        except Exception:
            pass

    # Persist
    now_str = datetime.now().isoformat()
    for a in anomalies_found:
        conn.execute("""
            INSERT INTO anomalies
            (detected_at, source_ip, anomaly_type, severity, z_score, description,
             raw_value, baseline_mean, baseline_std, status)
            VALUES (?,?,?,?,?,?,?,?,?,'Open')
        """, (now_str, a["source_ip"], a["anomaly_type"], a["severity"],
              a["z_score"], a["description"], a["raw_value"],
              a["baseline_mean"], a["baseline_std"]))

    conn.commit()
    conn.close()
    return anomalies_found


# ──────────────────────────────────────────────
# 4.  Rule-based behavioural pattern detection
# ──────────────────────────────────────────────

BEHAVIOR_RULES = [
    {
        "name": "Brute Force Burst",
        "anomaly_type": "Brute Force",
        "severity": "High",
        "description_tpl": "IP {ip} had {count} failed auth events in {window}min (threshold: {threshold})",
        "metric": "failed_logins",
        "window_minutes": 5,
        "threshold": 5,
    },
    {
        "name": "Port Scan",
        "anomaly_type": "Port Scan",
        "severity": "High",
        "description_tpl": "IP {ip} contacted {count} distinct ports in {window}min (threshold: {threshold})",
        "metric": "distinct_ports",
        "window_minutes": 2,
        "threshold": 15,
    },
    {
        "name": "Data Exfiltration Spike",
        "anomaly_type": "Data Exfiltration",
        "severity": "Critical",
        "description_tpl": "IP {ip} transferred {count} KB outbound in {window}min (threshold: {threshold} KB)",
        "metric": "bytes_out_kb",
        "window_minutes": 10,
        "threshold": 5000,
    },
    {
        "name": "Off-Hours Access",
        "anomaly_type": "Off-Hours Activity",
        "severity": "Medium",
        "description_tpl": "IP {ip} had {count} requests between 22:00-06:00 in last {window}min",
        "metric": "off_hours_requests",
        "window_minutes": 60,
        "threshold": 10,
    },
]


def detect_behavioral_patterns():
    """
    Runs rule-based detection against recent logs.
    Returns list of anomaly dicts and persists them.
    """
    ensure_anomaly_table()
    conn = get_db()
    now = datetime.now()
    anomalies_found = []

    cols_raw = conn.execute("PRAGMA table_info(network_logs)").fetchall()
    col_names = [c["name"] for c in cols_raw] if cols_raw else []
    fw_cols_raw = conn.execute("PRAGMA table_info(firewall_logs)").fetchall()
    fw_col_names = [c["name"] for c in fw_cols_raw] if fw_cols_raw else []

    # ── Brute Force: failed logins
    if col_names:
        ts_col = "timestamp" if "timestamp" in col_names else "created_at"
        window_start = (now - timedelta(minutes=5)).isoformat()
        rule = BEHAVIOR_RULES[0]
        try:
            status_col = "status_code" if "status_code" in col_names else None
            if status_col:
                rows = conn.execute(f"""
                    SELECT source_ip, COUNT(*) as cnt
                    FROM network_logs
                    WHERE {ts_col} >= ? AND {status_col} IN (401,403)
                    GROUP BY source_ip HAVING cnt >= ?
                """, (window_start, rule["threshold"])).fetchall()
                for row in rows:
                    ip = row["source_ip"] or "unknown"
                    desc = rule["description_tpl"].format(
                        ip=ip, count=row["cnt"],
                        window=rule["window_minutes"], threshold=rule["threshold"])
                    anomalies_found.append({
                        "source_ip": ip, "anomaly_type": rule["anomaly_type"],
                        "severity": rule["severity"], "z_score": None,
                        "description": desc, "raw_value": row["cnt"],
                        "baseline_mean": None, "baseline_std": None
                    })
        except Exception:
            pass

    # ── Port Scan: distinct destination ports
    if fw_col_names and "destination_port" in fw_col_names:
        ts_col = "timestamp" if "timestamp" in fw_col_names else "created_at"
        window_start = (now - timedelta(minutes=2)).isoformat()
        rule = BEHAVIOR_RULES[1]
        try:
            rows = conn.execute(f"""
                SELECT source_ip, COUNT(DISTINCT destination_port) as port_cnt
                FROM firewall_logs
                WHERE {ts_col} >= ?
                GROUP BY source_ip HAVING port_cnt >= ?
            """, (window_start, rule["threshold"])).fetchall()
            for row in rows:
                ip = row["source_ip"] or "unknown"
                desc = rule["description_tpl"].format(
                    ip=ip, count=row["port_cnt"],
                    window=rule["window_minutes"], threshold=rule["threshold"])
                anomalies_found.append({
                    "source_ip": ip, "anomaly_type": rule["anomaly_type"],
                    "severity": rule["severity"], "z_score": None,
                    "description": desc, "raw_value": row["port_cnt"],
                    "baseline_mean": None, "baseline_std": None
                })
        except Exception:
            pass

    # ── Off-Hours Access
    if col_names:
        ts_col = "timestamp" if "timestamp" in col_names else "created_at"
        window_start = (now - timedelta(minutes=60)).isoformat()
        rule = BEHAVIOR_RULES[3]
        try:
            rows = conn.execute(f"""
                SELECT source_ip, COUNT(*) as cnt
                FROM network_logs
                WHERE {ts_col} >= ?
                  AND (CAST(strftime('%H', {ts_col}) AS INTEGER) >= 22
                       OR CAST(strftime('%H', {ts_col}) AS INTEGER) < 6)
                GROUP BY source_ip HAVING cnt >= ?
            """, (window_start, rule["threshold"])).fetchall()
            for row in rows:
                ip = row["source_ip"] or "unknown"
                desc = rule["description_tpl"].format(
                    ip=ip, count=row["cnt"],
                    window=rule["window_minutes"], threshold=rule["threshold"])
                anomalies_found.append({
                    "source_ip": ip, "anomaly_type": rule["anomaly_type"],
                    "severity": rule["severity"], "z_score": None,
                    "description": desc, "raw_value": row["cnt"],
                    "baseline_mean": None, "baseline_std": None
                })
        except Exception:
            pass

    # Persist
    now_str = now.isoformat()
    for a in anomalies_found:
        conn.execute("""
            INSERT INTO anomalies
            (detected_at, source_ip, anomaly_type, severity, z_score, description,
             raw_value, baseline_mean, baseline_std, status)
            VALUES (?,?,?,?,?,?,?,?,?,'Open')
        """, (now_str, a["source_ip"], a["anomaly_type"], a["severity"],
              a.get("z_score"), a["description"], a.get("raw_value"),
              a.get("baseline_mean"), a.get("baseline_std")))

    conn.commit()
    conn.close()
    return anomalies_found


# ──────────────────────────────────────────────
# 5.  Simulator-side helper (called by Attack Simulator)
# ──────────────────────────────────────────────

def inject_simulated_anomaly(
    source_ip: str,
    anomaly_type: str,
    severity: str,
    description: str,
    z_score: Optional[float] = None,
    linked_alert_id: Optional[int] = None,
    details: Optional[dict] = None,
):
    """
    Called directly by the Attack Simulator page so simulated attacks
    appear as anomalies on the Anomaly Detection dashboard.
    """
    ensure_anomaly_table()
    conn = get_db()
    conn.execute("""
        INSERT INTO anomalies
        (detected_at, source_ip, anomaly_type, severity, z_score,
         description, status, linked_alert_id, details_json)
        VALUES (?,?,?,?,?,?,'Open',?,?)
    """, (
        datetime.now().isoformat(), source_ip, anomaly_type, severity,
        z_score, description, linked_alert_id,
        json.dumps(details) if details else None
    ))
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────
# 6.  Query helpers for UI pages
# ──────────────────────────────────────────────

def get_recent_anomalies(limit: int = 100, status: Optional[str] = None):
    ensure_anomaly_table()
    conn = get_db()
    if status:
        rows = conn.execute(
            "SELECT * FROM anomalies WHERE status=? ORDER BY detected_at DESC LIMIT ?",
            (status, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM anomalies ORDER BY detected_at DESC LIMIT ?",
            (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_anomaly_stats():
    ensure_anomaly_table()
    conn = get_db()
    stats = {}
    stats["total"] = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    stats["open"] = conn.execute("SELECT COUNT(*) FROM anomalies WHERE status='Open'").fetchone()[0]
    stats["critical"] = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE severity='Critical'").fetchone()[0]
    stats["high"] = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE severity='High'").fetchone()[0]

    by_type = conn.execute("""
        SELECT anomaly_type, COUNT(*) as cnt
        FROM anomalies GROUP BY anomaly_type ORDER BY cnt DESC
    """).fetchall()
    stats["by_type"] = {r["anomaly_type"]: r["cnt"] for r in by_type}

    by_ip = conn.execute("""
        SELECT source_ip, COUNT(*) as cnt
        FROM anomalies GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
    """).fetchall()
    stats["top_ips"] = [{"ip": r["source_ip"], "count": r["cnt"]} for r in by_ip]

    conn.close()
    return stats


def update_anomaly_status(anomaly_id: int, new_status: str):
    ensure_anomaly_table()
    conn = get_db()
    conn.execute("UPDATE anomalies SET status=? WHERE id=?", (new_status, anomaly_id))
    conn.commit()
    conn.close()


def run_full_detection():
    """Convenience: build baseline + run all detectors. Call from UI."""
    build_baseline(lookback_days=7)
    stat_anomalies = score_events(window_hours=1)
    rule_anomalies = detect_behavioral_patterns()
    return stat_anomalies + rule_anomalies