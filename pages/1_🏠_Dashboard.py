"""
EduSIEM Dashboard - Fully Correlated with Live Database
Pulls real data from: alerts, incidents, network_logs, firewall_logs, anomalies
Correlated with Attack Simulator, Anomaly Detection, and Log Search pages.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import sqlite3
import sys
import os
from datetime import datetime, timedelta

# ── Path setup so anomaly_engine can be imported ──────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="Dashboard - EduSIEM", page_icon="🏠", layout="wide")

# ── Auth check ────────────────────────────────────────────────────────────────
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.error("🔒 Please login first")
    st.stop()

user = st.session_state.get("user", {})
user_role = user.get("role", "student") if isinstance(user, dict) else "student"
user_name = user.get("username", "User") if isinstance(user, dict) else str(user)

DB_PATH = "data/edusiem.db"

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .dashboard-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #06b6d4 100%);
        padding: 2.5rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        box-shadow: 0 20px 60px rgba(59, 130, 246, 0.3);
    }
    .dashboard-header h1 { color: white; font-size: 2.5rem; font-weight: 800; margin: 0; }
    .dashboard-header p  { color: rgba(255,255,255,0.9); font-size: 1.1rem; margin: 0.5rem 0 0 0; }

    .stat-card {
        background: #1e293b;
        border-radius: 14px;
        padding: 1.2rem 1.4rem;
        border-left: 4px solid #3b82f6;
        margin-bottom: 0.5rem;
    }
    .sev-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.65rem 1rem;
        background: #1e293b;
        border-radius: 8px;
        margin-bottom: 0.45rem;
    }
    .badge {
        color: white;
        padding: 0.2rem 0.65rem;
        border-radius: 10px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .corr-tag {
        display: inline-block;
        font-size: 0.7rem;
        padding: 0.15rem 0.5rem;
        border-radius: 6px;
        background: #334155;
        color: #94a3b8;
        margin-left: 0.4rem;
        vertical-align: middle;
    }
    .feed-item {
        background: #1e293b;
        border-left: 3px solid #3b82f6;
        border-radius: 8px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        color: white;
    }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════
#  DATABASE HELPERS
# ══════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(name: str) -> bool:
    conn = get_db()
    r = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    conn.close()
    return r is not None


def col_exists(table: str, col: str) -> bool:
    conn = get_db()
    cols = [c["name"] for c in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    conn.close()
    return col in cols


def safe_count(sql: str, params=()) -> int:
    try:
        conn = get_db()
        result = conn.execute(sql, params).fetchone()
        conn.close()
        return result[0] if result else 0
    except Exception:
        return 0


# ══════════════════════════════════════════════
#  LIVE DATA LOADERS
# ══════════════════════════════════════════════

@st.cache_data(ttl=15)   # refresh every 15 seconds
def load_all_dashboard_data():
    data = {}

    # ── ALERTS ────────────────────────────────
    if table_exists("alerts"):
        data["alerts_total"]    = safe_count("SELECT COUNT(*) FROM alerts")
        data["alerts_new"]      = safe_count("SELECT COUNT(*) FROM alerts WHERE status='New'")
        data["alerts_critical"] = safe_count("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")
        data["alerts_high"]     = safe_count("SELECT COUNT(*) FROM alerts WHERE severity='High'")
        data["alerts_medium"]   = safe_count("SELECT COUNT(*) FROM alerts WHERE severity='Medium'")
        data["alerts_low"]      = safe_count("SELECT COUNT(*) FROM alerts WHERE severity='Low'")

        # Last 24 h alert trend (hourly)
        try:
            conn = get_db()
            ts_col = "created_at" if col_exists("alerts", "created_at") else "timestamp"
            rows = conn.execute(f"""
                SELECT strftime('%H:00', {ts_col}) as hour, COUNT(*) as cnt
                FROM alerts
                WHERE {ts_col} >= datetime('now', '-1 day')
                GROUP BY hour ORDER BY hour
            """).fetchall()
            conn.close()
            data["alerts_hourly"] = [{"hour": r["hour"], "count": r["cnt"]} for r in rows]
        except Exception:
            data["alerts_hourly"] = []

        # Alert type breakdown
        try:
            conn = get_db()
            type_col = next(
                (c for c in ["attack_type", "alert_type", "category"] if col_exists("alerts", c)),
                None
            )
            if type_col:
                rows = conn.execute(f"""
                    SELECT {type_col} as atype, COUNT(*) as cnt
                    FROM alerts
                    WHERE {type_col} IS NOT NULL
                    GROUP BY {type_col} ORDER BY cnt DESC LIMIT 6
                """).fetchall()
                conn.close()
                data["alert_types"] = [{"type": r["atype"] or "Unknown", "count": r["cnt"]} for r in rows]
            else:
                conn.close()
                data["alert_types"] = []
        except Exception:
            data["alert_types"] = []

        # Recent alerts for feed
        try:
            conn = get_db()
            ts_col = "created_at" if col_exists("alerts", "created_at") else "timestamp"
            rows = conn.execute(f"""
                SELECT id, title, severity, status, {ts_col} as ts
                FROM alerts ORDER BY {ts_col} DESC LIMIT 8
            """).fetchall()
            conn.close()
            data["recent_alerts"] = [dict(r) for r in rows]
        except Exception:
            data["recent_alerts"] = []
    else:
        data.update({
            "alerts_total": 0, "alerts_new": 0, "alerts_critical": 0,
            "alerts_high": 0, "alerts_medium": 0, "alerts_low": 0,
            "alerts_hourly": [], "alert_types": [], "recent_alerts": []
        })

    # ── INCIDENTS ─────────────────────────────
    if table_exists("incidents"):
        data["inc_open"]        = safe_count("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved','Closed')")
        data["inc_resolved"]    = safe_count("SELECT COUNT(*) FROM incidents WHERE status IN ('Resolved','Closed')")
        data["inc_total"]       = safe_count("SELECT COUNT(*) FROM incidents")
        data["inc_investigating"]= safe_count("SELECT COUNT(*) FROM incidents WHERE status='Investigating'")
    else:
        data.update({"inc_open": 0, "inc_resolved": 0, "inc_total": 0, "inc_investigating": 0})

    # ── NETWORK LOGS ──────────────────────────
    if table_exists("network_logs"):
        net_cols = []
        conn = get_db()
        net_cols = [c["name"] for c in conn.execute("PRAGMA table_info(network_logs)").fetchall()]
        conn.close()

        ts_col = "timestamp" if "timestamp" in net_cols else "created_at"
        data["net_logs_24h"] = safe_count(
            f"SELECT COUNT(*) FROM network_logs WHERE {ts_col} >= datetime('now','-1 day')"
        )
        data["net_logs_total"] = safe_count("SELECT COUNT(*) FROM network_logs")

        # Unique source IPs today
        try:
            conn = get_db()
            r = conn.execute(
                f"SELECT COUNT(DISTINCT source_ip) FROM network_logs WHERE {ts_col} >= datetime('now','-1 day')"
            ).fetchone()
            conn.close()
            data["unique_ips_24h"] = r[0] if r else 0
        except Exception:
            data["unique_ips_24h"] = 0

        # Top source IPs (last 24 h)
        try:
            conn = get_db()
            rows = conn.execute(f"""
                SELECT source_ip, COUNT(*) as cnt
                FROM network_logs
                WHERE {ts_col} >= datetime('now','-1 day')
                  AND source_ip IS NOT NULL
                GROUP BY source_ip ORDER BY cnt DESC LIMIT 5
            """).fetchall()
            conn.close()
            data["top_ips"] = [{"ip": r["source_ip"], "count": r["cnt"]} for r in rows]
        except Exception:
            data["top_ips"] = []

        # Hourly traffic last 24 h
        try:
            conn = get_db()
            rows = conn.execute(f"""
                SELECT strftime('%H:00', {ts_col}) as hour, COUNT(*) as cnt
                FROM network_logs
                WHERE {ts_col} >= datetime('now', '-1 day')
                GROUP BY hour ORDER BY hour
            """).fetchall()
            conn.close()
            data["net_hourly"] = [{"hour": r["hour"], "count": r["cnt"]} for r in rows]
        except Exception:
            data["net_hourly"] = []
    else:
        data.update({
            "net_logs_24h": 0, "net_logs_total": 0,
            "unique_ips_24h": 0, "top_ips": [], "net_hourly": []
        })

    # ── FIREWALL LOGS ─────────────────────────
    if table_exists("firewall_logs"):
        fw_cols = []
        conn = get_db()
        fw_cols = [c["name"] for c in conn.execute("PRAGMA table_info(firewall_logs)").fetchall()]
        conn.close()

        ts_col = "timestamp" if "timestamp" in fw_cols else "created_at"
        data["fw_total_24h"] = safe_count(
            f"SELECT COUNT(*) FROM firewall_logs WHERE {ts_col} >= datetime('now','-1 day')"
        )

        if "action" in fw_cols:
            data["fw_blocks_24h"] = safe_count(
                f"SELECT COUNT(*) FROM firewall_logs WHERE {ts_col} >= datetime('now','-1 day') AND action LIKE '%BLOCK%'"
            )
        else:
            data["fw_blocks_24h"] = 0
    else:
        data.update({"fw_total_24h": 0, "fw_blocks_24h": 0})

    # ── ANOMALIES ─────────────────────────────
    if table_exists("anomalies"):
        data["anom_open"]     = safe_count("SELECT COUNT(*) FROM anomalies WHERE status='Open'")
        data["anom_critical"] = safe_count("SELECT COUNT(*) FROM anomalies WHERE severity='Critical' AND status='Open'")
        data["anom_total"]    = safe_count("SELECT COUNT(*) FROM anomalies")

        # Anomaly type breakdown
        try:
            conn = get_db()
            rows = conn.execute("""
                SELECT anomaly_type, COUNT(*) as cnt
                FROM anomalies GROUP BY anomaly_type ORDER BY cnt DESC LIMIT 6
            """).fetchall()
            conn.close()
            data["anom_types"] = [{"type": r["anomaly_type"], "count": r["cnt"]} for r in rows]
        except Exception:
            data["anom_types"] = []

        # Recent anomalies
        try:
            conn = get_db()
            rows = conn.execute("""
                SELECT id, source_ip, anomaly_type, severity, detected_at, status
                FROM anomalies ORDER BY detected_at DESC LIMIT 6
            """).fetchall()
            conn.close()
            data["recent_anomalies"] = [dict(r) for r in rows]
        except Exception:
            data["recent_anomalies"] = []
    else:
        data.update({
            "anom_open": 0, "anom_critical": 0,
            "anom_total": 0, "anom_types": [], "recent_anomalies": []
        })

    # ── THREAT LEVEL (derived from live data) ─
    crit = data.get("alerts_critical", 0) + data.get("anom_critical", 0)
    high = data.get("alerts_high", 0)
    if crit >= 3 or data.get("inc_open", 0) >= 5:
        data["threat_level"] = "CRITICAL"
    elif crit >= 1 or high >= 5:
        data["threat_level"] = "HIGH"
    elif data.get("alerts_new", 0) >= 3 or data.get("anom_open", 0) >= 2:
        data["threat_level"] = "MEDIUM"
    else:
        data["threat_level"] = "LOW"

    return data


# ══════════════════════════════════════════════
#  LOAD DATA
# ══════════════════════════════════════════════

data = load_all_dashboard_data()

threat_colors = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#f59e0b",
    "MEDIUM":   "#f97316",
    "LOW":      "#10b981",
}
sev_colors = {
    "Critical": "#dc2626",
    "High":     "#f59e0b",
    "Medium":   "#3b82f6",
    "Low":      "#10b981",
}
tcolor = threat_colors.get(data["threat_level"], "#3b82f6")


# ══════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════

st.markdown(f"""
    <div class="dashboard-header">
        <h1>🛡️ Security Operations Dashboard</h1>
        <p>Real-time threat monitoring — all data live from database</p>
        <div style="color:rgba(255,255,255,0.7); margin-top:0.5rem; font-size:0.9rem;">
            👤 {user_name.title()} &nbsp;|&nbsp; Role: {user_role.title()} &nbsp;|&nbsp;
            Last updated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
        </div>
    </div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════
#  ROW 1 — TOP KPI METRICS (7 cards)
# ══════════════════════════════════════════════

c1, c2, c3, c4, c5, c6, c7 = st.columns(7)

c1.metric("🚨 Alerts",        data["alerts_total"],
          delta=f"{data['alerts_new']} new", delta_color="inverse")

c2.metric("🔴 Critical",      data["alerts_critical"])

c3.metric("📝 Open Incidents", data["inc_open"],
          delta=f"{data['inc_resolved']} resolved")

c4.metric("🌐 Net Logs (24h)", data["net_logs_24h"])

c5.metric("🔥 FW Blocks",     data["fw_blocks_24h"])

c6.metric("🧠 Anomalies",     data["anom_open"],
          delta=f"{data['anom_critical']} critical", delta_color="inverse")

with c7:
    st.markdown(f"""
        <div style="text-align:center; padding:1rem 0.5rem; background:#1e293b;
                    border-radius:12px; border:2px solid {tcolor};">
            <div style="color:#94a3b8; font-size:0.75rem; text-transform:uppercase; letter-spacing:1px;">
                ⚡ Threat Level
            </div>
            <div style="color:{tcolor}; font-size:1.6rem; font-weight:800; margin-top:0.3rem;">
                {data["threat_level"]}
            </div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ══════════════════════════════════════════════
#  ROW 2 — CHARTS
# ══════════════════════════════════════════════

col_left, col_right = st.columns(2)

# ── Alerts over 24 h (line) ───────────────────
with col_left:
    st.markdown("#### 📊 Alerts — Last 24 Hours")
    if data["alerts_hourly"]:
        df_h = pd.DataFrame(data["alerts_hourly"])
        fig = px.line(df_h, x="hour", y="count")
        fig.update_traces(line_color="#3b82f6", line_width=3,
                          fill="tozeroy", fillcolor="rgba(59,130,246,0.15)")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,41,59,0.5)",
            font={"color": "white"},
            height=280,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": ""},
            yaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": "Count"},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert data yet — run the Attack Simulator to generate events.")

# ── Alert type donut ──────────────────────────
with col_right:
    st.markdown("#### 🎯 Alert Distribution by Type")
    if data["alert_types"]:
        labels = [d["type"] for d in data["alert_types"]]
        values = [d["count"] for d in data["alert_types"]]
        colors = ["#ef4444", "#f59e0b", "#3b82f6", "#10b981", "#8b5cf6", "#06b6d4"]
        fig = go.Figure(data=[go.Pie(
            labels=labels, values=values, hole=0.42,
            marker=dict(colors=colors[:len(labels)],
                        line=dict(color="#0f172a", width=2))
        )])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "white"}, showlegend=True,
            height=280, margin=dict(l=10, r=10, t=10, b=10),
            legend=dict(bgcolor="rgba(0,0,0,0)")
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert type data yet.")


# ══════════════════════════════════════════════
#  ROW 3 — NETWORK TRAFFIC + ANOMALY BREAKDOWN
# ══════════════════════════════════════════════

col_net, col_anom = st.columns(2)

# ── Network traffic bar chart ─────────────────
with col_net:
    st.markdown("#### 🌐 Network Traffic — Last 24 Hours")
    if data["net_hourly"]:
        df_net = pd.DataFrame(data["net_hourly"])
        fig = px.bar(df_net, x="hour", y="count", color_discrete_sequence=["#06b6d4"])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,41,59,0.5)",
            font={"color": "white"}, height=260,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": ""},
            yaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": "Requests"},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No network log data yet.")

# ── Anomaly breakdown bar chart ───────────────
with col_anom:
    st.markdown("#### 🧠 Anomaly Types Detected")
    if data["anom_types"]:
        df_at = pd.DataFrame(data["anom_types"]).sort_values("count", ascending=True)
        fig = px.bar(df_at, x="count", y="type", orientation="h",
                     color_discrete_sequence=["#8b5cf6"])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,41,59,0.5)",
            font={"color": "white"}, height=260,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": "Count"},
            yaxis={"gridcolor": "rgba(148,163,184,0.1)", "title": ""},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No anomaly data yet — open Anomaly Detection and click Run Detection.")


# ══════════════════════════════════════════════
#  ROW 4 — SEVERITY BREAKDOWN + INCIDENT STATUS + TOP IPs
# ══════════════════════════════════════════════

col_sev, col_inc, col_ip = st.columns(3)

# ── Alert severity breakdown ─────────────────
with col_sev:
    st.markdown("#### 🔴 Alert Severity Breakdown")
    for sev, count in [
        ("Critical", data["alerts_critical"]),
        ("High",     data["alerts_high"]),
        ("Medium",   data["alerts_medium"]),
        ("Low",      data["alerts_low"]),
    ]:
        color = sev_colors[sev]
        st.markdown(f"""
            <div class="sev-bar" style="border-left: 4px solid {color};">
                <span style="color:white; font-weight:600;">{sev}</span>
                <span class="badge" style="background:{color};">{count}</span>
            </div>
        """, unsafe_allow_html=True)

# ── Incident status donut ─────────────────────
with col_inc:
    st.markdown("#### 📝 Incident Status")
    inc_labels = ["Open", "Investigating", "Resolved"]
    inc_values = [
        data["inc_open"] - data["inc_investigating"],
        data["inc_investigating"],
        data["inc_resolved"],
    ]
    inc_values = [max(v, 0) for v in inc_values]
    if sum(inc_values) > 0:
        fig = go.Figure(data=[go.Pie(
            labels=inc_labels, values=inc_values, hole=0.5,
            marker=dict(colors=["#ef4444", "#f59e0b", "#10b981"],
                        line=dict(color="#0f172a", width=2))
        )])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "white"}, showlegend=True,
            height=230, margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", y=-0.15)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.metric("Total Incidents", data["inc_total"])
        st.info("No incident data yet.")

# ── Top source IPs ────────────────────────────
with col_ip:
    st.markdown("#### 🌐 Top Source IPs (24h)")
    if data["top_ips"]:
        max_count = max(d["count"] for d in data["top_ips"]) or 1
        for entry in data["top_ips"]:
            pct = int((entry["count"] / max_count) * 100)
            st.markdown(f"""
                <div style="margin-bottom:0.5rem;">
                    <div style="display:flex; justify-content:space-between; color:white; font-size:0.85rem; margin-bottom:2px;">
                        <code>{entry['ip']}</code>
                        <span style="color:#94a3b8;">{entry['count']} req</span>
                    </div>
                    <div style="background:#334155; border-radius:4px; height:6px;">
                        <div style="background:#3b82f6; width:{pct}%; height:6px; border-radius:4px;"></div>
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No network IP data yet.")


# ══════════════════════════════════════════════
#  ROW 5 — ACTIVITY FEED (correlated from DB)
# ══════════════════════════════════════════════

st.markdown("---")
col_feed, col_anom_feed = st.columns(2)

# ── Recent alerts feed ────────────────────────
with col_feed:
    st.markdown("#### ⚡ Recent Alert Feed")
    sev_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    if data["recent_alerts"]:
        for a in data["recent_alerts"]:
            icon = sev_icons.get(a.get("severity", ""), "⚪")
            ts_raw = a.get("ts") or a.get("created_at") or ""
            try:
                ts_dt = datetime.fromisoformat(str(ts_raw))
                diff = datetime.now() - ts_dt
                mins = int(diff.total_seconds() / 60)
                time_str = f"{mins}m ago" if mins < 60 else f"{mins//60}h ago"
            except Exception:
                time_str = str(ts_raw)[:16]

            status_color = {"New": "#ef4444", "True Positive": "#f59e0b",
                            "False Positive": "#10b981", "Closed": "#6b7280"}.get(
                                a.get("status", ""), "#3b82f6")
            st.markdown(f"""
                <div class="feed-item">
                    {icon} <strong>#{a.get('id','?')}</strong> {a.get('title','Unknown Alert')}
                    <div style="color:#94a3b8; font-size:0.8rem; margin-top:0.3rem;">
                        🕐 {time_str} &nbsp;
                        <span style="color:{status_color}; font-weight:600;">● {a.get('status','New')}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts yet. Use the 🎯 Attack Simulator to generate correlated events.")

# ── Recent anomalies feed ─────────────────────
with col_anom_feed:
    st.markdown("#### 🧠 Recent Anomaly Feed")
    if data["recent_anomalies"]:
        for a in data["recent_anomalies"]:
            icon = sev_icons.get(a.get("severity", ""), "⚪")
            ts_raw = a.get("detected_at") or ""
            try:
                ts_dt = datetime.fromisoformat(str(ts_raw))
                diff = datetime.now() - ts_dt
                mins = int(diff.total_seconds() / 60)
                time_str = f"{mins}m ago" if mins < 60 else f"{mins//60}h ago"
            except Exception:
                time_str = str(ts_raw)[:16]

            st.markdown(f"""
                <div class="feed-item" style="border-left-color:#8b5cf6;">
                    {icon} <strong>{a.get('anomaly_type','Unknown')}</strong>
                    <div style="color:#94a3b8; font-size:0.8rem;">
                        IP: <code>{a.get('source_ip','?')}</code>
                    </div>
                    <div style="color:#94a3b8; font-size:0.8rem; margin-top:0.2rem;">
                        🕐 {time_str} &nbsp; ● {a.get('status','Open')}
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No anomalies yet. Open 🧠 Anomaly Detection and click Run Detection.")


# ══════════════════════════════════════════════
#  ROW 6 — QUICK NAVIGATION SHORTCUTS
# ══════════════════════════════════════════════

st.markdown("---")
st.markdown("#### 🚀 Quick Actions")

qc1, qc2, qc3, qc4, qc5 = st.columns(5)
with qc1:
    st.markdown("""
        <div class="stat-card" style="border-color:#ef4444; text-align:center;">
            <div style="font-size:1.8rem;">🎯</div>
            <div style="color:white; font-weight:700; margin-top:0.3rem;">Attack Simulator</div>
            <div style="color:#94a3b8; font-size:0.8rem;">Launch attack scenarios</div>
        </div>
    """, unsafe_allow_html=True)
with qc2:
    st.markdown("""
        <div class="stat-card" style="border-color:#8b5cf6; text-align:center;">
            <div style="font-size:1.8rem;">🧠</div>
            <div style="color:white; font-weight:700; margin-top:0.3rem;">Anomaly Detection</div>
            <div style="color:#94a3b8; font-size:0.8rem;">Run detection engine</div>
        </div>
    """, unsafe_allow_html=True)
with qc3:
    st.markdown("""
        <div class="stat-card" style="border-color:#06b6d4; text-align:center;">
            <div style="font-size:1.8rem;">🔎</div>
            <div style="color:white; font-weight:700; margin-top:0.3rem;">Log Search</div>
            <div style="color:#94a3b8; font-size:0.8rem;">Search all logs & IPs</div>
        </div>
    """, unsafe_allow_html=True)
with qc4:
    st.markdown("""
        <div class="stat-card" style="border-color:#f59e0b; text-align:center;">
            <div style="font-size:1.8rem;">🚨</div>
            <div style="color:white; font-weight:700; margin-top:0.3rem;">Alerts</div>
            <div style="color:#94a3b8; font-size:0.8rem;">Review & triage</div>
        </div>
    """, unsafe_allow_html=True)
with qc5:
    st.markdown("""
        <div class="stat-card" style="border-color:#10b981; text-align:center;">
            <div style="font-size:1.8rem;">📄</div>
            <div style="color:white; font-weight:700; margin-top:0.3rem;">Reports</div>
            <div style="color:#94a3b8; font-size:0.8rem;">Generate security reports</div>
        </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════

st.markdown("<br>", unsafe_allow_html=True)
col_ref, col_note = st.columns([1, 4])
with col_ref:
    if st.button("🔄 Refresh Dashboard", use_container_width=True, type="primary"):
        st.cache_data.clear()
        st.rerun()
with col_note:
    st.caption(
        "📌 All metrics are live from `data/edusiem.db`. "
        "Run the **Attack Simulator** to generate correlated events across all pages. "
        "Threat level is auto-calculated from critical alert + anomaly counts."
    )