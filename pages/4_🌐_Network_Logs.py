"""
Edusiem Network Logs Page
pages/4_🌐_Network_Logs.py
Fixed: null-safe .upper() and .strftime() calls
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import get_database_engine, get_session, NetworkLog, Alert, User

st.set_page_config(page_title="Network Logs - EduSIEM", page_icon="🌐", layout="wide")

# ── Auth ──────────────────────────────────────
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.error("🔒 Please login first")
    st.stop()

# ── Null-safe helpers ─────────────────────────
def safe_upper(val, default="UNKNOWN"):
    return str(val).upper() if val else default

def safe_str(val, default="N/A"):
    return str(val) if val else default

def safe_ts(ts, fmt="%I:%M %p"):
    try:
        return ts.strftime(fmt) if ts else "N/A"
    except Exception:
        return "N/A"

def safe_ts_long(ts):
    return safe_ts(ts, "%B %d, %Y at %I:%M %p")

# ── Header ────────────────────────────────────
st.markdown("""
    <div style="background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
                padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🌐 Network Traffic Monitoring</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Real-time network activity analysis</p>
    </div>
""", unsafe_allow_html=True)

# ── DB session ────────────────────────────────
engine  = get_database_engine()
session = get_session(engine)

# ── Metrics ───────────────────────────────────
total_connections    = session.query(NetworkLog).count()
suspicious_count     = session.query(NetworkLog).filter(NetworkLog.status == "suspicious").count()
normal_count         = session.query(NetworkLog).filter(NetworkLog.status == "normal").count()
blocked_count        = session.query(NetworkLog).filter(NetworkLog.status == "blocked").count()

all_logs_for_bytes   = session.query(NetworkLog).all()
total_bytes          = sum((log.bytes_sent or 0) + (log.bytes_received or 0) for log in all_logs_for_bytes)
total_gb             = total_bytes / (1024**3) if total_bytes > 0 else 0

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Connections", total_connections)
c2.metric("⚠️ Suspicious",     suspicious_count, delta=f"+{suspicious_count}")
c3.metric("✅ Normal",          normal_count)
c4.metric("🚫 Blocked",        blocked_count)
c5.metric("💾 Data Transfer",  f"{total_gb:.2f} GB")

st.markdown("---")

# ── Filters ───────────────────────────────────
f1, f2, f3, f4 = st.columns(4)
with f1:
    protocol_filter = st.selectbox("Protocol",     ["All","TCP","UDP","ICMP","HTTP","HTTPS"])
with f2:
    status_filter   = st.selectbox("Status",       ["All","Normal","Suspicious","Blocked"])
with f3:
    threat_filter   = st.selectbox("Threat Level", ["All","Critical","High","Medium","Low"])
with f4:
    search_ip       = st.text_input("🔍 Search IP", placeholder="Enter IP address...")

st.markdown("---")

# ── Build query ───────────────────────────────
query = session.query(NetworkLog).order_by(NetworkLog.timestamp.desc())

if protocol_filter != "All":
    query = query.filter(NetworkLog.protocol == protocol_filter)
if status_filter != "All":
    query = query.filter(NetworkLog.status == status_filter.lower())
if threat_filter != "All":
    query = query.filter(NetworkLog.threat_level == threat_filter.lower())
if search_ip:
    query = query.filter(
        (NetworkLog.source_ip.like(f"%{search_ip}%")) |
        (NetworkLog.destination_ip.like(f"%{search_ip}%"))
    )

network_logs = query.limit(100).all()

# ── Charts ────────────────────────────────────
if total_connections > 0:
    st.markdown("### 📊 Network Analytics")
    ch1, ch2 = st.columns(2)

    with ch1:
        now        = datetime.now()
        hours_data = []
        for i in range(24, 0, -1):
            h_start = now - timedelta(hours=i)
            h_end   = now - timedelta(hours=i - 1)
            cnt     = session.query(NetworkLog).filter(
                NetworkLog.timestamp.between(h_start, h_end)
            ).count()
            hours_data.append({"Hour": h_start.strftime("%H:%M"), "Connections": cnt})

        df_h = pd.DataFrame(hours_data)
        fig  = px.area(df_h, x="Hour", y="Connections", title="📈 Network Traffic (Last 24 Hours)")
        fig.update_traces(line_color="#06b6d4", fillcolor="rgba(6,182,212,0.3)")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,41,59,0.5)",
            font={"color": "white"}, height=300,
        )
        st.plotly_chart(fig, use_container_width=True)

    with ch2:
        proto_counts = {}
        for log in all_logs_for_bytes:
            p = log.protocol or "Unknown"
            proto_counts[p] = proto_counts.get(p, 0) + 1

        if proto_counts:
            df_p = pd.DataFrame(list(proto_counts.items()), columns=["Protocol", "Count"])
            fig  = go.Figure(data=[go.Pie(
                labels=df_p["Protocol"], values=df_p["Count"], hole=0.4,
                marker=dict(colors=["#3b82f6","#06b6d4","#10b981","#f59e0b","#8b5cf6"])
            )])
            fig.update_layout(
                title="📊 Protocol Distribution",
                paper_bgcolor="rgba(0,0,0,0)",
                font={"color": "white"}, height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ── Log table ─────────────────────────────────
st.markdown("### 📋 Network Connection Logs")

STATUS_COLORS = {
    "normal":     "#10b981",
    "suspicious": "#f59e0b",
    "blocked":    "#ef4444",
}
THREAT_COLORS = {
    "low":      "#10b981",
    "medium":   "#3b82f6",
    "high":     "#f59e0b",
    "critical": "#dc2626",
}

if not network_logs:
    st.info("📭 No network logs found. Run attack simulations to generate logs.")
else:
    st.write(f"**Showing {len(network_logs)} most recent connections**")

    for log in network_logs:
        # ── Null-safe values ──────────────────
        src_ip   = safe_str(log.source_ip,        "Unknown")
        src_port = safe_str(log.source_port,       "?")
        dst_ip   = safe_str(log.destination_ip,    "Unknown")
        dst_port = safe_str(log.destination_port,  "?")
        protocol = safe_str(log.protocol,          "Unknown")
        status   = (log.status or "unknown").lower()
        threat   = (log.threat_level or "low").lower()
        ts_short = safe_ts(log.timestamp)
        ts_long  = safe_ts_long(log.timestamp)

        with st.expander(
            f"**{src_ip}:{src_port}** → **{dst_ip}:{dst_port}** ({protocol}) — {ts_short}",
            expanded=False
        ):
            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown("**Source:**")
                st.write(f"IP: {src_ip}")
                st.write(f"Port: {src_port}")
                if log.user_id:
                    user = session.query(User).get(log.user_id)
                    st.write(f"User: {user.username if user else 'Unknown'}")

            with col2:
                st.markdown("**Destination:**")
                st.write(f"IP: {dst_ip}")
                st.write(f"Port: {dst_port}")
                st.write(f"Protocol: {protocol}")

            with col3:
                st.markdown("**Details:**")
                st.markdown(
                    f"**Status:** <span style='background:{STATUS_COLORS.get(status,'#64748b')};"
                    f"color:white;padding:0.25rem 0.75rem;border-radius:12px;"
                    f"font-weight:700;'>{status.upper()}</span>",
                    unsafe_allow_html=True
                )
                st.markdown(
                    f"**Threat:** <span style='background:{THREAT_COLORS.get(threat,'#64748b')};"
                    f"color:white;padding:0.25rem 0.75rem;border-radius:12px;"
                    f"font-weight:700;'>{threat.upper()}</span>",
                    unsafe_allow_html=True
                )
                st.write(f"Time: {ts_long}")

            st.markdown("---")
            st.markdown("**Traffic Details:**")
            ca, cb, cc = st.columns(3)
            with ca:
                st.write(f"📤 Sent: {(log.bytes_sent or 0) / (1024*1024):.2f} MB")
            with cb:
                st.write(f"📥 Received: {(log.bytes_received or 0) / (1024*1024):.2f} MB")
            with cc:
                st.write(f"📦 Packets: {log.packets or 0}")

            if log.connection_state:
                st.write(f"**Connection State:** {log.connection_state}")
            if log.duration:
                st.write(f"**Duration:** {log.duration} seconds")

            # Linked alert
            if log.alert_id:
                st.markdown("---")
                alert = session.query(Alert).get(log.alert_id)
                if alert:
                    sev = safe_upper(alert.severity)
                    st.warning(f"⚠️ **This connection triggered Alert #{alert.id}**")
                    st.write(f"**Alert:** {alert.title}")
                    st.write(f"**Severity:** {sev}")
                    if st.button("View Alert Details", key=f"view_alert_net_{log.id}"):
                        st.info("👉 Go to Alerts page to review this alert")

# ── Top talkers ───────────────────────────────
st.markdown("---")
st.markdown("### 🔝 Top Network Talkers")

t1, t2 = st.columns(2)

with t1:
    st.markdown("#### 📤 Top Sources (Outbound)")
    src_counts = {}
    for log in session.query(NetworkLog).all():
        ip = log.source_ip or "Unknown"
        src_counts[ip] = src_counts.get(ip, 0) + 1
    for ip, cnt in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        st.info(f"**{ip}** — {cnt} connection(s)")
    if not src_counts:
        st.write("No data available")

with t2:
    st.markdown("#### 📥 Top Destinations (Inbound)")
    dst_counts = {}
    for log in session.query(NetworkLog).all():
        ip = log.destination_ip or "Unknown"
        dst_counts[ip] = dst_counts.get(ip, 0) + 1
    for ip, cnt in sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        st.info(f"**{ip}** — {cnt} connection(s)")
    if not dst_counts:
        st.write("No data available")

session.close()