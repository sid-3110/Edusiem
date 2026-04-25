"""
Edusiem Firewall Logs Page
Monitor firewall events and blocked threats with real correlation
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    FirewallLog, Alert
)

st.set_page_config(page_title="Firewall Logs - Edusiem", page_icon="🔥", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🔥 Firewall Security Events</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Monitor blocked threats and firewall rules</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Get metrics
total_events = session.query(FirewallLog).count()
blocked_today = session.query(FirewallLog).filter(
    FirewallLog.action == 'block',
    FirewallLog.timestamp >= datetime.now().replace(hour=0, minute=0, second=0)
).count()
allowed = session.query(FirewallLog).filter(FirewallLog.action == 'allow').count()
dropped = session.query(FirewallLog).filter(FirewallLog.action == 'drop').count()

# Count unique threat types
all_logs = session.query(FirewallLog).all()
threat_types = set(log.threat_type for log in all_logs if log.threat_type)
unique_threats = len(threat_types)

# Metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Events", total_events)

with col2:
    st.metric("Blocked Today", blocked_today, delta=f"+{blocked_today}")

with col3:
    st.metric("Allowed", allowed)

with col4:
    st.metric("Dropped", dropped)

with col5:
    st.metric("Threat Types", unique_threats)

st.markdown("---")

# Filters
col1, col2, col3 = st.columns(3)

with col1:
    action_filter = st.selectbox("Action", ["All", "Block", "Allow", "Drop", "Reject"])

with col2:
    threat_filter = st.selectbox(
        "Threat Type",
        ["All", "Port Scan", "Brute Force", "Malware", "SQL Injection", "Intrusion Attempt", "DDoS"]
    )

with col3:
    severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])

st.markdown("---")

# Build query
query = session.query(FirewallLog).order_by(FirewallLog.timestamp.desc())

if action_filter != "All":
    query = query.filter(FirewallLog.action == action_filter.lower())

if threat_filter != "All":
    threat_map = {
        "Port Scan": "port_scan",
        "Brute Force": "brute_force",
        "Malware": "malware",
        "SQL Injection": "sql_injection",
        "Intrusion Attempt": "intrusion_attempt",
        "DDoS": "ddos"
    }
    query = query.filter(FirewallLog.threat_type == threat_map[threat_filter])

if severity_filter != "All":
    query = query.filter(FirewallLog.severity == severity_filter.lower())

# Get logs
firewall_logs = query.limit(100).all()

# Charts
if total_events > 0:
    st.markdown("### 📊 Firewall Analytics")

    col1, col2 = st.columns(2)

    with col1:
        # Actions over time
        now = datetime.now()
        hours_data = {
            'Hour': [],
            'Blocked': [],
            'Allowed': []
        }

        for i in range(24, 0, -1):
            hour_start = now - timedelta(hours=i)
            hour_end = now - timedelta(hours=i - 1)

            blocked_count = session.query(FirewallLog).filter(
                FirewallLog.timestamp.between(hour_start, hour_end),
                FirewallLog.action == 'block'
            ).count()

            allowed_count = session.query(FirewallLog).filter(
                FirewallLog.timestamp.between(hour_start, hour_end),
                FirewallLog.action == 'allow'
            ).count()

            hours_data['Hour'].append(hour_start.strftime('%H:%M'))
            hours_data['Blocked'].append(blocked_count)
            hours_data['Allowed'].append(allowed_count)

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=hours_data['Hour'],
            y=hours_data['Blocked'],
            name='Blocked',
            line=dict(color='#ef4444', width=3),
            fill='tozeroy',
            fillcolor='rgba(239, 68, 68, 0.2)'
        ))
        fig.add_trace(go.Scatter(
            x=hours_data['Hour'],
            y=hours_data['Allowed'],
            name='Allowed',
            line=dict(color='#10b981', width=3),
            fill='tozeroy',
            fillcolor='rgba(16, 185, 129, 0.2)'
        ))

        fig.update_layout(
            title='📈 Firewall Actions (Last 24 Hours)',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(30, 41, 59, 0.5)',
            font={'color': 'white'},
            height=300,
            xaxis={'gridcolor': 'rgba(148, 163, 184, 0.1)'},
            yaxis={'gridcolor': 'rgba(148, 163, 184, 0.1)'}
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Threat types distribution
        threat_counts = {}
        for log in all_logs:
            if log.threat_type:
                threat_type = log.threat_type.replace('_', ' ').title()
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

        if threat_counts:
            df_threats = pd.DataFrame(
                list(threat_counts.items()),
                columns=['Threat Type', 'Count']
            )

            fig = px.bar(
                df_threats,
                x='Count',
                y='Threat Type',
                orientation='h',
                title='🎯 Threat Types Blocked',
                color='Count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(30, 41, 59, 0.5)',
                font={'color': 'white'},
                height=300,
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Firewall Events Table
st.markdown("### 📋 Recent Firewall Events")

if not firewall_logs:
    st.info("📭 No firewall logs found. Run firewall attack simulations to generate logs.")
else:
    st.write(f"**Showing {len(firewall_logs)} most recent events**")

    for log in firewall_logs:
        action_colors = {
            'block': '#ef4444',
            'allow': '#10b981',
            'drop': '#f59e0b',
            'reject': '#dc2626'
        }

        severity_colors = {
            'critical': '#dc2626',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#10b981'
        }

        # --- FIX: guard against None values ---
        action_val = (log.action or 'unknown').lower()
        severity_val = (log.severity or 'unknown').lower()
        source_ip = log.source_ip or 'N/A'
        dest_ip = log.destination_ip or 'N/A'
        ts_str = log.timestamp.strftime('%I:%M %p') if log.timestamp else 'N/A'

        with st.expander(
            f"**{action_val.upper()}** - {source_ip} → {dest_ip} - {ts_str}",
            expanded=False
        ):
            col1, col2, col3 = st.columns(3)

            with col1:
                action_color = action_colors.get(action_val, '#64748b')
                st.markdown(f"""
                    **Action:** <span style="background: {action_color}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{action_val.upper()}</span>  
                    **Rule:** {log.rule_name or 'N/A'}  
                    **Rule ID:** {log.rule_id or 'N/A'}  
                    **Protocol:** {log.protocol or 'Unknown'}
                """, unsafe_allow_html=True)

            with col2:
                st.markdown("**Source:**")
                st.write(f"IP: {source_ip}")
                st.write(f"Port: {log.source_port or 'N/A'}")
                if log.source_country:
                    st.write(f"Country: {log.source_country} 🌍")

            with col3:
                st.markdown("**Destination:**")
                st.write(f"IP: {dest_ip}")
                st.write(f"Port: {log.destination_port or 'N/A'}")

                if log.threat_type:
                    st.write(f"**Threat:** {log.threat_type.replace('_', ' ').title()}")

            # Additional details
            st.markdown("---")

            col_a, col_b = st.columns(2)

            with col_a:
                severity_color = severity_colors.get(severity_val, '#64748b')
                st.markdown(f"""
                    **Severity:** <span style="background: {severity_color}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{severity_val.upper()}</span>
                """, unsafe_allow_html=True)

                ts_full = log.timestamp.strftime('%B %d, %Y at %I:%M %p') if log.timestamp else 'N/A'
                st.write(f"**Time:** {ts_full}")

            with col_b:
                if log.packets:
                    st.write(f"**Packets:** {log.packets}")
                if log.bytes_transferred:
                    bytes_kb = log.bytes_transferred / 1024
                    st.write(f"**Data:** {bytes_kb:.2f} KB")

            # Check if this log is linked to an alert
            if log.alert_id:
                st.markdown("---")
                alert = session.query(Alert).get(log.alert_id)
                if alert:
                    st.warning(f"⚠️ **This event triggered Alert #{alert.id}**")
                    st.write(f"**Alert:** {alert.title}")
                    alert_severity = (alert.severity or 'unknown').upper()
                    st.write(f"**Severity:** {alert_severity}")

                    if st.button("View Alert Details", key=f"view_alert_{log.id}"):
                        st.info("👉 Go to Alerts page to review this alert")

# Top Blocked IPs
st.markdown("---")
st.markdown("### 🚫 Top Blocked IP Addresses")

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Most Blocked Sources")

    # Count blocked IPs
    blocked_ips = {}
    for log in session.query(FirewallLog).filter(FirewallLog.action == 'block').all():
        ip = log.source_ip or 'Unknown'
        blocked_ips[ip] = blocked_ips.get(ip, 0) + 1

    top_blocked = sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_blocked:
        for ip, count in top_blocked:
            # Get country if available
            country_log = session.query(FirewallLog).filter(
                FirewallLog.source_ip == ip,
                FirewallLog.source_country != None
            ).first()

            country = f" ({country_log.source_country})" if country_log and country_log.source_country else ""

            st.markdown(f"""
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                     border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem;
                     display: flex; justify-content: space-between; align-items: center;">
                    <span>🚫 <strong>{ip}</strong>{country}</span>
                    <span style="background: #ef4444; color: white; padding: 0.25rem 0.75rem;
                         border-radius: 12px; font-weight: 700;">{count} blocks</span>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No blocked IPs recorded yet.")