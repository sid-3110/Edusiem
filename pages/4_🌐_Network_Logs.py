"""
Edusiem Network Logs Page
Monitor network traffic and detect anomalies with real correlation
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
    NetworkLog, Alert, User
)

st.set_page_config(page_title="Network Logs - Edusiem", page_icon="🌐", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🌐 Network Traffic Monitoring</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Real-time network activity analysis</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Get metrics
total_connections = session.query(NetworkLog).count()
suspicious_connections = session.query(NetworkLog).filter(NetworkLog.status == 'suspicious').count()
normal_connections = session.query(NetworkLog).filter(NetworkLog.status == 'normal').count()
blocked_connections = session.query(NetworkLog).filter(NetworkLog.status == 'blocked').count()

# Calculate total data transfer
total_bytes_query = session.query(NetworkLog).all()
total_bytes = sum((log.bytes_sent or 0) + (log.bytes_received or 0) for log in total_bytes_query)
total_gb = total_bytes / (1024 * 1024 * 1024) if total_bytes > 0 else 0

# Metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Connections", total_connections)

with col2:
    st.metric("Suspicious", suspicious_connections, delta=f"+{suspicious_connections}")

with col3:
    st.metric("Normal", normal_connections)

with col4:
    st.metric("Blocked", blocked_connections)

with col5:
    st.metric("Data Transfer", f"{total_gb:.2f} GB")

st.markdown("---")

# Filters
col1, col2, col3, col4 = st.columns(4)

with col1:
    protocol_filter = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP", "HTTP", "HTTPS"])

with col2:
    status_filter = st.selectbox("Status", ["All", "Normal", "Suspicious", "Blocked"])

with col3:
    threat_filter = st.selectbox("Threat Level", ["All", "Critical", "High", "Medium", "Low"])

with col4:
    search_ip = st.text_input("🔍 Search IP", placeholder="Enter IP address...")

st.markdown("---")

# Build query
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

# Get logs
network_logs = query.limit(100).all()

# Charts Section
if total_connections > 0:
    st.markdown("### 📊 Network Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Traffic over time (last 24 hours)
        now = datetime.now()
        hours_data = []
        
        for i in range(24, 0, -1):
            hour_start = now - timedelta(hours=i)
            hour_end = now - timedelta(hours=i-1)
            
            count = session.query(NetworkLog).filter(
                NetworkLog.timestamp.between(hour_start, hour_end)
            ).count()
            
            hours_data.append({
                'Hour': hour_start.strftime('%H:%M'),
                'Connections': count
            })
        
        df_hours = pd.DataFrame(hours_data)
        
        fig = px.area(df_hours, x='Hour', y='Connections', title='📈 Network Traffic (Last 24 Hours)')
        fig.update_traces(line_color='#06b6d4', fillcolor='rgba(6, 182, 212, 0.3)')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(30, 41, 59, 0.5)',
            font={'color': 'white'},
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Protocol distribution
        protocol_counts = {}
        for log in total_bytes_query:
            protocol = log.protocol or 'Unknown'
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        if protocol_counts:
            df_protocols = pd.DataFrame(
                list(protocol_counts.items()),
                columns=['Protocol', 'Count']
            )
            
            fig = go.Figure(data=[go.Pie(
                labels=df_protocols['Protocol'],
                values=df_protocols['Count'],
                hole=.4,
                marker=dict(colors=['#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#8b5cf6'])
            )])
            fig.update_layout(
                title='📊 Protocol Distribution',
                paper_bgcolor='rgba(0,0,0,0)',
                font={'color': 'white'},
                height=300
            )
            st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Network Logs Table
st.markdown("### 📋 Network Connection Logs")

if not network_logs:
    st.info("📭 No network logs found. Run network attack simulations to generate logs.")
else:
    st.write(f"**Showing {len(network_logs)} most recent connections**")
    
    for log in network_logs:
        status_colors = {
            'normal': '#10b981',
            'suspicious': '#f59e0b',
            'blocked': '#ef4444'
        }
        
        threat_colors = {
            'low': '#10b981',
            'medium': '#3b82f6',
            'high': '#f59e0b',
            'critical': '#dc2626'
        }
        
        # Connection info
        connection_key = f"net_log_{log.id}"
        
        with st.expander(
            f"**{log.source_ip}:{log.source_port or '?'}** → **{log.destination_ip}:{log.destination_port or '?'}** ({log.protocol or 'Unknown'}) - {log.timestamp.strftime('%I:%M %p')}",
            expanded=False
        ):
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Source:**")
                st.write(f"IP: {log.source_ip}")
                st.write(f"Port: {log.source_port or 'N/A'}")
                if log.user_id:
                    user = session.query(User).get(log.user_id)
                    st.write(f"User: {user.username if user else 'Unknown'}")
            
            with col2:
                st.markdown("**Destination:**")
                st.write(f"IP: {log.destination_ip}")
                st.write(f"Port: {log.destination_port or 'N/A'}")
                st.write(f"Protocol: {log.protocol or 'Unknown'}")
            
            with col3:
                st.markdown("**Details:**")
                
                # Status badge
                st.markdown(f"""
                    **Status:** <span style="background: {status_colors.get(log.status, '#64748b')}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{log.status.upper()}</span>
                """, unsafe_allow_html=True)
                
                # Threat level badge
                st.markdown(f"""
                    **Threat:** <span style="background: {threat_colors.get(log.threat_level, '#64748b')}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{log.threat_level.upper()}</span>
                """, unsafe_allow_html=True)
                
                st.write(f"Time: {log.timestamp.strftime('%B %d, %Y at %I:%M %p')}")
            
            # Additional details
            st.markdown("---")
            st.markdown("**Traffic Details:**")
            
            col_a, col_b, col_c = st.columns(3)
            
            with col_a:
                bytes_sent_mb = (log.bytes_sent or 0) / (1024 * 1024)
                st.write(f"📤 Sent: {bytes_sent_mb:.2f} MB")
            
            with col_b:
                bytes_recv_mb = (log.bytes_received or 0) / (1024 * 1024)
                st.write(f"📥 Received: {bytes_recv_mb:.2f} MB")
            
            with col_c:
                st.write(f"📦 Packets: {log.packets or 0}")
            
            if log.connection_state:
                st.write(f"**Connection State:** {log.connection_state}")
            
            if log.duration:
                st.write(f"**Duration:** {log.duration} seconds")
            
            # Check if this log is linked to an alert
            if log.alert_id:
                st.markdown("---")
                alert = session.query(Alert).get(log.alert_id)
                if alert:
                    st.warning(f"⚠️ **This connection triggered Alert #{alert.id}**")
                    st.write(f"**Alert:** {alert.title}")
                    st.write(f"**Severity:** {alert.severity.upper()}")
                    
                    if st.button("View Alert Details", key=f"view_alert_{log.id}"):
                        st.info("👉 Go to Alerts page to review this alert")

# Top Talkers
st.markdown("---")
st.markdown("### 🔝 Top Network Talkers")

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### 📤 Top Sources (Outbound)")
    
    # Get top source IPs
    source_counts = {}
    for log in session.query(NetworkLog).all():
        source_counts[log.source_ip] = source_counts.get(log.source_ip, 0) + 1
    
    top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if top_sources:
        for ip, count in top_sources:
            st.info(f"**{ip}** - {count} connection(s)")
    else:
        st.write("No data available")

with col2:
    st.markdown("#### 📥 Top Destinations (Inbound)")
    
    # Get top destination IPs
    dest_counts = {}
    for log in session.query(NetworkLog).all():
        dest_counts[log.destination_ip] = dest_counts.get(log.destination_ip, 0) + 1
    
    top_dests = sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    if top_dests:
        for ip, count in top_dests:
            st.info(f"**{ip}** - {count} connection(s)")
    else:
        st.write("No data available")

session.close()