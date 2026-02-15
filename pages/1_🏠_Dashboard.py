"""
Edusiem Dashboard - Interactive & Stylish
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Page config
st.set_page_config(page_title="Dashboard - Edusiem", page_icon="🏠", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Custom CSS
st.markdown("""
<style>
    .dashboard-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #06b6d4 100%);
        padding: 2.5rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        box-shadow: 0 20px 60px rgba(59, 130, 246, 0.3);
    }
    
    .dashboard-header h1 {
        color: white;
        font-size: 2.5rem;
        font-weight: 800;
        margin: 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
    }
    
    .dashboard-header p {
        color: rgba(255,255,255,0.9);
        font-size: 1.1rem;
        margin: 0.5rem 0 0 0;
    }
</style>
""", unsafe_allow_html=True)

# Generate sample data
def get_sample_data():
    now = datetime.now()
    hours = [(now - timedelta(hours=i)).strftime('%H:%M') for i in range(24, 0, -1)]
    
    return {
        'alerts': {'total': 47, 'critical': 3, 'high': 8, 'medium': 21, 'low': 15},
        'incidents': {'open': 5, 'investigating': 3, 'resolved': 28},
        'hosts': {'total': 156, 'online': 142, 'offline': 8, 'compromised': 6},
        'threat_level': 'MEDIUM',
        'hourly_alerts': [{'hour': h, 'count': np.random.randint(0, 10)} for h in hours],
        'alert_types': [
            {'type': 'Brute Force', 'count': 15},
            {'type': 'Malware', 'count': 8},
            {'type': 'Unauthorized Access', 'count': 12},
            {'type': 'Data Exfiltration', 'count': 6},
            {'type': 'Policy Violation', 'count': 6}
        ],
        'activities': [
            {'time': '2 min ago', 'desc': '🚨 Critical: Brute force attack detected'},
            {'time': '5 min ago', 'desc': '📝 Incident: Malware on LAB-PC-032'},
            {'time': '12 min ago', 'desc': '✅ Resolved: Phishing email blocked'},
            {'time': '18 min ago', 'desc': '⚠️ Alert: Unusual login time detected'},
            {'time': '25 min ago', 'desc': '🔍 Hunt completed: 3 suspicious events'}
        ]
    }

data = get_sample_data()

# Header
st.markdown(f"""
    <div class="dashboard-header">
        <h1>🛡️ Security Operations Dashboard</h1>
        <p>Real-time threat monitoring and incident management</p>
        <div style="color: rgba(255,255,255,0.7); margin-top: 0.5rem;">
            Last updated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
        </div>
    </div>
""", unsafe_allow_html=True)

# Top metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🚨 Active Alerts",
        value=data['alerts']['total'],
        delta="+12 today"
    )

with col2:
    st.metric(
        label="📝 Open Incidents",
        value=data['incidents']['open'],
        delta="-2 resolved"
    )

with col3:
    st.metric(
        label="💻 Monitored Hosts",
        value=f"{data['hosts']['online']}/{data['hosts']['total']}",
        delta="+2 online"
    )

with col4:
    threat_color = {'LOW': 'green', 'MEDIUM': 'orange', 'HIGH': 'red'}.get(data['threat_level'], 'blue')
    st.markdown(f"""
        <div style="text-align: center; padding: 1.5rem; background: #1e293b; border-radius: 15px; border: 2px solid {threat_color};">
            <div style="color: #94a3b8; font-size: 0.9rem; text-transform: uppercase;">⚡ Threat Level</div>
            <div style="color: {threat_color}; font-size: 2rem; font-weight: 800; margin-top: 0.5rem;">{data['threat_level']}</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Charts row 1
col1, col2 = st.columns(2)

with col1:
    # Line chart - Alerts over time
    df = pd.DataFrame(data['hourly_alerts'])
    fig = px.line(df, x='hour', y='count', title='📊 Alerts Over Last 24 Hours')
    fig.update_traces(line_color='#3b82f6', line_width=3, fill='tozeroy', fillcolor='rgba(59, 130, 246, 0.2)')
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(30, 41, 59, 0.5)',
        font={'color': 'white'},
        height=300,
        xaxis={'gridcolor': 'rgba(148, 163, 184, 0.1)'},
        yaxis={'gridcolor': 'rgba(148, 163, 184, 0.1)'}
    )
    st.plotly_chart(fig, use_container_width=True)

with col2:
    # Pie chart - Alert types
    labels = [item['type'] for item in data['alert_types']]
    values = [item['count'] for item in data['alert_types']]
    colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6']
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.4,
        marker=dict(colors=colors, line=dict(color='#0f172a', width=2))
    )])
    fig.update_layout(
        title='🎯 Alert Distribution by Type',
        paper_bgcolor='rgba(0,0,0,0)',
        font={'color': 'white'},
        showlegend=True,
        height=300
    )
    st.plotly_chart(fig, use_container_width=True)

# Activity feed and stats
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("### ⚡ Recent Activity Feed")
    for activity in data['activities']:
        st.info(f"**{activity['time']}** - {activity['desc']}")

with col2:
    st.markdown("### 🎯 Alert Severity")
    
    severity_colors = {
        'Critical': '#dc2626',
        'High': '#f59e0b',
        'Medium': '#3b82f6',
        'Low': '#10b981'
    }
    
    for severity, count in [('Critical', data['alerts']['critical']), 
                            ('High', data['alerts']['high']),
                            ('Medium', data['alerts']['medium']),
                            ('Low', data['alerts']['low'])]:
        st.markdown(f"""
            <div style="display: flex; justify-content: space-between; padding: 0.75rem; background: #1e293b; border-radius: 8px; margin-bottom: 0.5rem; border-left: 4px solid {severity_colors[severity]};">
                <span style="color: white; font-weight: 600;">{severity}</span>
                <span style="background: {severity_colors[severity]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{count}</span>
            </div>
        """, unsafe_allow_html=True)

st.markdown("<br><br>", unsafe_allow_html=True)

# Refresh button
if st.button("🔄 Refresh Dashboard", use_container_width=True):
    st.rerun()