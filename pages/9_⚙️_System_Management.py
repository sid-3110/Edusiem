"""
Edusiem System Management
Reset system, clear data, manage database
Admin only
"""

import streamlit as st
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    Alert, Incident, NetworkLog, FirewallLog, SimulatedAttack, IncidentResponse,
    User, DetectionRule, create_default_users, create_default_rules
)

st.set_page_config(page_title="System Management - Edusiem", page_icon="⚙️", layout="wide")

# Check auth - ADMIN ONLY
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

if st.session_state['role'] != 'admin':
    st.error("❌ Access Denied: Only Admin can access System Management")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #64748b 0%, #475569 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">⚙️ System Management</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Database management and system reset</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Get current counts
total_alerts = session.query(Alert).count()
total_incidents = session.query(Incident).count()
total_network_logs = session.query(NetworkLog).count()
total_firewall_logs = session.query(FirewallLog).count()
total_simulations = session.query(SimulatedAttack).count()
total_responses = session.query(IncidentResponse).count()
total_users = session.query(User).count()
total_rules = session.query(DetectionRule).count()

# Display current system status
st.markdown("### 📊 Current System Status")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Alerts", total_alerts)
    st.metric("Incidents", total_incidents)

with col2:
    st.metric("Network Logs", total_network_logs)
    st.metric("Firewall Logs", total_firewall_logs)

with col3:
    st.metric("Simulations", total_simulations)
    st.metric("Responses", total_responses)

with col4:
    st.metric("Users", total_users)
    st.metric("Detection Rules", total_rules)

st.markdown("---")

# Reset Options
st.markdown("### 🔄 System Reset Options")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; border-left: 4px solid #f59e0b;">
            <h3 style="color: white; margin: 0 0 1rem 0;">⚠️ Partial Reset</h3>
            <p style="color: #94a3b8; margin: 0;">Clear simulation data only (alerts, incidents, logs, simulations)</p>
            <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">✅ Keeps: Users, Detection Rules</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    if st.button("🔄 Partial Reset (Clear Simulation Data)", use_container_width=True, type="secondary"):
        with st.spinner("Clearing simulation data..."):
            # Delete in correct order due to foreign key constraints
            session.query(IncidentResponse).delete()
            session.query(Incident).delete()
            session.query(Alert).delete()
            session.query(NetworkLog).delete()
            session.query(FirewallLog).delete()
            session.query(SimulatedAttack).delete()
            session.commit()
            
            st.success("✅ Simulation data cleared successfully!")
            st.balloons()
            
            import time
            time.sleep(1)
            st.rerun()

with col2:
    st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; border-left: 4px solid #dc2626;">
            <h3 style="color: white; margin: 0 0 1rem 0;">🚨 Full Reset</h3>
            <p style="color: #94a3b8; margin: 0;">Clear ALL data and recreate default users & rules</p>
            <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">⚠️ This will delete everything!</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Confirmation checkbox
    confirm_full_reset = st.checkbox("⚠️ I understand this will delete ALL data", key="confirm_full")
    
    if st.button(
        "🗑️ Full System Reset (Delete Everything)",
        use_container_width=True,
        type="primary",
        disabled=not confirm_full_reset
    ):
        with st.spinner("Performing full system reset..."):
            # Delete everything in correct order
            session.query(IncidentResponse).delete()
            session.query(Incident).delete()
            session.query(Alert).delete()
            session.query(NetworkLog).delete()
            session.query(FirewallLog).delete()
            session.query(SimulatedAttack).delete()
            session.query(DetectionRule).delete()
            session.query(User).delete()
            session.commit()
            
            # Recreate default users and rules
            create_default_users(session)
            create_default_rules(session)
            
            st.success("✅ Full system reset complete!")
            st.success("✅ Default users and detection rules recreated!")
            st.balloons()
            
            import time
            time.sleep(2)
            
            # Logout user
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            
            st.info("🔒 You have been logged out. Please login again.")
            time.sleep(2)
            st.rerun()

st.markdown("---")

# Individual table management
st.markdown("### 🗂️ Individual Table Management")

st.warning("⚠️ **Advanced Options** - Use with caution")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Clear Alerts Only", use_container_width=True):
        session.query(Alert).delete()
        session.commit()
        st.success("✅ Alerts cleared!")
        st.rerun()
    
    if st.button("Clear Network Logs", use_container_width=True):
        session.query(NetworkLog).delete()
        session.commit()
        st.success("✅ Network logs cleared!")
        st.rerun()

with col2:
    if st.button("Clear Incidents Only", use_container_width=True):
        session.query(IncidentResponse).delete()
        session.query(Incident).delete()
        session.commit()
        st.success("✅ Incidents cleared!")
        st.rerun()
    
    if st.button("Clear Firewall Logs", use_container_width=True):
        session.query(FirewallLog).delete()
        session.commit()
        st.success("✅ Firewall logs cleared!")
        st.rerun()

with col3:
    if st.button("Clear Simulations", use_container_width=True):
        session.query(SimulatedAttack).delete()
        session.commit()
        st.success("✅ Simulations cleared!")
        st.rerun()
    
    if st.button("Clear Responses", use_container_width=True):
        session.query(IncidentResponse).delete()
        session.commit()
        st.success("✅ Responses cleared!")
        st.rerun()

st.markdown("---")

# Database info
st.markdown("### 💾 Database Information")

import os

db_path = 'data/edusiem.db'
if os.path.exists(db_path):
    db_size = os.path.getsize(db_path)
    db_size_mb = db_size / (1024 * 1024)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Database Size", f"{db_size_mb:.2f} MB")
    
    with col2:
        st.metric("Database Location", "data/edusiem.db")
    
    with col3:
        st.metric("Database Type", "SQLite")

st.markdown("---")

# Quick stats
st.markdown("### 📈 Quick Statistics")

if total_alerts > 0:
    true_positives = session.query(Alert).filter_by(status='true_positive').count()
    false_positives = session.query(Alert).filter_by(status='false_positive').count()
    accuracy = (true_positives / (true_positives + false_positives) * 100) if (true_positives + false_positives) > 0 else 0
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Alert Accuracy", f"{accuracy:.1f}%")
    
    with col2:
        resolved = session.query(Incident).filter_by(status='resolved').count()
        resolution_rate = (resolved / total_incidents * 100) if total_incidents > 0 else 0
        st.metric("Resolution Rate", f"{resolution_rate:.1f}%")
    
    with col3:
        incidents_from_alerts = session.query(Incident).filter_by(created_from_alert=True).count()
        automation_rate = (incidents_from_alerts / total_incidents * 100) if total_incidents > 0 else 0
        st.metric("Automation Rate", f"{automation_rate:.1f}%")
    
    with col4:
        st.metric("Total Events", total_alerts + total_network_logs + total_firewall_logs)

session.close()