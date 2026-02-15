"""
Edusiem Alerts Page - Complete Workflow
Review alerts, mark as True/False Positive, create incidents
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    Alert, Incident, User, DetectionRule
)

st.set_page_config(page_title="Alerts - Edusiem", page_icon="🚨", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🚨 Security Alerts</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Monitor and respond to security threats</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Get current user
current_user = session.query(User).get(st.session_state['user_id'])

# Metrics
total_alerts = session.query(Alert).count()
new_alerts = session.query(Alert).filter_by(status='new').count()
true_positives = session.query(Alert).filter_by(status='true_positive').count()
false_positives = session.query(Alert).filter_by(status='false_positive').count()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Alerts", total_alerts)

with col2:
    st.metric("New/Unreviewed", new_alerts, delta=f"{new_alerts} pending")

with col3:
    st.metric("True Positives", true_positives)

with col4:
    st.metric("False Positives", false_positives)

st.markdown("---")

# Filters
col1, col2, col3, col4 = st.columns(4)

with col1:
    severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])

with col2:
    status_filter = st.selectbox("Status", ["All", "New", "True Positive", "False Positive", "Dismissed"])

with col3:
    alert_type_filter = st.selectbox(
        "Alert Type",
        ["All", "Brute Force", "Port Scan", "SQL Injection", "Unusual Time", 
         "Geo Anomaly", "Data Exfiltration", "Malware", "Privilege Escalation", 
         "Phishing", "DDoS"]
    )

with col4:
    sort_by = st.selectbox("Sort By", ["Newest First", "Oldest First", "Severity"])

st.markdown("---")

# Build query based on filters
query = session.query(Alert)

if severity_filter != "All":
    query = query.filter(Alert.severity == severity_filter.lower())

if status_filter != "All":
    status_map = {
        "New": "new",
        "True Positive": "true_positive",
        "False Positive": "false_positive",
        "Dismissed": "dismissed"
    }
    query = query.filter(Alert.status == status_map[status_filter])

if alert_type_filter != "All":
    type_map = {
        "Brute Force": "brute_force",
        "Port Scan": "port_scan",
        "SQL Injection": "sql_injection",
        "Unusual Time": "unusual_time",
        "Geo Anomaly": "geo_anomaly",
        "Data Exfiltration": "data_exfiltration",
        "Malware": "malware",
        "Privilege Escalation": "privilege_escalation",
        "Phishing": "phishing",
        "DDoS": "ddos"
    }
    query = query.filter(Alert.alert_type == type_map[alert_type_filter])

# Sort
if sort_by == "Newest First":
    query = query.order_by(Alert.created_at.desc())
elif sort_by == "Oldest First":
    query = query.order_by(Alert.created_at.asc())
else:  # Severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    alerts_list = query.all()
    alerts_list.sort(key=lambda x: severity_order.get(x.severity, 4))
    query = None

# Get alerts
if query:
    alerts = query.all()
else:
    alerts = alerts_list

# Display alerts
if not alerts:
    st.info("📭 No alerts match your filters")
else:
    st.markdown(f"### Found {len(alerts)} alert(s)")
    
    for alert in alerts:
        severity_colors = {
            'critical': '#dc2626',
            'high': '#f59e0b',
            'medium': '#3b82f6',
            'low': '#10b981'
        }
        
        status_colors = {
            'new': '#3b82f6',
            'true_positive': '#dc2626',
            'false_positive': '#10b981',
            'dismissed': '#64748b'
        }
        
        status_labels = {
            'new': '🆕 New',
            'true_positive': '✅ True Positive',
            'false_positive': '❌ False Positive',
            'dismissed': '🚫 Dismissed'
        }
        
        # Create unique key for this alert's expander
        expander_key = f"alert_exp_{alert.id}"
        
        # Alert expander
        with st.expander(
            f"**Alert #{alert.id}** - {alert.title} - {status_labels.get(alert.status, alert.status)}",
            expanded=(alert.status == 'new')
        ):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                # Alert Details
                st.markdown("#### 🔍 Alert Details")
                
                st.markdown(f"""
                    **Severity:** <span style="background: {severity_colors[alert.severity]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{alert.severity.upper()}</span>  
                    **Status:** <span style="background: {status_colors[alert.status]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{status_labels[alert.status]}</span>  
                    **Alert Type:** {alert.alert_type.replace('_', ' ').title()}  
                    **Created:** {alert.created_at.strftime('%B %d, %Y at %I:%M %p')}
                """, unsafe_allow_html=True)
                
                st.markdown("---")
                
                st.markdown("**Description:**")
                st.info(alert.message)
                
                st.markdown("**Source Information:**")
                col_a, col_b = st.columns(2)
                with col_a:
                    st.write(f"**Source IP:** {alert.source_ip or 'N/A'}")
                    st.write(f"**Target IP:** {alert.target_ip or 'N/A'}")
                with col_b:
                    st.write(f"**Rule:** {alert.rule_name or 'N/A'}")
                    st.write(f"**Rule ID:** {alert.rule_id or 'N/A'}")
                
                # Evidence
                if alert.evidence:
                    st.markdown("---")
                    st.markdown("**📋 Attack Evidence:**")
                    try:
                        evidence = json.loads(alert.evidence)
                        for key, value in evidence.items():
                            st.write(f"**{key.replace('_', ' ').title()}:** {value}")
                    except:
                        st.write(alert.evidence)
                
                # If already reviewed
                if alert.status != 'new':
                    st.markdown("---")
                    st.markdown("**Review Information:**")
                    if alert.reviewed_by:
                        reviewer = session.query(User).get(alert.reviewed_by)
                        if reviewer:
                            st.write(f"**Reviewed by:** {reviewer.full_name}")
                    if alert.reviewed_at:
                        st.write(f"**Reviewed at:** {alert.reviewed_at.strftime('%B %d, %Y at %I:%M %p')}")
                    
                    # If incident was created
                    if alert.incident_id:
                        incident = session.query(Incident).get(alert.incident_id)
                        if incident:
                            st.success(f"✅ **Incident Created:** INC-{incident.id:04d} - {incident.title}")
                            st.write(f"**Status:** {incident.status.replace('_', ' ').title()}")
            
            with col2:
                st.markdown("### ⚡ Actions")
                
                # Only show actions if alert is new and user has permission
                if alert.status == 'new' and current_user.role in ['admin', 'edusiem_lead', 'security_analyst']:
                    
                    st.markdown("#### Quick Review:")
                    
                    # True Positive - Creates Incident
                    if st.button("✅ True Positive", key=f"tp_{alert.id}", use_container_width=True):
                        # Mark alert
                        alert.status = 'true_positive'
                        alert.reviewed_by = st.session_state['user_id']
                        alert.reviewed_at = datetime.utcnow()
                        
                        # Create incident automatically
                        incident = Incident(
                            title=alert.title,
                            description=alert.message,
                            incident_type=alert.alert_type,
                            severity=alert.severity,
                            status='open',
                            alert_id=alert.id,
                            created_from_alert=True,
                            reported_by=st.session_state['user_id'],
                            assigned_to=None  # Will be assigned by lead
                        )
                        
                        session.add(incident)
                        session.commit()
                        
                        # Link incident to alert
                        alert.incident_id = incident.id
                        session.commit()
                        
                        st.success(f"✅ Alert marked as True Positive!")
                        st.success(f"📝 Incident INC-{incident.id:04d} created automatically!")
                        st.info("👉 Go to Incidents page to assign and investigate")
                        st.rerun()
                    
                    # False Positive
                    if st.button("❌ False Positive", key=f"fp_{alert.id}", use_container_width=True):
                        alert.status = 'false_positive'
                        alert.reviewed_by = st.session_state['user_id']
                        alert.reviewed_at = datetime.utcnow()
                        session.commit()
                        
                        st.success("✅ Alert marked as False Positive")
                        st.rerun()
                    
                    # Dismiss
                    if st.button("🚫 Dismiss", key=f"dismiss_{alert.id}", use_container_width=True):
                        alert.status = 'dismissed'
                        alert.reviewed_by = st.session_state['user_id']
                        alert.reviewed_at = datetime.utcnow()
                        session.commit()
                        
                        st.success("✅ Alert dismissed")
                        st.rerun()
                    
                    st.markdown("---")
                    
                    # Custom incident creation toggle
                    st.markdown("#### 📝 Custom Incident")
                    
                    # Use checkbox to show/hide form (NO NESTED EXPANDERS)
                    show_custom = st.checkbox("Create Custom Incident", key=f"show_custom_{alert.id}")
                    
                    if show_custom:
                        # Form for custom incident
                        with st.form(key=f"incident_form_{alert.id}"):
                            incident_title = st.text_input("Title", value=alert.title)
                            incident_desc = st.text_area("Description", value=alert.message, height=100)
                            incident_severity = st.selectbox(
                                "Severity",
                                ["critical", "high", "medium", "low"],
                                index=["critical", "high", "medium", "low"].index(alert.severity)
                            )
                            
                            submit_incident = st.form_submit_button("Create Incident", use_container_width=True)
                            
                            if submit_incident:
                                incident = Incident(
                                    title=incident_title,
                                    description=incident_desc,
                                    incident_type=alert.alert_type,
                                    severity=incident_severity,
                                    status='open',
                                    alert_id=alert.id,
                                    created_from_alert=True,
                                    reported_by=st.session_state['user_id']
                                )
                                
                                session.add(incident)
                                session.commit()
                                
                                alert.status = 'true_positive'
                                alert.incident_id = incident.id
                                alert.reviewed_by = st.session_state['user_id']
                                alert.reviewed_at = datetime.utcnow()
                                session.commit()
                                
                                st.success(f"✅ Incident INC-{incident.id:04d} created!")
                                st.rerun()
                
                else:
                    if alert.status != 'new':
                        st.info("✓ Already reviewed")
                    else:
                        st.warning("⚠️ You don't have permission to review alerts")

session.close()