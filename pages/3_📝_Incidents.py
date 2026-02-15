"""
Edusiem Incidents Page - Role-Based Access + Full Correlation
Edusiem Lead sees all, Analysts see only assigned to them
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    Incident, Alert, User, IncidentResponse
)

st.set_page_config(page_title="Incidents - Edusiem", page_icon="📝", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #8b5cf6 0%, #a78bfa 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">📝 Incident Management</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Track, investigate, and resolve security incidents</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Get current user
current_user = session.query(User).get(st.session_state['user_id'])

# Role-based query filtering
if current_user.role == 'security_analyst':
    # Analysts only see incidents assigned to them
    base_query = session.query(Incident).filter(
        Incident.assigned_to == current_user.id
    )
    st.info(f"👤 Showing incidents assigned to you ({current_user.full_name})")
elif current_user.role in ['admin', 'edusiem_lead']:
    # Admin and Lead see all incidents
    base_query = session.query(Incident)
else:
    # Students/Faculty only see incidents they reported
    base_query = session.query(Incident).filter(
        Incident.reported_by == current_user.id
    )
    st.info(f"👤 Showing incidents you reported")

# Metrics
total_incidents = base_query.count()
open_incidents = base_query.filter(Incident.status == 'open').count()
investigating = base_query.filter(Incident.status == 'investigating').count()
resolved = base_query.filter(Incident.status == 'resolved').count()

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total", total_incidents)

with col2:
    st.metric("Open", open_incidents)

with col3:
    st.metric("Investigating", investigating)

with col4:
    st.metric("Resolved", resolved)

with col5:
    from_alerts = base_query.filter(Incident.created_from_alert == True).count()
    st.metric("From Alerts", from_alerts)

st.markdown("---")

# Tabs
tab1, tab2, tab3 = st.tabs(["📋 Active Incidents", "✅ Resolved Incidents", "➕ Create New"])

with tab1:
    st.markdown("### 🔴 Active Incidents")
    
    # Get active incidents
    active_incidents = base_query.filter(
        Incident.status.in_(['open', 'investigating'])
    ).order_by(Incident.created_at.desc()).all()
    
    if not active_incidents:
        st.info("📭 No active incidents")
    else:
        for inc in active_incidents:
            severity_colors = {
                'critical': '#dc2626',
                'high': '#f59e0b',
                'medium': '#3b82f6',
                'low': '#10b981'
            }
            
            status_colors = {
                'open': '#ef4444',
                'investigating': '#f59e0b',
                'resolved': '#10b981',
                'closed': '#64748b'
            }
            
            with st.expander(f"**INC-{inc.id:04d}** - {inc.title}", expanded=False):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown("#### 📋 Incident Details")
                    
                    st.markdown(f"""
                        **Severity:** <span style="background: {severity_colors[inc.severity]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{inc.severity.upper()}</span>  
                        **Status:** <span style="background: {status_colors[inc.status]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-weight: 700;">{inc.status.upper()}</span>  
                        **Type:** {inc.incident_type.replace('_', ' ').title()}  
                        **Created:** {inc.created_at.strftime('%B %d, %Y at %I:%M %p')}
                    """, unsafe_allow_html=True)
                    
                    st.markdown("---")
                    
                    st.markdown("**Description:**")
                    st.info(inc.description)
                    
                    # Show correlation to alert
                    if inc.alert_id:
                        alert = session.query(Alert).get(inc.alert_id)
                        if alert:
                            st.markdown("---")
                            st.success(f"🔗 **Created from Alert #{alert.id}**")
                            st.write(f"**Alert Type:** {alert.alert_type.replace('_', ' ').title()}")
                            st.write(f"**Source IP:** {alert.source_ip}")
                            if st.button(f"View Original Alert", key=f"view_alert_{inc.id}"):
                                st.info("👉 Go to Alerts page to view full alert details")
                    
                    # Assignment info
                    st.markdown("---")
                    st.markdown("**Assignment:**")
                    
                    if inc.reported_by:
                        reporter = session.query(User).get(inc.reported_by)
                        st.write(f"**Reported by:** {reporter.full_name if reporter else 'Unknown'}")
                    
                    if inc.assigned_to:
                        assignee = session.query(User).get(inc.assigned_to)
                        st.write(f"**Assigned to:** {assignee.full_name if assignee else 'Unassigned'}")
                    else:
                        st.warning("⚠️ Not yet assigned")
                    
                    # Response actions
                    st.markdown("---")
                    st.markdown("### 🛡️ Response Actions")
                    
                    responses = session.query(IncidentResponse).filter(
                        IncidentResponse.incident_id == inc.id
                    ).all()
                    
                    if responses:
                        for resp in responses:
                            status_icon = "✅" if resp.status == 'completed' else "⏳"
                            st.write(f"{status_icon} **{resp.action_type.replace('_', ' ').title()}** - {resp.status}")
                    else:
                        st.info("No response actions taken yet")
                
                with col2:
                    st.markdown("### ⚡ Quick Actions")
                    
                    # Only allow actions if user has permission
                    can_modify = (
                        current_user.role in ['admin', 'edusiem_lead'] or
                        (current_user.role == 'security_analyst' and inc.assigned_to == current_user.id)
                    )
                    
                    if can_modify:
                        # Assign analyst (only for lead/admin)
                        if current_user.role in ['admin', 'edusiem_lead']:
                            st.markdown("#### 👤 Assign Analyst")
                            analysts = session.query(User).filter(
                                User.role == 'security_analyst'
                            ).all()
                            
                            analyst_options = {a.full_name: a.id for a in analysts}
                            analyst_options['Unassigned'] = None
                            
                            current_assignee = "Unassigned"
                            if inc.assigned_to:
                                assignee = session.query(User).get(inc.assigned_to)
                                if assignee:
                                    current_assignee = assignee.full_name
                            
                            selected_analyst = st.selectbox(
                                "Assign to",
                                list(analyst_options.keys()),
                                index=list(analyst_options.keys()).index(current_assignee),
                                key=f"assign_{inc.id}"
                            )
                            
                            if st.button("💾 Update Assignment", key=f"update_assign_{inc.id}"):
                                inc.assigned_to = analyst_options[selected_analyst]
                                session.commit()
                                st.success(f"✅ Assigned to {selected_analyst}")
                                st.rerun()
                            
                            st.markdown("---")
                        
                        # Response actions
                        st.markdown("#### 🛡️ Take Action")
                        
                        if st.button("🚫 Block IP", key=f"block_{inc.id}", use_container_width=True):
                            response = IncidentResponse(
                                incident_id=inc.id,
                                action_type='block_ip',
                                action_description='Blocked source IP via firewall',
                                status='completed',
                                executed_by=current_user.id,
                                executed_at=datetime.utcnow(),
                                result='IP successfully blocked'
                            )
                            session.add(response)
                            session.commit()
                            st.success("✅ IP blocked!")
                            st.rerun()
                        
                        if st.button("🔒 Lock Account", key=f"lock_{inc.id}", use_container_width=True):
                            response = IncidentResponse(
                                incident_id=inc.id,
                                action_type='disable_account',
                                action_description='Disabled compromised user account',
                                status='completed',
                                executed_by=current_user.id,
                                executed_at=datetime.utcnow(),
                                result='Account successfully disabled'
                            )
                            session.add(response)
                            session.commit()
                            st.success("✅ Account locked!")
                            st.rerun()
                        
                        if st.button("💻 Isolate Host", key=f"isolate_{inc.id}", use_container_width=True):
                            response = IncidentResponse(
                                incident_id=inc.id,
                                action_type='isolate_host',
                                action_description='Isolated host from network',
                                status='completed',
                                executed_by=current_user.id,
                                executed_at=datetime.utcnow(),
                                result='Host successfully isolated'
                            )
                            session.add(response)
                            session.commit()
                            st.success("✅ Host isolated!")
                            st.rerun()
                        
                        st.markdown("---")
                        
                        # Update status
                        st.markdown("#### 📊 Update Status")
                        
                        new_status = st.selectbox(
                            "Change Status",
                            ["open", "investigating", "resolved", "closed"],
                            index=["open", "investigating", "resolved", "closed"].index(inc.status),
                            key=f"status_{inc.id}"
                        )
                        
                        if new_status != inc.status:
                            if st.button("💾 Update Status", key=f"update_status_{inc.id}"):
                                inc.status = new_status
                                inc.updated_at = datetime.utcnow()
                                
                                if new_status == 'resolved':
                                    inc.resolved_at = datetime.utcnow()
                                
                                session.commit()
                                st.success(f"✅ Status updated to {new_status}!")
                                st.rerun()
                        
                        st.markdown("---")
                        
                        # Add resolution notes
                        st.markdown("#### 📝 Resolution Notes")
                        
                        notes = st.text_area(
                            "Notes",
                            value=inc.resolution_notes or "",
                            key=f"notes_{inc.id}",
                            height=100
                        )
                        
                        if st.button("💬 Save Notes", key=f"save_notes_{inc.id}"):
                            inc.resolution_notes = notes
                            session.commit()
                            st.success("✅ Notes saved!")
                    
                    else:
                        st.warning("⚠️ You don't have permission to modify this incident")

with tab2:
    st.markdown("### ✅ Resolved Incidents")
    
    resolved_incidents = base_query.filter(
        Incident.status.in_(['resolved', 'closed'])
    ).order_by(Incident.resolved_at.desc()).limit(20).all()
    
    if not resolved_incidents:
        st.info("No resolved incidents yet")
    else:
        for inc in resolved_incidents:
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**INC-{inc.id:04d}** - {inc.title}")
                st.caption(f"Resolved: {inc.resolved_at.strftime('%B %d, %Y') if inc.resolved_at else 'N/A'}")
            
            with col2:
                st.success("✅ Resolved")
            
            if inc.resolution_notes:
                with st.expander("View Notes"):
                    st.write(inc.resolution_notes)
            
            st.markdown("---")

with tab3:
    st.markdown("### ➕ Create New Incident")
    
    with st.form("new_incident"):
        title = st.text_input("Incident Title*")
        
        col1, col2 = st.columns(2)
        
        with col1:
            incident_type = st.selectbox(
                "Type*",
                ["brute_force", "port_scan", "sql_injection", "malware", 
                 "phishing", "data_exfiltration", "privilege_escalation", 
                 "ddos", "unusual_time", "geo_anomaly", "other"]
            )
            severity = st.selectbox("Severity*", ["critical", "high", "medium", "low"])
        
        with col2:
            priority = st.selectbox("Priority", ["high", "medium", "low"])
            
            # Show analyst assignment only for lead/admin
            if current_user.role in ['admin', 'edusiem_lead']:
                analysts = session.query(User).filter(User.role == 'security_analyst').all()
                analyst_options = {a.full_name: a.id for a in analysts}
                analyst_options['Unassigned'] = None
                
                assigned = st.selectbox("Assign To", list(analyst_options.keys()))
        
        description = st.text_area("Description*")
        
        submitted = st.form_submit_button("🚀 Create Incident")
        
        if submitted:
            if title and description:
                incident = Incident(
                    title=title,
                    description=description,
                    incident_type=incident_type,
                    severity=severity,
                    priority=priority,
                    status='open',
                    reported_by=current_user.id,
                    assigned_to=analyst_options[assigned] if current_user.role in ['admin', 'edusiem_lead'] else None,
                    created_from_alert=False
                )
                
                session.add(incident)
                session.commit()
                
                st.success(f"✅ Incident INC-{incident.id:04d} created!")
                st.balloons()
            else:
                st.error("Please fill required fields!")

session.close()