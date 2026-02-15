"""
Edusiem Threat Hunting Page
Proactive threat investigation and hunting
"""

import streamlit as st
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Threat Hunting - Edusiem", page_icon="🔍", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🔍 Threat Hunting</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Proactive security investigation and analysis</p>
    </div>
""", unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3 = st.tabs(["🎯 New Hunt", "📋 Active Hunts", "✅ Completed Hunts"])

with tab1:
    st.markdown("### 🎯 Start New Threat Hunt")
    
    col1, col2 = st.columns(2)
    
    with col1:
        hunt_name = st.text_input("Hunt Name*", placeholder="e.g., Unusual After-Hours Access")
        
        hypothesis = st.text_area(
            "Hypothesis*",
            placeholder="What threat are you looking for? e.g., Students accessing exam portal between 2-4 AM",
            height=100
        )
        
        data_sources = st.multiselect(
            "Data Sources",
            ["EduCloud Logs", "Exam Security", "Network Logs", "Firewall Logs", 
             "Workstation Logs", "Authentication Logs"],
            default=["EduCloud Logs"]
        )
    
    with col2:
        time_range = st.selectbox(
            "Time Range",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom Range"]
        )
        
        query = st.text_area(
            "Search Query",
            placeholder="activity_type='exam_access' AND time BETWEEN 02:00-04:00",
            height=100
        )
        
        severity = st.selectbox("Expected Severity", ["Critical", "High", "Medium", "Low"])
    
    if st.button("🚀 Start Hunt", use_container_width=True):
        with st.spinner("Hunting for threats..."):
            import time
            time.sleep(3)  # Simulate hunting
            
            st.success("✅ Hunt completed! Found 12 suspicious events")
            
            # Results
            st.markdown("### 🎯 Hunt Results")
            
            findings = [
                {
                    'time': '2025-02-07 02:15 AM',
                    'user': 'student_rahul',
                    'action': 'Exam Portal Access',
                    'ip': '10.0.1.45',
                    'suspicious': 'Yes - After hours'
                },
                {
                    'time': '2025-02-07 03:30 AM',
                    'user': 'student_priya',
                    'action': 'Exam Portal Access',
                    'ip': '10.0.2.34',
                    'suspicious': 'Yes - After hours'
                },
                {
                    'time': '2025-02-06 02:45 AM',
                    'user': 'student_amit',
                    'action': 'Answer Submission',
                    'ip': '203.45.67.89',
                    'suspicious': 'Yes - External IP + After hours'
                }
            ]
            
            df = pd.DataFrame(findings)
            st.dataframe(df, use_container_width=True)
            
            col_a, col_b, col_c = st.columns(3)
            
            with col_a:
                if st.button("📋 Create Incidents"):
                    st.success("✅ 3 incidents created!")
            
            with col_b:
                if st.button("🚨 Generate Alerts"):
                    st.success("✅ Alerts sent to admins!")
            
            with col_c:
                if st.button("💾 Save Hunt"):
                    st.success("✅ Hunt saved to archive!")

with tab2:
    st.markdown("### 📋 Active Threat Hunts")
    
    active_hunts = [
        {
            'name': 'Data Exfiltration Detection',
            'hypothesis': 'Large file downloads to external IPs',
            'status': 'In Progress',
            'started': '2 hours ago',
            'progress': 65
        },
        {
            'name': 'Lateral Movement Analysis',
            'hypothesis': 'Unusual workstation-to-workstation connections',
            'status': 'In Progress',
            'started': '5 hours ago',
            'progress': 85
        }
    ]
    
    for hunt in active_hunts:
        st.markdown(f"""
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem; border-left: 4px solid #f59e0b;">
                <h4 style="color: white; margin: 0 0 0.5rem 0;">{hunt['name']}</h4>
                <p style="color: #94a3b8; margin: 0 0 1rem 0;">{hunt['hypothesis']}</p>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="background: #f59e0b; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; font-weight: 600;">
                            {hunt['status']}
                        </span>
                        <span style="color: #94a3b8; margin-left: 1rem;">Started {hunt['started']}</span>
                    </div>
                    <div style="color: white; font-weight: 600;">{hunt['progress']}% Complete</div>
                </div>
                <div style="background: #334155; height: 8px; border-radius: 4px; margin-top: 1rem;">
                    <div style="background: #f59e0b; height: 100%; border-radius: 4px; width: {hunt['progress']}%;"></div>
                </div>
            </div>
        """, unsafe_allow_html=True)

with tab3:
    st.markdown("### ✅ Completed Threat Hunts")
    
    completed = [
        {
            'name': 'Unusual After-Hours Access',
            'completed': '1 day ago',
            'threats_found': 12,
            'time_taken': '45 minutes',
            'result': 'Threats Detected'
        },
        {
            'name': 'Brute Force Pattern Analysis',
            'completed': '3 days ago',
            'threats_found': 5,
            'time_taken': '1.2 hours',
            'result': 'Threats Detected'
        },
        {
            'name': 'Malware Communication Patterns',
            'completed': '5 days ago',
            'threats_found': 0,
            'time_taken': '2 hours',
            'result': 'No Threats Found'
        }
    ]
    
    for hunt in completed:
        result_color = '#10b981' if hunt['threats_found'] > 0 else '#64748b'
        
        st.markdown(f"""
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem; border-left: 4px solid {result_color};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4 style="color: white; margin: 0 0 0.5rem 0;">{hunt['name']}</h4>
                        <div style="color: #94a3b8; font-size: 0.875rem;">
                            Completed {hunt['completed']} • Took {hunt['time_taken']}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="background: {result_color}; color: white; padding: 0.5rem 1rem; border-radius: 12px; font-weight: 700; margin-bottom: 0.5rem;">
                            {hunt['threats_found']} Threats
                        </div>
                        <div style="color: #94a3b8; font-size: 0.875rem;">{hunt['result']}</div>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)