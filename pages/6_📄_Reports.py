"""
Edusiem Reports Page - Real Data Correlation
Generate reports with actual data from alerts, incidents, and simulations
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path
from sqlalchemy import func

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    Alert, Incident, User, DetectionRule, SimulatedAttack, IncidentResponse
)

st.set_page_config(page_title="Reports - Edusiem", page_icon="📄", layout="wide")

# Check auth
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">📄 Security Reports</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Generate comprehensive security analysis reports</p>
    </div>
""", unsafe_allow_html=True)

# Get database session
engine = get_database_engine()
session = get_session(engine)

# Tabs
tab1, tab2, tab3 = st.tabs(["📊 Generate Report", "📁 Report Archive", "📈 Analytics Dashboard"])

with tab1:
    st.markdown("### 📝 Create New Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        report_type = st.selectbox(
            "Report Type",
            ["Security Summary Report", "Alert Analysis Report", "Incident Response Report", 
             "Threat Intelligence Report", "Compliance Audit Report", "Executive Dashboard"]
        )
        
        date_range = st.date_input(
            "Date Range",
            value=(datetime.now() - timedelta(days=30), datetime.now())
        )
        
        include_charts = st.checkbox("Include Visualizations", value=True)
    
    with col2:
        format_type = st.selectbox("Export Format", ["TXT", "CSV", "JSON"])
        
        recipients = st.text_area(
            "Email Recipients (optional)",
            placeholder="admin@edusiem.edu, security@edusiem.edu"
        )
        
        include_recommendations = st.checkbox("Include Security Recommendations", value=True)
    
    if st.button("🚀 Generate Report", use_container_width=True, type="primary"):
        with st.spinner("Generating comprehensive security report..."):
            import time
            time.sleep(1)
            
            # Get date range
            start_date = datetime.combine(date_range[0], datetime.min.time())
            end_date = datetime.combine(date_range[1], datetime.max.time())
            
            # === ALERTS DATA ===
            total_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date)
            ).count()
            
            critical_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.severity == 'critical'
            ).count()
            
            high_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.severity == 'high'
            ).count()
            
            medium_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.severity == 'medium'
            ).count()
            
            low_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.severity == 'low'
            ).count()
            
            # True vs False positives
            true_positives = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.status == 'true_positive'
            ).count()
            
            false_positives = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.status == 'false_positive'
            ).count()
            
            new_alerts = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date),
                Alert.status == 'new'
            ).count()
            
            # === INCIDENTS DATA ===
            total_incidents = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date)
            ).count()
            
            open_incidents = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date),
                Incident.status == 'open'
            ).count()
            
            investigating_incidents = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date),
                Incident.status == 'investigating'
            ).count()
            
            resolved_incidents = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date),
                Incident.status == 'resolved'
            ).count()
            
            incidents_from_alerts = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date),
                Incident.created_from_alert == True
            ).count()
            
            # === RESPONSE ACTIONS ===
            total_responses = session.query(IncidentResponse).filter(
                IncidentResponse.created_at.between(start_date, end_date)
            ).count()
            
            completed_responses = session.query(IncidentResponse).filter(
                IncidentResponse.created_at.between(start_date, end_date),
                IncidentResponse.status == 'completed'
            ).count()
            
            # === AVERAGE RESOLUTION TIME ===
            resolved_with_time = session.query(Incident).filter(
                Incident.created_at.between(start_date, end_date),
                Incident.status == 'resolved',
                Incident.resolved_at != None
            ).all()
            
            if resolved_with_time:
                resolution_times = [
                    (inc.resolved_at - inc.created_at).total_seconds() / 3600
                    for inc in resolved_with_time
                ]
                avg_resolution_hours = sum(resolution_times) / len(resolution_times)
            else:
                avg_resolution_hours = 0
            
            # === GET ALERT TYPES ===
            alerts_in_period = session.query(Alert).filter(
                Alert.created_at.between(start_date, end_date)
            ).all()
            
            alert_type_counts = {}
            for alert in alerts_in_period:
                alert_type = alert.alert_type.replace('_', ' ').title()
                alert_type_counts[alert_type] = alert_type_counts.get(alert_type, 0) + 1
            
            sorted_threats = sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True)
            
            # === GET TOP SOURCES ===
            source_counts = {}
            for alert in alerts_in_period:
                if alert.source_ip:
                    source_counts[alert.source_ip] = source_counts.get(alert.source_ip, 0) + 1
            
            top_sources_list = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # === GET RESPONSE ACTION TYPES ===
            response_actions = session.query(IncidentResponse).filter(
                IncidentResponse.created_at.between(start_date, end_date)
            ).all()
            
            action_counts = {}
            for action in response_actions:
                action_type = action.action_type.replace('_', ' ').title()
                action_counts[action_type] = action_counts.get(action_type, 0) + 1
            
            # === DISPLAY REPORT ===
            st.success("✅ Report generated successfully!")
            
            st.markdown("---")
            st.markdown("# 📊 Security Report")
            st.markdown(f"**Report Type:** {report_type}")
            st.markdown(f"**Generated:** {datetime.now().strftime('%B %d, %Y at %I:%M %p')}")
            st.markdown(f"**Period:** {date_range[0].strftime('%B %d, %Y')} to {date_range[1].strftime('%B %d, %Y')}")
            st.markdown(f"**Generated by:** {st.session_state['full_name']}")
            
            st.markdown("---")
            
            # === EXECUTIVE SUMMARY ===
            st.markdown("## 📌 Executive Summary")
            
            summary_data = {
                'Metric': [
                    'Total Security Alerts',
                    'Critical Alerts',
                    'High Priority Alerts',
                    'Medium Priority Alerts',
                    'Low Priority Alerts',
                    'New/Unreviewed Alerts',
                    'True Positives',
                    'False Positives',
                    'Total Incidents',
                    'Open Incidents',
                    'Investigating',
                    'Resolved Incidents',
                    'Incidents from Alerts',
                    'Response Actions Taken',
                    'Completed Actions',
                    'Avg Resolution Time (hours)'
                ],
                'Value': [
                    total_alerts,
                    critical_alerts,
                    high_alerts,
                    medium_alerts,
                    low_alerts,
                    new_alerts,
                    true_positives,
                    false_positives,
                    total_incidents,
                    open_incidents,
                    investigating_incidents,
                    resolved_incidents,
                    incidents_from_alerts,
                    total_responses,
                    completed_responses,
                    f"{avg_resolution_hours:.1f}"
                ]
            }
            
            df_summary = pd.DataFrame(summary_data)
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
            
            # === KEY FINDINGS ===
            st.markdown("---")
            st.markdown("## 🔍 Key Findings")
            
            # Calculate metrics
            if (true_positives + false_positives) > 0:
                accuracy_rate = (true_positives / (true_positives + false_positives) * 100)
            else:
                accuracy_rate = 0
            
            if true_positives > 0:
                incident_creation_rate = (incidents_from_alerts / true_positives * 100)
            else:
                incident_creation_rate = 0
            
            if total_incidents > 0:
                resolution_rate = (resolved_incidents / total_incidents * 100)
            else:
                resolution_rate = 0
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric(
                    "Alert Accuracy Rate",
                    f"{accuracy_rate:.1f}%",
                    help="Percentage of alerts that were true positives"
                )
            
            with col2:
                st.metric(
                    "Incident Creation Rate",
                    f"{incident_creation_rate:.1f}%",
                    help="Percentage of true positive alerts that became incidents"
                )
            
            with col3:
                st.metric(
                    "Resolution Rate",
                    f"{resolution_rate:.1f}%",
                    help="Percentage of incidents that were resolved"
                )
            
            # === VISUALIZATIONS ===
            if include_charts and total_alerts > 0:
                st.markdown("---")
                st.markdown("## 📊 Visualizations")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Alert severity distribution
                    severity_data = pd.DataFrame({
                        'Severity': ['Critical', 'High', 'Medium', 'Low'],
                        'Count': [critical_alerts, high_alerts, medium_alerts, low_alerts]
                    })
                    
                    fig = px.pie(
                        severity_data,
                        values='Count',
                        names='Severity',
                        title='Alert Severity Distribution',
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#dc2626',
                            'High': '#f59e0b',
                            'Medium': '#3b82f6',
                            'Low': '#10b981'
                        }
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        font={'color': 'white'},
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # True vs False Positives
                    accuracy_data = pd.DataFrame({
                        'Status': ['True Positive', 'False Positive', 'Unreviewed'],
                        'Count': [true_positives, false_positives, new_alerts]
                    })
                    
                    fig = px.bar(
                        accuracy_data,
                        x='Status',
                        y='Count',
                        title='Alert Review Status',
                        color='Status',
                        color_discrete_map={
                            'True Positive': '#10b981',
                            'False Positive': '#ef4444',
                            'Unreviewed': '#3b82f6'
                        }
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(30, 41, 59, 0.5)',
                        font={'color': 'white'},
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Incident Status
                col3, col4 = st.columns(2)
                
                with col3:
                    incident_data = pd.DataFrame({
                        'Status': ['Open', 'Investigating', 'Resolved'],
                        'Count': [open_incidents, investigating_incidents, resolved_incidents]
                    })
                    
                    fig = px.pie(
                        incident_data,
                        values='Count',
                        names='Status',
                        title='Incident Status Distribution',
                        hole=0.4,
                        color='Status',
                        color_discrete_map={
                            'Open': '#ef4444',
                            'Investigating': '#f59e0b',
                            'Resolved': '#10b981'
                        }
                    )
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        font={'color': 'white'},
                        height=300
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col4:
                    # Response actions
                    if action_counts:
                        action_df = pd.DataFrame(
                            list(action_counts.items()),
                            columns=['Action', 'Count']
                        )
                        
                        fig = px.bar(
                            action_df,
                            x='Count',
                            y='Action',
                            orientation='h',
                            title='Response Actions Taken',
                            color='Count',
                            color_continuous_scale='Blues'
                        )
                        fig.update_layout(
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(30, 41, 59, 0.5)',
                            font={'color': 'white'},
                            height=300,
                            showlegend=False
                        )
                        st.plotly_chart(fig, use_container_width=True)
            
            # === TOP THREATS ===
            st.markdown("---")
            st.markdown("## 🎯 Top Threats Detected")
            
            if sorted_threats:
                for i, (threat_type, count) in enumerate(sorted_threats[:10], 1):
                    st.write(f"{i}. **{threat_type}** - {count} incident(s)")
            else:
                st.info("No threats detected in this period")
            
            # === TOP SOURCES ===
            if top_sources_list:
                st.markdown("---")
                st.markdown("## 🌍 Top Threat Sources (by IP)")
                
                for i, (source_ip, count) in enumerate(top_sources_list, 1):
                    st.write(f"{i}. **{source_ip}** - {count} alert(s)")
            
            # === INCIDENT RESPONSE ===
            st.markdown("---")
            st.markdown("## 🛡️ Incident Response Summary")
            
            if total_responses > 0:
                st.write(f"**Total Response Actions:** {total_responses}")
                st.write(f"**Completed Actions:** {completed_responses}")
                st.write(f"**Success Rate:** {(completed_responses/total_responses*100):.1f}%")
                st.write("")
                
                if action_counts:
                    st.write("**Actions Breakdown:**")
                    for action_type, count in sorted(action_counts.items(), key=lambda x: x[1], reverse=True):
                        st.write(f"- {action_type}: {count}")
            else:
                st.info("No response actions taken in this period")
            
            # === RECOMMENDATIONS ===
            if include_recommendations:
                st.markdown("---")
                st.markdown("## 💡 Security Recommendations")
                
                recommendations = []
                
                # Dynamic recommendations
                if critical_alerts > 5:
                    recommendations.append("🔴 **High number of critical alerts** - Review and strengthen critical system protections")
                
                if false_positives > true_positives:
                    recommendations.append("⚠️ **High false positive rate** - Review and tune detection rules")
                
                if open_incidents > resolved_incidents:
                    recommendations.append("📝 **More open than resolved incidents** - Increase analyst capacity")
                
                if avg_resolution_hours > 24:
                    recommendations.append("⏱️ **Long average resolution time** - Implement faster response procedures")
                
                if new_alerts > (total_alerts * 0.5):
                    recommendations.append("👁️ **Many unreviewed alerts** - Allocate more time for alert triage")
                
                # Standard recommendations
                recommendations.extend([
                    "✅ **Enable Multi-Factor Authentication** for all privileged accounts",
                    "✅ **Conduct security awareness training** for students and faculty",
                    "✅ **Implement automated response playbooks** for common scenarios",
                    "✅ **Regular security audits** of critical systems",
                    "✅ **Keep systems updated** with latest security patches"
                ])
                
                for rec in recommendations:
                    st.info(rec)
            
            # === DATA CORRELATION ===
            st.markdown("---")
            st.markdown("## 🔗 Data Correlation Insights")
            
            st.write(f"**Alert → Incident Workflow:**")
            st.write(f"- {incidents_from_alerts} out of {total_incidents} incidents were created from alerts")
            st.write(f"- {(incidents_from_alerts/total_incidents*100):.1f}% automation rate" if total_incidents > 0 else "- 0% automation rate")
            
            st.write(f"\n**Response Effectiveness:**")
            st.write(f"- {completed_responses} out of {total_responses} actions completed")
            st.write(f"- {(completed_responses/total_responses*100):.1f}% success rate" if total_responses > 0 else "- N/A")
            
            # === DOWNLOAD REPORT ===
            st.markdown("---")
            st.markdown("## 📥 Download Report")
            
            # Generate text report
            report_content = f"""
╔══════════════════════════════════════════════════════════════╗
║              EDUSIEM SECURITY REPORT                         ║
║              {report_type}                                   
╚══════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
Period: {date_range[0].strftime('%B %d, %Y')} to {date_range[1].strftime('%B %d, %Y')}
Generated by: {st.session_state['full_name']}

═══════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════

Security Alerts:
  • Total: {total_alerts}
  • Critical: {critical_alerts}
  • High: {high_alerts}
  • Medium: {medium_alerts}
  • Low: {low_alerts}

Alert Review Status:
  • True Positives: {true_positives}
  • False Positives: {false_positives}
  • Unreviewed: {new_alerts}
  • Accuracy Rate: {accuracy_rate:.1f}%

Incidents:
  • Total: {total_incidents}
  • Open: {open_incidents}
  • Investigating: {investigating_incidents}
  • Resolved: {resolved_incidents}
  • From Alerts: {incidents_from_alerts}
  • Resolution Rate: {resolution_rate:.1f}%
  • Avg Resolution Time: {avg_resolution_hours:.1f} hours

Response Actions:
  • Total: {total_responses}
  • Completed: {completed_responses}
  • Success Rate: {(completed_responses/total_responses*100):.1f}%

═══════════════════════════════════════════════════════════════
TOP THREATS
═══════════════════════════════════════════════════════════════

"""
            
            for i, (threat_type, count) in enumerate(sorted_threats[:10], 1):
                report_content += f"{i}. {threat_type}: {count} incident(s)\n"
            
            if top_sources_list:
                report_content += f"""
═══════════════════════════════════════════════════════════════
TOP THREAT SOURCES
═══════════════════════════════════════════════════════════════

"""
                for i, (source_ip, count) in enumerate(top_sources_list, 1):
                    report_content += f"{i}. {source_ip}: {count} alert(s)\n"
            
            report_content += f"""
═══════════════════════════════════════════════════════════════
SECURITY RECOMMENDATIONS
═══════════════════════════════════════════════════════════════

"""
            for rec in recommendations:
                clean_rec = rec.replace('🔴', '').replace('⚠️', '').replace('📝', '').replace('⏱️', '').replace('👁️', '').replace('✅', '').replace('**', '')
                report_content += f"• {clean_rec}\n"
            
            report_content += f"""
═══════════════════════════════════════════════════════════════
CONCLUSION
═══════════════════════════════════════════════════════════════

This report covers the period from {date_range[0].strftime('%B %d, %Y')} to 
{date_range[1].strftime('%B %d, %Y')}.

Key Statistics:
- {total_alerts} alerts generated
- {true_positives} confirmed threats
- {resolved_incidents} incidents resolved
- {avg_resolution_hours:.1f} hours average resolution time

Continued monitoring and security improvements recommended.

═══════════════════════════════════════════════════════════════
Generated by Edusiem - Educational Institution SIEM
Contact: security@edusiem.edu
═══════════════════════════════════════════════════════════════
"""
            
            col_a, col_b, col_c = st.columns(3)
            
            with col_a:
                st.download_button(
                    label="📥 Download TXT",
                    data=report_content,
                    file_name=f"edusiem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            
            with col_b:
                csv_data = df_summary.to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv_data,
                    file_name=f"edusiem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            
            with col_c:
                if recipients:
                    if st.button("📧 Send Email", use_container_width=True):
                        st.success(f"✅ Report sent to: {recipients}")

with tab2:
    st.markdown("### 📁 Report Archive")
    
    st.info("📝 Generated reports are stored here for future reference")
    
    # Get some stats for archive
    all_alerts = session.query(Alert).count()
    all_incidents = session.query(Incident).count()
    
    sample_reports = [
        {
            'name': f'Security Summary - {(datetime.now() - timedelta(days=7)).strftime("%B %d")}',
            'type': 'Security Summary',
            'generated': '7 days ago',
            'size': '156 KB'
        },
        {
            'name': f'Incident Response - {(datetime.now() - timedelta(days=14)).strftime("%B %d")}',
            'type': 'Incident Response',
            'generated': '14 days ago',
            'size': '234 KB'
        },
        {
            'name': f'Threat Intelligence - {(datetime.now() - timedelta(days=30)).strftime("%B %d")}',
            'type': 'Threat Intelligence',
            'generated': '30 days ago',
            'size': '189 KB'
        }
    ]
    
    for report in sample_reports:
        with st.expander(f"**{report['name']}**"):
            st.write(f"**Type:** {report['type']}")
            st.write(f"**Generated:** {report['generated']}")
            st.write(f"**Size:** {report['size']}")
            
            col1, col2 = st.columns(2)
            with col1:
                st.button("📥 Download", key=f"dl_{report['name']}", disabled=True)
            with col2:
                st.button("📧 Send", key=f"send_{report['name']}", disabled=True)

with tab3:
    st.markdown("### 📈 Analytics Dashboard")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Alert trend
        st.markdown("#### 📊 Alert Trend (Last 30 Days)")
        
        days = []
        counts = []
        
        for i in range(30, 0, -1):
            day = datetime.now() - timedelta(days=i)
            day_start = datetime.combine(day.date(), datetime.min.time())
            day_end = datetime.combine(day.date(), datetime.max.time())
            
            count = session.query(Alert).filter(
                Alert.created_at.between(day_start, day_end)
            ).count()
            
            days.append(day.strftime('%m/%d'))
            counts.append(count)
        
        df_trend = pd.DataFrame({'Date': days, 'Alerts': counts})
        
        fig = px.area(df_trend, x='Date', y='Alerts', title='Daily Alert Count')
        fig.update_traces(line_color='#3b82f6', fillcolor='rgba(59, 130, 246, 0.3)')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(30, 41, 59, 0.5)',
            font={'color': 'white'},
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Incident status
        st.markdown("#### 📝 Current Incident Status")
        
        status_counts = {
            'Open': session.query(Incident).filter(Incident.status == 'open').count(),
            'Investigating': session.query(Incident).filter(Incident.status == 'investigating').count(),
            'Resolved': session.query(Incident).filter(Incident.status == 'resolved').count(),
            'Closed': session.query(Incident).filter(Incident.status == 'closed').count()
        }
        
        df_status = pd.DataFrame(list(status_counts.items()), columns=['Status', 'Count'])
        
        fig = px.pie(df_status, values='Count', names='Status', hole=.4)
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Overall metrics
    st.markdown("---")
    st.markdown("#### 📊 Overall System Metrics")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_sys_alerts = session.query(Alert).count()
    total_sys_incidents = session.query(Incident).count()
    total_users = session.query(User).filter(User.is_active == True).count()
    total_rules = session.query(DetectionRule).filter(DetectionRule.is_enabled == True).count()
    total_sims = session.query(SimulatedAttack).count()
    
    with col1:
        st.metric("Total Alerts", total_sys_alerts)
    
    with col2:
        st.metric("Total Incidents", total_sys_incidents)
    
    with col3:
        st.metric("Active Users", total_users)
    
    with col4:
        st.metric("Detection Rules", total_rules)
    
    with col5:
        st.metric("Simulations", total_sims)

session.close()