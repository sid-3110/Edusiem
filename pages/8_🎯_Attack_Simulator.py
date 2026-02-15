"""
Edusiem Attack Simulator
Simulate various cyber attacks to test detection rules
Includes: Application, Network, and Firewall attacks
"""

import streamlit as st
from datetime import datetime
import random
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from database.models import (
    get_database_engine, get_session,
    Alert, DetectionRule, SimulatedAttack, User, NetworkLog, FirewallLog
)

st.set_page_config(page_title="Attack Simulator - Edusiem", page_icon="🎯", layout="wide")

# Check auth - Only admin and lead can access
if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
    st.error("🔒 Please login first")
    st.stop()

if st.session_state['role'] not in ['admin', 'edusiem_lead']:
    st.error("❌ Access Denied: Only Admin and Edusiem Lead can access Attack Simulator")
    st.stop()

# Header
st.markdown("""
    <div style="background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%); padding: 2rem; border-radius: 15px; margin-bottom: 2rem;">
        <h1 style="color: white; margin: 0;">🎯 Attack Simulator</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 0.5rem 0 0 0;">Test detection rules by simulating cyber attacks</p>
    </div>
""", unsafe_allow_html=True)

# Warning
st.warning("⚠️ **Testing Environment Only** - These simulations trigger real alerts in the system for testing purposes.")

# Get database session
engine = get_database_engine()
session = get_session(engine)

# =============================================================================
# SIMULATION FUNCTIONS - APPLICATION ATTACKS
# =============================================================================

def simulate_brute_force():
    """Simulate brute force attack"""
    source_ip = f"203.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_ip = "10.0.1.100"
    
    alert = Alert(
        alert_type='brute_force',
        title='Brute Force Attack Detected',
        message=f'Multiple failed login attempts detected from {source_ip}',
        severity='high',
        status='new',
        source='attack_simulator',
        source_ip=source_ip,
        target_ip=target_ip,
        rule_id='RULE-001',
        rule_name='Brute Force Detection',
        evidence=json.dumps({
            'failed_attempts': 7,
            'time_window': '10 minutes',
            'username_targeted': 'admin',
            'attack_pattern': 'dictionary_attack'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='brute_force',
        attack_name='Brute Force Login Attack',
        description='Simulated 7 failed login attempts within 10 minutes',
        source_ip=source_ip,
        target_ip=target_ip,
        parameters=json.dumps({'attempts': 7}),
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


def simulate_sql_injection():
    """Simulate SQL injection attack"""
    source_ip = f"102.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    alert = Alert(
        alert_type='sql_injection',
        title='SQL Injection Attempt Detected',
        message=f'SQL injection attempt detected from {source_ip}',
        severity='critical',
        status='new',
        source='attack_simulator',
        source_ip=source_ip,
        target_ip='10.0.2.100',
        rule_id='RULE-003',
        rule_name='SQL Injection Detection',
        evidence=json.dumps({
            'payload': "' OR '1'='1' --",
            'target_field': 'username',
            'url': '/student/login.php'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='sql_injection',
        attack_name='SQL Injection Attack',
        description='Simulated SQL injection in login form',
        source_ip=source_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


def simulate_malware():
    """Simulate malware detection"""
    alert = Alert(
        alert_type='malware',
        title='Malware Detected',
        message=f'Malicious file detected on workstation',
        severity='critical',
        status='new',
        source='attack_simulator',
        source_ip='10.0.5.32',
        rule_id='RULE-007',
        rule_name='Malware Detection',
        evidence=json.dumps({
            'file_name': 'invoice_2026.exe',
            'malware_type': 'Trojan.GenericKD',
            'workstation': 'LAB-PC-032',
            'detection_method': 'signature_match'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='malware',
        attack_name='Malware Detection',
        description='Simulated Trojan detection on workstation',
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, '10.0.5.32'


def simulate_phishing():
    """Simulate phishing detection"""
    alert = Alert(
        alert_type='phishing',
        title='Phishing Email Detected',
        message=f'Suspicious phishing email intercepted',
        severity='high',
        status='new',
        source='attack_simulator',
        source_ip='mail.suspicious-domain.com',
        rule_id='RULE-009',
        rule_name='Phishing Detection',
        evidence=json.dumps({
            'sender': 'admin@university-verify.com',
            'subject': 'URGENT: Verify Your Account',
            'suspicious_links': ['http://fake-university.com/verify'],
            'keywords': ['urgent', 'verify', 'click here']
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='phishing',
        attack_name='Phishing Email',
        description='Simulated phishing email detection',
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, 'mail.suspicious-domain.com'


def simulate_privilege_escalation():
    """Simulate privilege escalation"""
    user = session.query(User).filter_by(role='student').first()
    
    alert = Alert(
        alert_type='privilege_escalation',
        title='Privilege Escalation Attempt Detected',
        message=f'Unauthorized attempt to gain admin privileges',
        severity='critical',
        status='new',
        source='attack_simulator',
        source_ip='10.0.6.55',
        user_id=user.id if user else None,
        rule_id='RULE-008',
        rule_name='Privilege Escalation Detection',
        evidence=json.dumps({
            'attempts': 4,
            'target_privilege': 'administrator',
            'method': 'sudo_exploit',
            'commands_executed': ['sudo su', 'sudo -s']
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='privilege_escalation',
        attack_name='Privilege Escalation',
        description='Simulated attempt to gain admin access',
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, '10.0.6.55'


# =============================================================================
# SIMULATION FUNCTIONS - NETWORK ATTACKS
# =============================================================================

def simulate_port_scan_network():
    """Simulate network port scan with detailed network logs"""
    source_ip = f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_ip = "10.0.1.50"
    
    # Create multiple network log entries for port scan
    scanned_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 3306]
    
    for port in scanned_ports:
        net_log = NetworkLog(
            source_ip=source_ip,
            source_port=random.randint(40000, 65000),
            destination_ip=target_ip,
            destination_port=port,
            protocol='TCP',
            bytes_sent=64,
            bytes_received=0,
            packets=1,
            status='suspicious',
            threat_level='medium',
            connection_state='syn_sent'
        )
        session.add(net_log)
    
    session.commit()
    
    # Create alert
    alert = Alert(
        alert_type='port_scan',
        title='Network Port Scan Detected',
        message=f'Port scanning detected from {source_ip} targeting {target_ip}',
        severity='medium',
        status='new',
        source='network_monitor',
        source_ip=source_ip,
        target_ip=target_ip,
        rule_id='NET-RULE-001',
        rule_name='Port Scan Detection',
        evidence=json.dumps({
            'ports_scanned': scanned_ports,
            'scan_duration': '45 seconds',
            'scan_type': 'TCP SYN scan',
            'total_packets': len(scanned_ports)
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    # Update network logs with alert_id
    network_logs = session.query(NetworkLog).filter(
        NetworkLog.source_ip == source_ip,
        NetworkLog.destination_ip == target_ip
    ).all()
    
    for log in network_logs:
        log.alert_id = alert.id
    
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='network_port_scan',
        attack_name='Network Port Scan',
        description=f'Simulated port scan on {len(scanned_ports)} ports with network logs',
        source_ip=source_ip,
        target_ip=target_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


def simulate_ddos_network():
    """Simulate DDoS attack with network traffic flood"""
    target_ip = "10.0.0.1"
    
    # Create 100 network log entries simulating traffic flood
    source_ips = [f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)]
    
    for i in range(100):
        source_ip = random.choice(source_ips)
        net_log = NetworkLog(
            source_ip=source_ip,
            source_port=random.randint(1024, 65000),
            destination_ip=target_ip,
            destination_port=80,
            protocol='TCP',
            bytes_sent=random.randint(500, 2000),
            bytes_received=0,
            packets=random.randint(10, 50),
            status='suspicious',
            threat_level='critical',
            connection_state='syn_flood'
        )
        session.add(net_log)
    
    session.commit()
    
    # Create alert
    alert = Alert(
        alert_type='ddos',
        title='DDoS Attack Detected',
        message=f'DDoS attack detected targeting {target_ip} from {len(source_ips)} unique sources',
        severity='critical',
        status='new',
        source='network_monitor',
        source_ip='multiple_sources',
        target_ip=target_ip,
        rule_id='NET-RULE-002',
        rule_name='DDoS Detection',
        evidence=json.dumps({
            'unique_sources': len(source_ips),
            'total_connections': 100,
            'attack_type': 'SYN_flood',
            'target_service': 'Web Server (port 80)',
            'packets_per_second': 15000
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='ddos_network',
        attack_name='DDoS Network Attack',
        description=f'Simulated DDoS from {len(source_ips)} sources with 100 network log entries',
        source_ip='multiple',
        target_ip=target_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, 'multiple_sources'


def simulate_suspicious_traffic():
    """Simulate suspicious network traffic pattern"""
    source_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
    target_ip = f"8.8.{random.randint(1,255)}.{random.randint(1,255)}"
    
    # Create suspicious network activity - large data transfer
    for i in range(20):
        net_log = NetworkLog(
            source_ip=source_ip,
            source_port=random.randint(40000, 65000),
            destination_ip=target_ip,
            destination_port=443,
            protocol='HTTPS',
            bytes_sent=random.randint(5000000, 10000000),  # 5-10 MB per connection
            bytes_received=random.randint(1000, 5000),
            packets=random.randint(1000, 5000),
            status='suspicious',
            threat_level='high',
            connection_state='established',
            duration=random.randint(60, 300)
        )
        session.add(net_log)
    
    session.commit()
    
    # Calculate total data
    total_mb = (20 * 7500000) / (1024 * 1024)
    
    # Create alert
    alert = Alert(
        alert_type='data_exfiltration',
        title='Suspicious Data Transfer Detected',
        message=f'Large data transfer detected from internal host {source_ip}',
        severity='high',
        status='new',
        source='network_monitor',
        source_ip=source_ip,
        target_ip=target_ip,
        rule_id='NET-RULE-003',
        rule_name='Data Exfiltration Detection',
        evidence=json.dumps({
            'total_data_mb': round(total_mb, 2),
            'connections': 20,
            'destination': 'External IP',
            'protocol': 'HTTPS',
            'duration': '5 minutes'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='suspicious_traffic',
        attack_name='Suspicious Network Traffic',
        description=f'Simulated {round(total_mb, 2)} MB data transfer with network logs',
        source_ip=source_ip,
        target_ip=target_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


# =============================================================================
# SIMULATION FUNCTIONS - FIREWALL ATTACKS
# =============================================================================

def simulate_firewall_block():
    """Simulate firewall blocking malicious traffic"""
    source_ip = f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_ip = "10.0.1.100"
    
    # Create firewall log entries
    blocked_attempts = []
    threat_types = ['port_scan', 'brute_force', 'malware', 'sql_injection']
    
    for i in range(15):
        threat = random.choice(threat_types)
        fw_log = FirewallLog(
            action='block',
            rule_name='DENY_SUSPICIOUS_TRAFFIC',
            rule_id='FW-RULE-001',
            source_ip=source_ip,
            source_port=random.randint(1024, 65000),
            source_country='China',
            destination_ip=target_ip,
            destination_port=random.choice([22, 80, 443, 3389]),
            protocol='TCP',
            threat_type=threat,
            severity='high',
            packets=random.randint(1, 10)
        )
        session.add(fw_log)
        blocked_attempts.append(threat)
    
    session.commit()
    
    # Create alert
    alert = Alert(
        alert_type='firewall_block',
        title='Multiple Firewall Blocks Detected',
        message=f'Firewall blocked {len(blocked_attempts)} malicious attempts from {source_ip}',
        severity='high',
        status='new',
        source='firewall',
        source_ip=source_ip,
        target_ip=target_ip,
        rule_id='FW-RULE-001',
        rule_name='Suspicious Traffic Detection',
        evidence=json.dumps({
            'blocked_attempts': len(blocked_attempts),
            'threat_types': list(set(blocked_attempts)),
            'source_country': 'China',
            'action_taken': 'All traffic blocked'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    # Link firewall logs to alert
    fw_logs = session.query(FirewallLog).filter(
        FirewallLog.source_ip == source_ip
    ).all()
    
    for log in fw_logs:
        log.alert_id = alert.id
    
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='firewall_block',
        attack_name='Firewall Block Event',
        description=f'Simulated {len(blocked_attempts)} blocked attempts with firewall logs',
        source_ip=source_ip,
        target_ip=target_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


def simulate_intrusion_attempt():
    """Simulate intrusion attempt blocked by firewall"""
    source_ip = f"91.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    target_ip = "10.0.2.50"
    
    # Create firewall logs for intrusion attempts
    for i in range(25):
        fw_log = FirewallLog(
            action='drop',
            rule_name='INTRUSION_PREVENTION',
            rule_id='FW-RULE-002',
            source_ip=source_ip,
            source_port=random.randint(1024, 65000),
            source_country='Russia',
            destination_ip=target_ip,
            destination_port=random.choice([21, 22, 23, 3389, 445]),
            protocol='TCP',
            threat_type='intrusion_attempt',
            severity='critical',
            packets=random.randint(5, 20),
            bytes_transferred=random.randint(500, 2000)
        )
        session.add(fw_log)
    
    session.commit()
    
    # Create alert
    alert = Alert(
        alert_type='intrusion',
        title='Intrusion Attempt Blocked',
        message=f'Multiple intrusion attempts blocked from {source_ip}',
        severity='critical',
        status='new',
        source='firewall',
        source_ip=source_ip,
        target_ip=target_ip,
        rule_id='FW-RULE-002',
        rule_name='Intrusion Prevention',
        evidence=json.dumps({
            'attempts': 25,
            'source_country': 'Russia',
            'targeted_services': ['FTP', 'SSH', 'Telnet', 'RDP', 'SMB'],
            'action_taken': 'All packets dropped'
        }),
        created_by=st.session_state['user_id']
    )
    
    session.add(alert)
    session.commit()
    
    sim = SimulatedAttack(
        attack_type='intrusion_attempt',
        attack_name='Intrusion Attempt',
        description='Simulated 25 intrusion attempts with firewall logs',
        source_ip=source_ip,
        target_ip=target_ip,
        alert_generated=True,
        alert_id=alert.id,
        simulated_by=st.session_state['user_id'],
        status='success'
    )
    
    session.add(sim)
    session.commit()
    
    return alert.id, source_ip


# =============================================================================
# ATTACK SCENARIOS DEFINITION
# =============================================================================

attack_scenarios = {
    # Application Attacks
    'Brute Force Attack': {
        'icon': '🔐',
        'description': 'Simulate multiple failed login attempts',
        'severity': 'High',
        'category': 'Application',
        'function': simulate_brute_force
    },
    'SQL Injection': {
        'icon': '💉',
        'description': 'Simulate SQL injection attempt',
        'severity': 'Critical',
        'category': 'Application',
        'function': simulate_sql_injection
    },
    'Malware Detection': {
        'icon': '🦠',
        'description': 'Simulate malware on workstation',
        'severity': 'Critical',
        'category': 'Application',
        'function': simulate_malware
    },
    'Phishing Email': {
        'icon': '🎣',
        'description': 'Simulate phishing email detection',
        'severity': 'High',
        'category': 'Application',
        'function': simulate_phishing
    },
    'Privilege Escalation': {
        'icon': '⬆️',
        'description': 'Simulate unauthorized admin access attempt',
        'severity': 'Critical',
        'category': 'Application',
        'function': simulate_privilege_escalation
    },
    
    # Network Attacks
    'Network Port Scan': {
        'icon': '🔍',
        'description': 'Simulate network-level port scanning',
        'severity': 'Medium',
        'category': 'Network',
        'function': simulate_port_scan_network
    },
    'Network DDoS': {
        'icon': '💥',
        'description': 'Simulate DDoS with network traffic flood',
        'severity': 'Critical',
        'category': 'Network',
        'function': simulate_ddos_network
    },
    'Suspicious Network Traffic': {
        'icon': '📤',
        'description': 'Simulate large data exfiltration',
        'severity': 'High',
        'category': 'Network',
        'function': simulate_suspicious_traffic
    },
    
    # Firewall Attacks
    'Firewall Block Event': {
        'icon': '🛡️',
        'description': 'Simulate firewall blocking malicious traffic',
        'severity': 'High',
        'category': 'Firewall',
        'function': simulate_firewall_block
    },
    'Intrusion Attempt': {
        'icon': '⚠️',
        'description': 'Simulate intrusion blocked by firewall',
        'severity': 'Critical',
        'category': 'Firewall',
        'function': simulate_intrusion_attempt
    }
}

# =============================================================================
# UI - ATTACK SCENARIOS DISPLAY
# =============================================================================

st.markdown("### 🚨 Available Attack Scenarios")

# Category tabs
tab1, tab2, tab3 = st.tabs(["💻 Application Attacks", "🌐 Network Attacks", "🔥 Firewall Attacks"])

severity_colors = {
    'Critical': '#dc2626',
    'High': '#f59e0b',
    'Medium': '#3b82f6',
    'Low': '#10b981'
}

with tab1:
    st.markdown("#### Application-Level Attacks")
    app_attacks = {k: v for k, v in attack_scenarios.items() if v['category'] == 'Application'}
    
    col1, col2 = st.columns(2)
    
    for i, (attack_name, details) in enumerate(app_attacks.items()):
        with col1 if i % 2 == 0 else col2:
            st.markdown(f"""
                <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem; border-left: 4px solid {severity_colors[details['severity']]};">
                    <h3 style="margin: 0; color: white;">{details['icon']} {attack_name}</h3>
                    <p style="color: #94a3b8; margin: 0.5rem 0;">{details['description']}</p>
                    <span style="background: {severity_colors[details['severity']]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; font-weight: 700;">
                        {details['severity']} Severity
                    </span>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button(f"🚀 Launch {attack_name}", key=f"app_{i}", use_container_width=True):
                with st.spinner(f"Simulating {attack_name}..."):
                    import time
                    time.sleep(1)
                    
                    alert_id, source_ip = details['function']()
                    
                    st.success(f"✅ **{attack_name} Simulated Successfully!**")
                    st.info(f"🚨 **Alert #{alert_id} created** from {source_ip}")
                    st.info("👉 **Go to Alerts page** to review and create incident")
                    
                    with st.expander("📋 View Attack Evidence"):
                        alert = session.query(Alert).get(alert_id)
                        if alert and alert.evidence:
                            evidence = json.loads(alert.evidence)
                            for key, value in evidence.items():
                                st.write(f"**{key.replace('_', ' ').title()}:** {value}")

with tab2:
    st.markdown("#### Network-Level Attacks")
    net_attacks = {k: v for k, v in attack_scenarios.items() if v['category'] == 'Network'}
    
    col1, col2 = st.columns(2)
    
    for i, (attack_name, details) in enumerate(net_attacks.items()):
        with col1 if i % 2 == 0 else col2:
            st.markdown(f"""
                <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem; border-left: 4px solid {severity_colors[details['severity']]};">
                    <h3 style="margin: 0; color: white;">{details['icon']} {attack_name}</h3>
                    <p style="color: #94a3b8; margin: 0.5rem 0;">{details['description']}</p>
                    <span style="background: {severity_colors[details['severity']]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; font-weight: 700;">
                        {details['severity']} Severity
                    </span>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button(f"🚀 Launch {attack_name}", key=f"net_{i}", use_container_width=True):
                with st.spinner(f"Simulating {attack_name}..."):
                    import time
                    time.sleep(1)
                    
                    alert_id, source_ip = details['function']()
                    
                    st.success(f"✅ **{attack_name} Simulated Successfully!**")
                    st.info(f"🚨 **Alert #{alert_id} created** from {source_ip}")
                    st.info("👉 **Check Network Logs page** to see network traffic entries")
                    
                    with st.expander("📋 View Attack Evidence"):
                        alert = session.query(Alert).get(alert_id)
                        if alert and alert.evidence:
                            evidence = json.loads(alert.evidence)
                            for key, value in evidence.items():
                                st.write(f"**{key.replace('_', ' ').title()}:** {value}")

with tab3:
    st.markdown("#### Firewall-Level Attacks")
    fw_attacks = {k: v for k, v in attack_scenarios.items() if v['category'] == 'Firewall'}
    
    col1, col2 = st.columns(2)
    
    for i, (attack_name, details) in enumerate(fw_attacks.items()):
        with col1 if i % 2 == 0 else col2:
            st.markdown(f"""
                <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-bottom: 1rem; border-left: 4px solid {severity_colors[details['severity']]};">
                    <h3 style="margin: 0; color: white;">{details['icon']} {attack_name}</h3>
                    <p style="color: #94a3b8; margin: 0.5rem 0;">{details['description']}</p>
                    <span style="background: {severity_colors[details['severity']]}; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem; font-weight: 700;">
                        {details['severity']} Severity
                    </span>
                </div>
            """, unsafe_allow_html=True)
            
            if st.button(f"🚀 Launch {attack_name}", key=f"fw_{i}", use_container_width=True):
                with st.spinner(f"Simulating {attack_name}..."):
                    import time
                    time.sleep(1)
                    
                    alert_id, source_ip = details['function']()
                    
                    st.success(f"✅ **{attack_name} Simulated Successfully!**")
                    st.info(f"🚨 **Alert #{alert_id} created** from {source_ip}")
                    st.info("👉 **Check Firewall Logs page** to see firewall block entries")
                    
                    with st.expander("📋 View Attack Evidence"):
                        alert = session.query(Alert).get(alert_id)
                        if alert and alert.evidence:
                            evidence = json.loads(alert.evidence)
                            for key, value in evidence.items():
                                st.write(f"**{key.replace('_', ' ').title()}:** {value}")

st.markdown("---")

# Simulation History
st.markdown("### 📊 Recent Simulations")

recent_sims = session.query(SimulatedAttack).order_by(
    SimulatedAttack.simulated_at.desc()
).limit(15).all()

if recent_sims:
    for sim in recent_sims:
        col1, col2, col3 = st.columns([2, 2, 1])
        
        with col1:
            st.write(f"**{sim.attack_name}**")
        
        with col2:
            st.caption(f"Simulated {sim.simulated_at.strftime('%B %d, %Y at %I:%M %p')}")
        
        with col3:
            if sim.alert_generated:
                st.success("✅ Alert Created")
else:
    st.info("No simulations run yet. Click an attack scenario above to begin testing!")

session.close()