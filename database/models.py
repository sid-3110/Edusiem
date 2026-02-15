"""
Edusiem Complete Database Models - Fully Correlated
All entities are interconnected for complete data flow
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import bcrypt
import os

Base = declarative_base()


# ============================================
# USERS & ROLES
# ============================================

class User(Base):
    """User accounts with role-based access"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(120), nullable=False)
    
    # Role: admin, edusiem_lead, security_analyst, student, faculty
    role = Column(String(20), nullable=False)
    department = Column(String(100))
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    created_alerts = relationship('Alert', foreign_keys='Alert.created_by', backref='creator')
    reviewed_alerts = relationship('Alert', foreign_keys='Alert.reviewed_by', backref='reviewer')
    reported_incidents = relationship('Incident', foreign_keys='Incident.reported_by', backref='reporter')
    assigned_incidents = relationship('Incident', foreign_keys='Incident.assigned_to', backref='assignee')
    
    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


# ============================================
# ALERTS (Updated with correlation)
# ============================================

class Alert(Base):
    """Security alerts with full workflow tracking"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    
    # Alert details
    alert_type = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    
    # Status tracking - THIS IS KEY FOR WORKFLOW
    status = Column(String(20), default='new')  # new, true_positive, false_positive, dismissed
    
    # Source information
    source = Column(String(50))  # brute_force, port_scan, sql_injection, etc.
    source_ip = Column(String(50))
    target_ip = Column(String(50))
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Rule that triggered this alert
    rule_id = Column(String(50))
    rule_name = Column(String(200))
    
    # Workflow tracking
    created_by = Column(Integer, ForeignKey('users.id'))  # System or user who created
    reviewed_by = Column(Integer, ForeignKey('users.id'))  # Analyst who reviewed
    
    # Correlation to incident
    incident_id = Column(Integer, ForeignKey('incidents.id'))  # Created incident (if true positive)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)
    
    # Additional evidence
    evidence = Column(Text)  # JSON with attack details
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'status': self.status,
            'source': self.source,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'user_id': self.user_id,
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'incident_id': self.incident_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'reviewed_by': self.reviewed_by,
            'evidence': self.evidence
        }


# ============================================
# INCIDENTS (Updated with correlation)
# ============================================

class Incident(Base):
    """Security incidents with full tracking"""
    __tablename__ = 'incidents'
    
    id = Column(Integer, primary_key=True)
    
    # Incident details
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    incident_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    priority = Column(String(20), default='medium')
    status = Column(String(20), default='open')  # open, investigating, resolved, closed
    
    # Correlation - THIS IS KEY
    alert_id = Column(Integer, ForeignKey('alerts.id'))  # Original alert
    alert = relationship('Alert', foreign_keys=[alert_id], backref='related_incident')
    
    created_from_alert = Column(Boolean, default=False)  # Was this auto-created from alert?
    
    # Assignment
    reported_by = Column(Integer, ForeignKey('users.id'))
    assigned_to = Column(Integer, ForeignKey('users.id'))  # Security analyst
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime)
    
    # Resolution
    resolution_notes = Column(Text)
    
    # Response actions taken
    responses = relationship('IncidentResponse', backref='incident')
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'incident_type': self.incident_type,
            'severity': self.severity,
            'priority': self.priority,
            'status': self.status,
            'alert_id': self.alert_id,
            'created_from_alert': self.created_from_alert,
            'reported_by': self.reported_by,
            'assigned_to': self.assigned_to,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution_notes': self.resolution_notes
        }


# ============================================
# INCIDENT RESPONSES
# ============================================

class IncidentResponse(Base):
    """Actions taken in response to incidents"""
    __tablename__ = 'incident_responses'
    
    id = Column(Integer, primary_key=True)
    incident_id = Column(Integer, ForeignKey('incidents.id'), nullable=False)
    
    action_type = Column(String(50), nullable=False)  # block_ip, disable_account, isolate_host
    action_description = Column(Text, nullable=False)
    status = Column(String(20), default='pending')  # pending, completed, failed
    
    executed_by = Column(Integer, ForeignKey('users.id'))
    executed_at = Column(DateTime)
    
    result = Column(Text)
    
    created_at = Column(DateTime, default=datetime.utcnow)


# ============================================
# DETECTION RULES
# ============================================

class DetectionRule(Base):
    """Rules that trigger alerts"""
    __tablename__ = 'detection_rules'
    
    id = Column(Integer, primary_key=True)
    rule_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Rule type
    attack_type = Column(String(50), nullable=False)  # brute_force, port_scan, etc.
    severity = Column(String(20), nullable=False)
    
    # Rule logic (stored as JSON)
    conditions = Column(Text, nullable=False)  # {"failed_logins": 5, "time_window": 600}
    
    # Status
    is_enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


# ============================================
# ATTACK SIMULATIONS (For testing)
# ============================================

class SimulatedAttack(Base):
    """Record of simulated attacks for testing"""
    __tablename__ = 'simulated_attacks'
    
    id = Column(Integer, primary_key=True)
    
    attack_type = Column(String(50), nullable=False)
    attack_name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Simulation details
    source_ip = Column(String(50))
    target_ip = Column(String(50))
    parameters = Column(Text)  # JSON with attack parameters
    
    # Results
    alert_generated = Column(Boolean, default=False)
    alert_id = Column(Integer, ForeignKey('alerts.id'))
    
    # Execution
    simulated_by = Column(Integer, ForeignKey('users.id'))
    simulated_at = Column(DateTime, default=datetime.utcnow)
    
    status = Column(String(20))  # success, failed

# ============================================
# NETWORK & FIREWALL LOGS
# ============================================

class NetworkLog(Base):
    """Network traffic monitoring"""
    __tablename__ = 'network_logs'
    
    id = Column(Integer, primary_key=True)
    source_ip = Column(String(50), nullable=False)
    source_port = Column(Integer)
    destination_ip = Column(String(50), nullable=False)
    destination_port = Column(Integer)
    protocol = Column(String(20))  # TCP, UDP, ICMP, HTTP, HTTPS
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    packets = Column(Integer)
    status = Column(String(20), default='normal')  # normal, suspicious, blocked
    threat_level = Column(String(20), default='low')  # low, medium, high, critical
    user_id = Column(Integer, ForeignKey('users.id'))
    connection_state = Column(String(20))  # established, closed, syn_sent, etc.
    duration = Column(Integer)  # in seconds
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Correlation to alert (if this network activity triggered an alert)
    alert_id = Column(Integer, ForeignKey('alerts.id'))


class FirewallLog(Base):
    """Firewall events and blocked threats"""
    __tablename__ = 'firewall_logs'
    
    id = Column(Integer, primary_key=True)
    action = Column(String(20), nullable=False)  # allow, block, drop, reject
    rule_name = Column(String(100))
    rule_id = Column(String(50))
    source_ip = Column(String(50), nullable=False)
    source_port = Column(Integer)
    source_country = Column(String(50))
    destination_ip = Column(String(50), nullable=False)
    destination_port = Column(Integer)
    protocol = Column(String(20))  # TCP, UDP, ICMP
    threat_type = Column(String(50))  # port_scan, ddos, brute_force, malware, etc.
    severity = Column(String(20), default='low')  # low, medium, high, critical
    bytes_transferred = Column(Integer)
    packets = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Correlation to alert (if this firewall event triggered an alert)
    alert_id = Column(Integer, ForeignKey('alerts.id'))
# ============================================
# DATABASE CONNECTION
# ============================================

def get_database_engine(db_path='data/edusiem.db'):
    """Create database engine"""
    if not os.path.exists('data'):
        os.makedirs('data')
    
    engine = create_engine(f'sqlite:///{db_path}', echo=False)
    return engine


def create_all_tables(engine):
    """Create all tables"""
    Base.metadata.create_all(engine)
    print("✅ All database tables created successfully!")


def get_session(engine):
    """Get database session"""
    Session = sessionmaker(bind=engine)
    return Session()


def create_default_users(session):
    """Create default test users with all roles"""
    
    # Check if users exist
    if session.query(User).count() > 0:
        return
    
    # Admin
    admin = User(
        username='admin',
        email='admin@edusiem.edu',
        full_name='System Administrator',
        role='admin',
        department='IT Security'
    )
    admin.set_password('admin123')
    
    # Edusiem Lead
    lead = User(
        username='lead1',
        email='lead@edusiem.edu',
        full_name='Security Lead',
        role='edusiem_lead',
        department='Security Operations'
    )
    lead.set_password('lead123')
    
    # Security Analysts
    analyst1 = User(
        username='analyst1',
        email='analyst1@edusiem.edu',
        full_name='John Analyst',
        role='security_analyst',
        department='Security Operations'
    )
    analyst1.set_password('analyst123')
    
    analyst2 = User(
        username='analyst2',
        email='analyst2@edusiem.edu',
        full_name='Jane Analyst',
        role='security_analyst',
        department='Security Operations'
    )
    analyst2.set_password('analyst123')
    
    # Student
    student = User(
        username='student1',
        email='student1@edusiem.edu',
        full_name='Student User',
        role='student',
        department='Computer Science'
    )
    student.set_password('student123')
    
    # Faculty
    faculty = User(
        username='faculty1',
        email='faculty1@edusiem.edu',
        full_name='Dr. Faculty',
        role='faculty',
        department='Computer Science'
    )
    faculty.set_password('faculty123')
    
    # Save all
    session.add_all([admin, lead, analyst1, analyst2, student, faculty])
    session.commit()
    
    print("✅ Default users created:")
    print("   Admin: admin / admin123")
    print("   Lead: lead1 / lead123")
    print("   Analyst 1: analyst1 / analyst123")
    print("   Analyst 2: analyst2 / analyst123")
    print("   Student: student1 / student123")
    print("   Faculty: faculty1 / faculty123")


def create_default_rules(session):
    """Create default detection rules"""
    
    if session.query(DetectionRule).count() > 0:
        return
    
    rules = [
        DetectionRule(
            rule_id='RULE-001',
            name='Brute Force Detection',
            description='Detects 5 or more failed login attempts within 10 minutes',
            attack_type='brute_force',
            severity='high',
            conditions='{"failed_attempts": 5, "time_window_minutes": 10}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-002',
            name='Port Scan Detection',
            description='Detects scanning of multiple ports from single source',
            attack_type='port_scan',
            severity='medium',
            conditions='{"ports_scanned": 10, "time_window_seconds": 60}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-003',
            name='SQL Injection Detection',
            description='Detects SQL injection attempts in web requests',
            attack_type='sql_injection',
            severity='critical',
            conditions='{"sql_keywords": ["SELECT", "UNION", "DROP", "OR 1=1"]}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-004',
            name='Unusual Time Access',
            description='Detects access during unusual hours (2 AM - 5 AM)',
            attack_type='unusual_time',
            severity='medium',
            conditions='{"hours_start": 2, "hours_end": 5}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-005',
            name='Geographic Anomaly',
            description='Detects login from unusual geographic location',
            attack_type='geo_anomaly',
            severity='high',
            conditions='{"distance_threshold_km": 500}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-006',
            name='Data Exfiltration',
            description='Detects excessive file downloads',
            attack_type='data_exfiltration',
            severity='critical',
            conditions='{"files_downloaded": 50, "time_window_minutes": 60}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-007',
            name='Malware Detection',
            description='Detects suspicious file uploads or malware signatures',
            attack_type='malware',
            severity='critical',
            conditions='{"file_types": [".exe", ".bat", ".ps1"], "suspicious_names": ["trojan", "virus"]}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-008',
            name='Privilege Escalation',
            description='Detects attempts to gain elevated privileges',
            attack_type='privilege_escalation',
            severity='critical',
            conditions='{"admin_access_attempts": 3}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-009',
            name='Phishing Detection',
            description='Detects phishing emails or suspicious links',
            attack_type='phishing',
            severity='high',
            conditions='{"suspicious_keywords": ["verify account", "urgent", "click here"]}',
            is_enabled=True
        ),
        DetectionRule(
            rule_id='RULE-010',
            name='DDoS Detection',
            description='Detects Distributed Denial of Service attacks',
            attack_type='ddos',
            severity='critical',
            conditions='{"requests_per_second": 1000, "unique_sources": 50}',
            is_enabled=True
        )
    ]
    
    session.add_all(rules)
    session.commit()
    
    print("✅ Default detection rules created!")