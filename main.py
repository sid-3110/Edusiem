"""
Edusiem - Main Application
Educational Institution SIEM
"""

import streamlit as st
from database.models import (
    get_database_engine, 
    create_all_tables, 
    get_session, 
    User, 
    create_default_users
)
from datetime import datetime

# Page config
st.set_page_config(
    page_title="Edusiem - Educational SIEM",
    page_icon="🛡️",
    layout="wide"
)

# CSS
st.markdown("""
<style>
    .header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 40px rgba(59, 130, 246, 0.3);
    }
    
    .header h1 {
        margin: 0;
        font-size: 2.5rem;
        font-weight: 800;
    }
    
    .header p {
        margin: 0.5rem 0 0 0;
        opacity: 0.9;
    }
</style>
""", unsafe_allow_html=True)


def initialize_database():
    """Initialize database"""
    engine = get_database_engine()
    create_all_tables(engine)
    session = get_session(engine)
    create_default_users(session)
    session.close()
    return engine


def login_page():
    """Login page"""
    st.markdown("""
        <div class="header">
            <h1>🛡️ EDUSIEM</h1>
            <p>Security Information and Event Management for Educational Institutions</p>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("### 🔐 Login")
        
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        
        if st.button("Login", use_container_width=True):
            if authenticate_user(username, password):
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials")
        
        st.markdown("---")
        st.info("""
        **Demo Credentials:**
        - Admin: `admin` / `admin123`
        - Student: `student1` / `student123`
        """)


def authenticate_user(username, password):
    """Authenticate user"""
    engine = get_database_engine()
    session = get_session(engine)
    
    user = session.query(User).filter_by(username=username).first()
    
    if user and user.check_password(password):
        user.last_login = datetime.utcnow()
        session.commit()
        
        st.session_state['authenticated'] = True
        st.session_state['user_id'] = user.id
        st.session_state['username'] = user.username
        st.session_state['role'] = user.role
        st.session_state['full_name'] = user.full_name
        
        session.close()
        return True
    
    session.close()
    return False


def logout():
    """Logout"""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()


def main_app():
    """Main dashboard"""
    
    # Sidebar
    with st.sidebar:
        st.markdown("""
            <div style="text-align: center; padding: 1rem; background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); border-radius: 10px; margin-bottom: 1rem;">
                <h2 style="color: white; margin: 0;">🛡️ EDUSIEM</h2>
            </div>
        """, unsafe_allow_html=True)
        
        st.write(f"**User:** {st.session_state['full_name']}")
        st.write(f"**Role:** {st.session_state['role'].title()}")
        
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    # Main content
    st.markdown("""
        <div class="header">
            <h1>🛡️ Security Operations Dashboard</h1>
            <p>Real-time Threat Monitoring and Incident Management</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(label="🚨 Active Alerts", value="47", delta="12 new")
    
    with col2:
        st.metric(label="📝 Open Incidents", value="5", delta="-2")
    
    with col3:
        st.metric(label="💻 Monitored Hosts", value="156", delta="2")
    
    with col4:
        st.metric(label="⚡ Threat Level", value="MEDIUM")
    
    st.markdown("---")
    
    st.success("✅ System operational. All monitoring services active.")
    
    st.info("""
    **Next Steps:**
    - Click pages in sidebar (once we add them)
    - View alerts, incidents, logs
    - Generate reports
    """)


def main():
    """Entry point"""
    
    # Initialize DB once
    if 'db_initialized' not in st.session_state:
        initialize_database()
        st.session_state['db_initialized'] = True
    
    # Check auth
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        login_page()
    else:
        main_app()


if __name__ == "__main__":
    main()