# 🛡️ EDUSIEM - Educational Institution SIEM
## Security Information and Event Management Platform

**Complete interconnected SIEM prototype with role-based access control**

---

## ✨ Features

### 🔗 **Complete Data Correlation**
- Alerts → Incidents → Reports (fully interconnected)
- True/False positive workflow
- Automatic incident creation from alerts
- Real-time data in all reports

### 👥 **Role-Based Access Control**
- **Admin**: Full system access
- **Edusiem Lead**: View all incidents, assign to analysts
- **Security Analyst**: View only assigned incidents
- **Student/Faculty**: Report incidents, view own alerts

### 🎯 **Attack Simulation**
- 10 realistic attack scenarios
- Automatic alert generation
- Evidence tracking
- Rule-based detection

### 📊 **Real-Time Reports**
- Pull actual data from database
- Alert accuracy metrics
- Incident resolution tracking
- Security recommendations

---

## 🚀 Quick Start

### Installation
```bash
# 1. Navigate to project
cd edusiem

# 2. Activate virtual environment
source venv/bin/activate  # Mac/Linux
venv\Scripts\activate     # Windows

# 3. Run Edusiem
streamlit run main.py
```

### Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| **Admin** | admin | admin123 |
| **Edusiem Lead** | lead1 | lead123 |
| **Security Analyst** | analyst1 | analyst123 |
| **Student** | student1 | student123 |

---

## 📖 User Guide

### For Admin/Lead:

1. **Simulate Attacks**
   - Go to 🎯 Attack Simulator
   - Click any attack scenario
   - Alert auto-generated

2. **Review Alerts**
   - Go to 🚨 Alerts
   - Mark as True/False Positive
   - Incident auto-created if True Positive

3. **Assign Incidents**
   - Go to 📝 Incidents
   - Assign to security analyst
   - Track response actions

4. **Generate Reports**
   - Go to 📄 Reports
   - Select date range
   - Generate with real data

### For Security Analysts:

1. View assigned incidents only
2. Take response actions (Block IP, Lock Account, Isolate Host)
3. Update incident status
4. Add resolution notes

---

## 🎯 Complete Workflow Demo
```
1. Admin simulates Brute Force Attack
   ↓
2. Alert #001 auto-created (Status: New)
   ↓
3. Analyst reviews alert → Marks True Positive
   ↓
4. Incident INC-0001 auto-created from alert
   ↓
5. Lead assigns incident to Analyst
   ↓
6. Analyst takes actions: Blocks IP, Locks account
   ↓
7. Analyst marks incident as Resolved
   ↓
8. Report shows complete correlation:
   - 1 Alert (True Positive)
   - 1 Incident (Resolved)
   - 2 Response Actions (Completed)
```

---

## 📁 Project Structure
```
edusiem/
├── main.py                    # Login & authentication
├── database/
│   ├── models.py             # Complete database schema
│   └── __init__.py
├── pages/
│   ├── 1_🏠_Dashboard.py      # Security overview
│   ├── 2_🚨_Alerts.py         # Alert management
│   ├── 3_📝_Incidents.py      # Incident response
│   ├── 4_🌐_Network_Logs.py   # Network monitoring
│   ├── 5_🔥_Firewall_Logs.py  # Firewall events
│   ├── 6_📄_Reports.py        # Report generation
│   ├── 7_🔍_Threat_Hunting.py # Proactive hunting
│   └── 8_🎯_Attack_Simulator.py # Attack simulation
└── data/
    └── edusiem.db            # SQLite database
```

---

## 🎓 For Project Submission

### What to Demonstrate:

1. **Attack Simulation** → Show how attacks trigger alerts
2. **Alert Workflow** → True/False positive decision
3. **Incident Creation** → Automatic from alerts
4. **Role-Based Access** → Different views for different roles
5. **Data Correlation** → Reports pull real interconnected data

### Key Points for Jury:

- ✅ All data is correlated (not fake/random)
- ✅ Simulates real SIEM workflows
- ✅ Role-based security implemented
- ✅ Production-ready architecture
- ✅ Cost-effective alternative to commercial SIEM

---

## 💡 Future Enhancements

- [ ] Integration with actual campus network
- [ ] Machine learning threat detection
- [ ] Email/SMS alerting
- [ ] Active Directory integration
- [ ] Multi-tenancy support
- [ ] Mobile app

---

## 👥 Team

- Prem Abnave
- Siya Ingle
- Siddharth Kamble

**Mentor:** Vidya A.

**Course:** MCA (Cloud Technology) - 4th Semester

---

## 📄 License

Educational use only - MCA Final Year Project

---

**Last Updated:** February 14, 2026  
**Version:** 1.0.0 - Complete Prototype