"""
EduSIEM - Log Search Engine
pages/10_🔎_Log_Search.py
Built to match exact database schema from database/models.py
"""

import streamlit as st
import sqlite3
import pandas as pd
import os
from datetime import datetime, timedelta

st.set_page_config(page_title="Log Search - EduSIEM", page_icon="🔎", layout="wide")

# ── Auth ──────────────────────────────────────
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.error("🔒 Please login first")
    st.stop()

DB_PATH = "data/edusiem.db"

def get_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def table_exists(name):
    conn = get_db()
    r = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    conn.close()
    return r is not None

def get_columns(table):
    if not table_exists(table):
        return []
    conn = get_db()
    cols = [c["name"] for c in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    conn.close()
    return cols

def row_count(table):
    if not table_exists(table):
        return 0
    try:
        conn = get_db()
        n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.close()
        return n
    except Exception:
        return 0

# ── Table configs matching models.py exactly ──
# alerts:       id, alert_type, title, message, severity, status, source, source_ip, target_ip, rule_name, created_at, evidence
# network_logs: id, source_ip, destination_ip, destination_port, protocol, bytes_sent, status, threat_level, timestamp
# firewall_logs:id, action, rule_name, source_ip, destination_ip, destination_port, protocol, threat_type, severity, timestamp
# incidents:    id, title, description, incident_type, severity, status, created_at, resolution_notes
# anomalies:    id, detected_at, source_ip, anomaly_type, severity, z_score, description, status
# simulated_attacks: id, attack_type, attack_name, description, source_ip, target_ip, simulated_at, status

TABLE_CONFIG = {
    "alerts": {
        "icon": "🚨", "label": "Alerts",
        "text_cols": ["title","message","source_ip","target_ip","alert_type","source","rule_name","status","evidence"],
        "ts_col":    "created_at",
        "sev_col":   "severity",
        "ip_col":    "source_ip",
    },
    "network_logs": {
        "icon": "🌐", "label": "Network Logs",
        "text_cols": ["source_ip","destination_ip","protocol","status","threat_level"],
        "ts_col":    "timestamp",
        "sev_col":   "threat_level",
        "ip_col":    "source_ip",
    },
    "firewall_logs": {
        "icon": "🔥", "label": "Firewall Logs",
        "text_cols": ["source_ip","destination_ip","action","rule_name","threat_type","protocol","severity"],
        "ts_col":    "timestamp",
        "sev_col":   "severity",
        "ip_col":    "source_ip",
    },
    "anomalies": {
        "icon": "🧠", "label": "Anomalies",
        "text_cols": ["source_ip","anomaly_type","description","status","severity"],
        "ts_col":    "detected_at",
        "sev_col":   "severity",
        "ip_col":    "source_ip",
    },
    "incidents": {
        "icon": "📝", "label": "Incidents",
        "text_cols": ["title","description","incident_type","status","resolution_notes"],
        "ts_col":    "created_at",
        "sev_col":   "severity",
        "ip_col":    None,
    },
    "simulated_attacks": {
        "icon": "🎯", "label": "Simulated Attacks",
        "text_cols": ["attack_type","attack_name","description","source_ip","target_ip","status"],
        "ts_col":    "simulated_at",
        "sev_col":   None,
        "ip_col":    "source_ip",
    },
}


def search_table(table, query, ip_filter, dt_from, dt_to, sev_filter, limit=200):
    if not table_exists(table):
        return pd.DataFrame()

    cfg         = TABLE_CONFIG.get(table, {})
    actual_cols = get_columns(table)
    text_cols   = [c for c in cfg.get("text_cols", []) if c in actual_cols]
    ts_col      = cfg.get("ts_col") if cfg.get("ts_col") in actual_cols else None
    sev_col     = cfg.get("sev_col") if cfg.get("sev_col") in actual_cols else None
    ip_col      = cfg.get("ip_col")

    conds, params = [], []

    # Free text — each word must match at least one text column
    if query.strip():
        for term in query.split():
            if term.strip() and text_cols:
                parts = " OR ".join([f"{c} LIKE ?" for c in text_cols])
                conds.append(f"({parts})")
                params.extend([f"%{term.strip()}%"] * len(text_cols))

    # IP filter — search source_ip and destination_ip
    if ip_filter.strip():
        ip_search_cols = []
        if ip_col and ip_col in actual_cols:
            ip_search_cols.append(ip_col)
        if "destination_ip" in actual_cols and "destination_ip" not in ip_search_cols:
            ip_search_cols.append("destination_ip")
        if "target_ip" in actual_cols:
            ip_search_cols.append("target_ip")
        if ip_search_cols:
            parts = " OR ".join([f"{c} LIKE ?" for c in ip_search_cols])
            conds.append(f"({parts})")
            params.extend([f"%{ip_filter.strip()}%"] * len(ip_search_cols))

    # Date range
    if ts_col:
        if dt_from:
            conds.append(f"{ts_col} >= ?")
            params.append(dt_from.isoformat())
        if dt_to:
            conds.append(f"{ts_col} <= ?")
            params.append(dt_to.isoformat())

    # Severity
    if sev_filter and sev_col:
        conds.append(f"{sev_col} IN ({','.join(['?']*len(sev_filter))})")
        params.extend(sev_filter)

    where = ("WHERE " + " AND ".join(conds)) if conds else ""
    order = f"ORDER BY {ts_col} DESC" if ts_col else ""
    sql   = f"SELECT * FROM {table} {where} {order} LIMIT {limit}"

    try:
        conn = get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            df["_source"] = cfg.get("label", table)
            return df
    except Exception as e:
        st.warning(f"Search error in {table}: {e}")
    return pd.DataFrame()


def reorder_cols(df):
    """Put the most useful columns first."""
    priority = ["id","source_ip","target_ip","severity","threat_level","status",
                "title","message","anomaly_type","attack_type","alert_type",
                "description","action","rule_name","threat_type","protocol",
                "destination_ip","destination_port","bytes_sent","z_score",
                "timestamp","created_at","detected_at","simulated_at"]
    ordered = [c for c in priority if c in df.columns]
    rest    = [c for c in df.columns if c not in ordered and c != "_source"]
    return df[ordered + rest]


# ── UI ────────────────────────────────────────

st.title("🔎 Unified Log Search")
st.caption("Search across all EduSIEM tables: Alerts · Network Logs · Firewall Logs · Anomalies · Incidents · Simulated Attacks")

# Search bar
query = st.text_input(
    "search",
    placeholder="🔍  Search anything: IP address, attack name, brute force, SQL injection, BLOCK ...",
    label_visibility="collapsed",
    key="search_q"
)

# Filters
with st.expander("🎛️ Filters", expanded=True):
    fc1, fc2, fc3, fc4 = st.columns([2, 2, 2, 2])
    with fc1:
        ip_filter = st.text_input("🌐 Filter by IP", placeholder="e.g. 192.168.1  or  203.0")
    with fc2:
        date_from = st.date_input("📅 From", value=datetime.now().date() - timedelta(days=7))
        dt_from   = datetime.combine(date_from, datetime.min.time())
    with fc3:
        date_to = st.date_input("📅 To", value=datetime.now().date())
        dt_to   = datetime.combine(date_to, datetime.max.time())
    with fc4:
        sev_opts   = ["critical","high","medium","low","normal","suspicious","blocked"]
        sev_filter = st.multiselect("Severity / Threat", sev_opts, default=["critical","high","medium","low"])

    available  = [t for t in TABLE_CONFIG if table_exists(t)]
    sel_tables = st.multiselect(
        "Search in tables",
        options=available,
        default=available,
        format_func=lambda t: f"{TABLE_CONFIG[t]['icon']} {TABLE_CONFIG[t]['label']}"
    )
    limit = st.slider("Max results per table", 50, 500, 200, 50)

# Buttons
b1, b2 = st.columns([1, 5])
with b1:
    do_search = st.button("🔍 Search", type="primary", use_container_width=True)
with b2:
    if st.button("✖ Reset"):
        st.rerun()

st.divider()

# ── Results ───────────────────────────────────

if do_search or query.strip() or ip_filter.strip():
    results, counts = [], {}

    with st.spinner("Searching all tables..."):
        for tbl in (sel_tables or available):
            df = search_table(tbl, query, ip_filter, dt_from, dt_to, sev_filter, limit)
            if not df.empty:
                results.append((tbl, df))
                counts[tbl] = len(df)

    total = sum(counts.values())

    if total:
        st.success(f"**{total} results** across **{len(counts)} table(s)**")

        # Badge row
        bcols = st.columns(len(counts))
        for col, (tbl, cnt) in zip(bcols, counts.items()):
            cfg = TABLE_CONFIG.get(tbl, {})
            col.metric(f"{cfg.get('icon','')} {cfg.get('label',tbl)}", cnt)

        st.divider()

        # Tabs
        tab_labels = [f"{TABLE_CONFIG[t]['icon']} {TABLE_CONFIG[t]['label']} ({c})" for t, c in counts.items()]
        tab_labels.append("📋 All Combined")
        tabs = st.tabs(tab_labels)

        all_dfs = []
        for tab_ui, (tbl, df) in zip(tabs[:-1], results):
            with tab_ui:
                display = df.drop(columns=["_source"], errors="ignore")
                display = reorder_cols(display)
                st.dataframe(display, use_container_width=True, height=400)
                st.download_button(
                    f"⬇️ Export {TABLE_CONFIG[tbl]['label']} CSV",
                    data=display.to_csv(index=False),
                    file_name=f"edusiem_{tbl}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key=f"dl_{tbl}"
                )
            all_dfs.append(display)

        with tabs[-1]:
            combined = pd.concat(all_dfs, ignore_index=True)
            st.dataframe(combined, use_container_width=True, height=500)
            st.download_button(
                "⬇️ Export All as CSV",
                data=combined.to_csv(index=False),
                file_name=f"edusiem_search_all_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key="dl_all"
            )
    else:
        st.warning("No results found.")
        st.markdown("""
**Tips:**
- Use partial IP: `192.168` matches all internal IPs
- Attack Simulator must be run first to generate log data
- Try widening the date range
- Remove severity filters to see all records
        """)

else:
    # Landing — database overview
    st.markdown("### 📊 Database Overview")
    db_cols = st.columns(len(TABLE_CONFIG))
    for col, (tbl, cfg) in zip(db_cols, TABLE_CONFIG.items()):
        n = row_count(tbl)
        col.metric(f"{cfg['icon']} {cfg['label']}", f"{n:,}" if n else "Empty")

    st.divider()
    st.markdown("### ⚡ Quick Searches")

    quick = [
        ("🔐 Brute Force",    "brute force"),
        ("💉 SQL Injection",   "sql_injection"),
        ("🌊 DDoS",           "ddos"),
        ("🔍 Port Scan",       "port_scan"),
        ("📤 Exfiltration",    "data_exfiltration"),
        ("🦠 Malware",         "malware"),
        ("🚫 Blocked",         "block"),
        ("🚨 Critical",        "critical"),
    ]
    rows = [quick[i:i+4] for i in range(0, len(quick), 4)]
    for row in rows:
        cols = st.columns(4)
        for col, (label, term) in zip(cols, row):
            if col.button(label, use_container_width=True, key=f"qs_{term}"):
                st.session_state["search_q"] = term
                st.rerun()

    st.divider()
    st.markdown("""
**Search tips:**
- **IP address**: `192.168.1.5` or partial `192.168`
- **Attack types**: `brute_force`, `sql_injection`, `ddos`, `port_scan`, `malware`, `phishing`
- **Status**: `new`, `open`, `suspicious`, `blocked`
- **Severity**: `critical`, `high`, `medium`, `low`
- **MITRE**: `T1110`, `T1190`, `T1498`
- All columns in all tables are searched simultaneously
    """)