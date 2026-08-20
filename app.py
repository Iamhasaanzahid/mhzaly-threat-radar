import streamlit as st
import pandas as pd
import numpy as np

# Page configuration
st.set_page_config(page_title="MHZALY Threat Radar", layout="wide", page_icon="🛡️")

# Custom Dark Cyberpunk CSS
st.markdown("""
    <style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 18px 24px;
    }
    .metric-title {
        font-size: 0.75rem;
        font-weight: 600;
        color: #8b949e;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }
    .metric-number {
        font-size: 2rem;
        font-weight: 700;
        color: #58a6ff;
        margin: 4px 0;
    }
    .metric-subtext {
        font-size: 0.8rem;
        color: #7ee787;
    }
    .badge-unlocked {
        background-color: #1f6feb22;
        color: #58a6ff;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.8rem;
    }
    </style>
""", unsafe_allow_html=True)

# Session state initialization for Credits & Unlocked rows
if "points" not in st.session_state:
    st.session_state.points = 150

if "unlocked_ids" not in st.session_state:
    st.session_state.unlocked_ids = {1, 2, 3, 4, 5}

# Sample Dataset Engine
RAW_BREACH_DB = [
    {"id": 1, "domain": "umt.edu.pk", "user": "f2018134093@umt.edu.pk", "pwd": "ProShoaibillah2", "url": "http://onlineadmissions.umt.edu.pk/login", "category": "Customers", "added": "2026-08-16", "risk": 18, "len": 15},
    {"id": 2, "domain": "umt.edu.pk", "user": "f2019105057@umt.edu.pk", "pwd": "MalikA_A986", "url": "http://upwork.com", "category": "third_parties", "added": "2026-08-16", "risk": 10, "len": 10},
    {"id": 3, "domain": "umt.edu.pk", "user": "f2019105057@umt.edu.pk", "pwd": "Aimenh00", "url": "http://online.umt.edu.pk/account/resetpassword", "category": "Employees", "added": "2026-08-16", "risk": 5, "len": 8},
    {"id": 4, "domain": "umt.edu.pk", "user": "f2019088054@umt.edu.pk", "pwd": "Farazq07", "url": "http://online.umt.edu.pk/account/resetpassword", "category": "Employees", "added": "2026-08-16", "risk": 18, "len": 8},
    {"id": 5, "domain": "umt.edu.pk", "user": "afreen.abbas930@gmail.com", "pwd": "827460", "url": "http://onlineadmissions.umt.edu.pk/login", "category": "Customers", "added": "2026-08-16", "risk": 2, "len": 6},
    {"id": 6, "domain": "umt.edu.pk", "user": "f2018266059@umt.edu.pk", "pwd": "K2Y5jRFN", "url": "http://lms.umt.edu.pk/moodle/login/index.php", "category": "Customers", "added": "2026-08-16", "risk": 9, "len": 8},
    {"id": 7, "domain": "umt.edu.pk", "user": "user22@umt.edu.pk", "pwd": "SecP@ss2026!", "url": "http://socialbakers.com", "category": "third_parties", "added": "2026-08-16", "risk": 10, "len": 12},
    {"id": 8, "domain": "umt.edu.pk", "user": "researcher@umt.edu.pk", "pwd": "Research!99", "url": "http://researchgate.net", "category": "third_parties", "added": "2026-08-16", "risk": 6, "len": 11},
    {"id": 9, "domain": "umt.edu.pk", "user": "admin_sys@umt.edu.pk", "pwd": "AdminRoot#2026", "url": "http://online.umt.edu.pk/cpanel", "category": "Employees", "added": "2026-08-16", "risk": 25, "len": 14},
    {"id": 10, "domain": "umt.edu.pk", "user": "support@umt.edu.pk", "pwd": "Helpdesk#123", "url": "http://online.umt.edu.pk/portal/login", "category": "Employees", "added": "2026-08-16", "risk": 14, "len": 12},
]

# Header Bar
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ SoloRadar — THREAT INTEL TOOL")
with col_h2:
    st.markdown(f"<div style='text-align:right; margin-top:20px;'><span class='badge-unlocked'>⚡ Daily Burn: <b>{st.session_state.points} points</b></span></div>", unsafe_allow_html=True)

# Top Filter Radio Options
search_mode = st.radio(
    "Search Mode Selector",
    ["Email / Username", "Domain", "Dark Web", "Password Range"],
    horizontal=True,
    label_visibility="collapsed"
)

# Search Input and Secondary Filters
c_in1, c_in2 = st.columns([3, 2])
with c_in1:
    query = st.text_input("Search query", value="umt.edu.pk", placeholder="Search across domains, subdomains, and related assets...")

with c_in2:
    url_filter = st.text_input("URL / Subdomain Filter", placeholder="e.g. login, resetpassword, upwork")

# Advanced Options
c_opt1, c_opt2 = st.columns([1, 4])
with c_opt1:
    raw_json_toggle = st.checkbox("Raw aggregate JSON")
with c_opt2:
    if search_mode == "Password Range":
        pwd_range = st.slider("Password Length Filter", min_value=4, max_value=20, value=(6, 16))
    else:
        pwd_range = (0, 100)

st.markdown("---")

# Query Logic
results = [
    r for r in RAW_BREACH_DB 
    if (query.lower() in r["domain"].lower() or query.lower() in r["user"].lower())
    and (not url_filter or url_filter.lower() in r["url"].lower())
    and (pwd_range[0] <= r["len"] <= pwd_range[1])
]

# Calculation Metrics
emp_count = sum(1 for r in results if r["category"] == "Employees")
cust_count = sum(1 for r in results if r["category"] == "Customers")
third_count = sum(1 for r in results if r["category"] == "third_parties")

# Dashboard Analytics Cards
col_m1, col_m2, col_m3 = st.columns([1.2, 1.2, 1])

with col_m1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">👥 EMPLOYEES</div>
        <div class="metric-number">{emp_count * 831:,}</div>
        <div class="metric-subtext">97% strong · 3% weak</div>
    </div>
    """, unsafe_allow_html=True)

with col_m2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">👤 CUSTOMERS</div>
        <div class="metric-number">{cust_count * 18169:,}</div>
        <div class="metric-subtext">78% strong · 22% weak</div>
    </div>
    """, unsafe_allow_html=True)

with col_m3:
    st.markdown("""<div class="metric-card"><div class="metric-title">📈 BREACH TIMELINE</div>""", unsafe_allow_html=True)
    # Sparkline chart simulation
    chart_data = pd.DataFrame({"Incidents": np.random.randint(10, 80, size=15)})
    st.line_chart(chart_data, height=75)
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Raw JSON display if checked
if raw_json_toggle:
    st.json(results)

# Category Tabs
tab_all, tab_emp, tab_cust, tab_third = st.tabs(["All", "Employees", "Customers", "third_parties"])

def render_interactive_table(category_name):
    if category_name == "All":
        filtered = results
    else:
        filtered = [r for r in results if r["category"] == category_name]

    if not filtered:
        st.info("No matching intelligence records found.")
        return

    # Table Header
    cols = st.columns([3, 2.5, 4, 1.5, 1.5, 1.5])
    cols[0].write("**Username / Email**")
    cols[1].write("**Password**")
    cols[2].write("**Target URL**")
    cols[3].write("**Category**")
    cols[4].write("**Added**")
    cols[5].write("**Action**")
    st.divider()

    for item in filtered:
        row = st.columns([3, 2.5, 4, 1.5, 1.5, 1.5])
        row[0].code(item["user"])

        # Masking / Unlocking Logic
        is_unlocked = item["id"] in st.session_state.unlocked_ids
        if is_unlocked:
            row[1].markdown(f"🔓 `{item['pwd']}`")
        else:
            row[1].markdown("🔒 `••••••••`")

        row[2].caption(item["url"])
        row[3].write(item["category"])
        row[4].write(item["added"])

        if is_unlocked:
            row[5].markdown("<span style='color:#7ee787;'>Unlocked</span>", unsafe_allow_html=True)
        else:
            if row[5].button("Unlock", key=f"btn_{item['id']}"):
                if st.session_state.points > 0:
                    st.session_state.points -= 1
                    st.session_state.unlocked_ids.add(item["id"])
                    st.rerun()
                else:
                    st.error("Insufficient points!")

with tab_all:
    render_interactive_table("All")
with tab_emp:
    render_interactive_table("Employees")
with tab_cust:
    render_interactive_table("Customers")
with tab_third:
    render_interactive_table("third_parties")
