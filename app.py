import streamlit as st
import streamlit as st
import pandas as pd
import numpy as np
import hashlib
import dns.resolver

# 1. Page Configuration
st.set_page_config(page_title="MHZALY Threat Radar", layout="wide", page_icon="🛡️")

# 2. Dark Cyberpunk Styling (Video Matched)
st.markdown("""
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #c9d1d9;
    }
    .metric-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 16px 20px;
    }
    .metric-title {
        font-size: 0.75rem;
        font-weight: 600;
        color: #9ca3af;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }
    .metric-number {
        font-size: 1.9rem;
        font-weight: 700;
        color: #38bdf8;
        margin: 3px 0;
    }
    .metric-subtext {
        font-size: 0.8rem;
        color: #4ade80;
    }
    .badge-points {
        background-color: #1e293b;
        color: #38bdf8;
        border: 1px solid #334155;
        padding: 4px 10px;
        border-radius: 8px;
        font-size: 0.85rem;
    }
    </style>
""", unsafe_allow_html=True)

# 3. Session State (Daily Points & Unlocked Items)
if "points" not in st.session_state:
    st.session_state.points = 150

if "unlocked_keys" not in st.session_state:
    st.session_state.unlocked_keys = set()

# 4. Header Bar
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ MHZALY Threat Radar — THREAT INTEL TOOL")
with col_h2:
    st.markdown(f"<div style='text-align:right; margin-top:20px;'><span class='badge-points'>⚡ Daily Burn: <b>{st.session_state.points} points</b></span></div>", unsafe_allow_html=True)

# 5. Top Filter Mode
search_mode = st.radio(
    "Search Mode Selector",
    ["Domain", "Email / Username", "Dark Web", "Password Range"],
    horizontal=True
)

# 6. Inputs
c_in1, c_in2 = st.columns([3, 2])
with c_in1:
    placeholder_val = "Enter any domain worldwide (e.g. google.com, oxford.ac.uk, bbc.com)" if search_mode in ["Domain", "Password Range"] else "Enter email / username (e.g. admin@target.com)"
    default_val = "umt.edu.pk" if search_mode in ["Domain", "Password Range"] else "admin@umt.edu.pk"
    query = st.text_input("Target Query", value=default_val, placeholder=placeholder_val)

with c_in2:
    url_filter = st.text_input("URL / Path Filter", placeholder="e.g. login, resetpassword, portal")

c_opt1, c_opt2 = st.columns([1, 4])
with c_opt1:
    raw_json_toggle = st.checkbox("Raw aggregate JSON")
with c_opt2:
    if search_mode == "Password Range":
        pwd_range = st.slider("Password Length Filter", min_value=4, max_value=24, value=(6, 18))
    else:
        pwd_range = (0, 100)

st.markdown("---")

# 7. Worldwide Dynamic Intelligence Synthesizer
def generate_worldwide_intelligence(target_input, mode):
    target = target_input.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not target:
        return "", [], 0, 0, 0
    
    if "@" in target:
        domain = target.split("@")[-1]
        user_prefix = target.split("@")[0]
    else:
        domain = target
        user_prefix = "user"

    # Base seed from string to keep consistency for same domain/email
    seed_val = int(hashlib.md5(target.encode()).hexdigest()[:8], 16)
    np.random.seed(seed_val)

    # Dynamic synthetic record generation for ANY domain worldwide
    sample_endpoints = [
        f"http://onlineadmissions.{domain}/login",
        f"https://portal.{domain}/account/resetpassword",
        f"https://lms.{domain}/moodle/login/index.php",
        f"http://upwork.com",
        f"https://coursera.org/programs/{domain.split('.')[0]}",
        f"http://socialbakers.com",
        f"http://researchgate.net",
        f"https://vpn.{domain}/dana-na/auth/url_default/welcome.cgi",
        f"https://cpanel.{domain}:2083",
        f"https://mail.{domain}/owa"
    ]

    sample_usernames = [
        f"admin@{domain}",
        f"f2018134093@{domain}",
        f"f2019105057@{domain}",
        f"f2019088054@{domain}",
        f"f2018266059@{domain}",
        f"user_sec@{domain}",
        f"researcher@{domain}",
        f"support@{domain}",
        f"director_it@{domain}",
        f"info@{domain}",
        f"test.account@{domain}",
        f"lead_developer@{domain}"
    ]

    sample_passwords = [
        "ProShoaibillah2", "MalikA_A986", "Aimenh00", "Farazq07", "827460",
        "K2Y5jRFN", "SecP@ss2026!", "Research!99", "AdminRoot#2026", "Helpdesk#123",
        "CyberSecure99", "CloudInfra#2026", "OracleDb@Pass", "Passcode9901"
    ]

    categories = ["Employees", "Customers", "third_parties"]
    records = []
    
    num_records = 15
    for idx in range(num_records):
        cat = categories[idx % len(categories)]
        u_name = sample_usernames[idx % len(sample_usernames)]
        pwd = sample_passwords[idx % len(sample_passwords)]
        url = sample_endpoints[idx % len(sample_endpoints)]
        risk = int(np.random.randint(2, 28))
        
        rec_id = f"{domain}_{idx+1}"
        records.append({
            "key": rec_id,
            "domain": domain,
            "user": u_name,
            "pwd": pwd,
            "url": url,
            "category": cat,
            "added": "2026-08-16",
            "risk": risk,
            "len": len(pwd)
        })

    emp_metric = int(np.random.randint(1200, 4500))
    cust_metric = int(np.random.randint(25000, 85000))
    third_metric = int(np.random.randint(300, 1500))

    return domain, records, emp_metric, cust_metric, third_metric

# 8. Query Execution
if query:
    target_domain, all_records, emp_total, cust_total, third_total = generate_worldwide_intelligence(query, search_mode)
    
    # Filter records based on UI inputs
    filtered_results = [
        r for r in all_records
        if (not url_filter or url_filter.lower() in r["url"].lower())
        and (pwd_range[0] <= r["len"] <= pwd_range[1])
    ]

    # Metrics Analytics Row
    col_m1, col_m2, col_m3 = st.columns([1.2, 1.2, 1])

    with col_m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">👥 EMPLOYEES</div>
            <div class="metric-number">{emp_total:,}</div>
            <div class="metric-subtext">97% strong · 3% weak</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">👤 CUSTOMERS</div>
            <div class="metric-number">{cust_total:,}</div>
            <div class="metric-subtext">78% strong · 22% weak</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m3:
        st.markdown("""<div class="metric-card"><div class="metric-title">📈 BREACH TIMELINE</div>""", unsafe_allow_html=True)
        timeline_data = pd.DataFrame({"Incidents": [12, 18, 25, 30, 22, 45, 60, 52, 70, 65, 80, 95]})
        st.line_chart(timeline_data, height=75)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if raw_json_toggle:
        st.json(filtered_results)

    # Category Tabs
    tab_all, tab_emp, tab_cust, tab_third = st.tabs(["All", "Employees", "Customers", "third_parties"])

    def render_threat_table(category_name):
        if category_name == "All":
            dataset = filtered_results
        else:
            dataset = [r for r in filtered_results if r["category"] == category_name]

        if not dataset:
            st.info("No matching records found for this category.")
            return

        # Table Header Layout
        cols = st.columns([3, 2.5, 4, 1.5, 1.5, 1.5])
        cols[0].write("**Username / Email**")
        cols[1].write("**Password**")
        cols[2].write("**Target URL**")
        cols[3].write("**Category**")
        cols[4].write("**Added**")
        cols[5].write("**Action**")
        st.divider()

        for idx, item in enumerate(dataset):
            row = st.columns([3, 2.5, 4, 1.5, 1.5, 1.5])
            row[0].code(item["user"])

            # Unlocked State logic (first 4 unlocked by default)
            is_unlocked = (idx < 4) or (item["key"] in st.session_state.unlocked_keys)
            
            if is_unlocked:
                row[1].markdown(f"🔓 `{item['pwd']}`")
            else:
                row[1].markdown("🔒 `••••••••`")

            row[2].caption(item["url"])
            row[3].write(item["category"])
            row[4].write(item["added"])

            if is_unlocked:
                row[5].markdown("<span style='color:#4ade80;'>Unlocked</span>", unsafe_allow_html=True)
            else:
                if row[5].button("Unlock", key=f"btn_{item['key']}"):
                    if st.session_state.points > 0:
                        st.session_state.points -= 1
                        st.session_state.unlocked_keys.add(item["key"])
                        st.rerun()
                    else:
                        st.error("Out of points!")

    with tab_all:
        render_threat_table("All")
    with tab_emp:
        render_threat_table("Employees")
    with tab_cust:
        render_threat_table("Customers")
    with tab_third:
        render_threat_table("third_parties")

else:
    st.info("👆 Enter any domain worldwide (e.g. `google.com`, `shopify.com`, `umt.edu.pk`) to inspect.")
