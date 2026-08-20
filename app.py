import streamlit as st
import pandas as pd
import numpy as np
import hashlib
import re

# 1. Page Configuration
st.set_page_config(page_title="MHZALY Threat Radar", layout="wide", page_icon="🛡️")

# 2. Dark Cyberpunk UI Styling
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

# 3. State Management
if "points" not in st.session_state:
    st.session_state.points = 150

if "unlocked_keys" not in st.session_state:
    st.session_state.unlocked_keys = set()

# 4. Header
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ MHZALY Threat Radar — THREAT INTEL TOOL")
with col_h2:
    st.markdown(f"<div style='text-align:right; margin-top:20px;'><span class='badge-points'>⚡ Daily Burn: <b>{st.session_state.points} points</b></span></div>", unsafe_allow_html=True)

# 5. Search Filters
search_mode = st.radio(
    "Search Mode Selector",
    ["Domain", "Email / Username", "Dark Web", "Password Range"],
    horizontal=True
)

c_in1, c_in2 = st.columns([3, 2])
with c_in1:
    query = st.text_input("Target Query", value="", placeholder="Enter target (e.g. google.com, oxford.ac.uk, admin@domain.com)...")

with c_in2:
    url_filter = st.text_input("URL / Path Filter", placeholder="e.g. login, portal, cpanel")

c_opt1, c_opt2 = st.columns([1, 4])
with c_opt1:
    raw_json_toggle = st.checkbox("Raw aggregate JSON")
with c_opt2:
    if search_mode == "Password Range":
        pwd_range = st.slider("Password Length Filter", min_value=4, max_value=24, value=(4, 24))
    else:
        pwd_range = (0, 100)

st.markdown("---")

# 6. Target Validity Check
def is_valid_target(target):
    target = target.strip()
    if not target or len(target) < 4:
        return False
    # Check if user just entered dots or symbols
    if re.fullmatch(r"[\.\-_/]+", target):
        return False
    # Must have a valid dot for domain or @ for email
    if "." not in target and "@" not in target:
        return False
    return True

# 7. Intelligence Generator
def generate_threat_data(target_input):
    target = target_input.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    
    if not is_valid_target(target):
        return target, [], 0, 0

    if "@" in target:
        domain = target.split("@")[-1]
    else:
        domain = target

    # Consistent seed
    seed = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
    np.random.seed(seed)

    records = [
        # Employees
        {"user": f"admin@{domain}", "pwd": "AdminRoot#2026", "url": f"https://online.{domain}/cpanel", "category": "Employees", "len": 14},
        {"user": f"director_it@{domain}", "pwd": "CloudInfra#2026", "url": f"https://mail.{domain}/owa", "category": "Employees", "len": 15},
        {"user": f"support@{domain}", "pwd": "Helpdesk#123", "url": f"https://portal.{domain}/account/resetpassword", "category": "Employees", "len": 12},
        {"user": f"lead_sec@{domain}", "pwd": "CyberSecure99", "url": f"https://vpn.{domain}/auth", "category": "Employees", "len": 13},
        {"user": f"hr_portal@{domain}", "pwd": "HrAccess!987", "url": f"https://hr.{domain}/login", "category": "Employees", "len": 12},
        
        # Customers
        {"user": f"customer_user1@{domain}", "pwd": "ProShoaibillah2", "url": f"http://onlineadmissions.{domain}/login", "category": "Customers", "len": 15},
        {"user": f"client_portal@{domain}", "pwd": "Farazq07", "url": f"https://online.{domain}/account/resetpassword", "category": "Customers", "len": 8},
        {"user": f"student_access@{domain}", "pwd": "Aimenh00", "url": f"https://online.{domain}/account/resetpassword", "category": "Customers", "len": 8},
        {"user": f"billing_user@{domain}", "pwd": "827460", "url": f"http://onlineadmissions.{domain}/login", "category": "Customers", "len": 6},
        {"user": f"lms_member@{domain}", "pwd": "K2Y5jRFN", "url": f"https://lms.{domain}/moodle/login/index.php", "category": "Customers", "len": 8},
        
        # Third Parties
        {"user": f"freelancer@{domain}", "pwd": "MalikA_A986", "url": "http://upwork.com", "category": "third_parties", "len": 10},
        {"user": f"researcher@{domain}", "pwd": "Research!99", "url": "http://researchgate.net", "category": "third_parties", "len": 11},
        {"user": f"marketing@{domain}", "pwd": "SecP@ss2026!", "url": "http://socialbakers.com", "category": "third_parties", "len": 12},
        {"user": f"elearning@{domain}", "pwd": "OnlinePass#11", "url": f"https://coursera.org/programs/{domain.split('.')[0]}", "category": "third_parties", "len": 13},
    ]

    for idx, r in enumerate(records):
        r["key"] = f"{domain}_{idx+1}"
        r["added"] = "2026-08-16"

    emp_metric = sum(1 for r in records if r["category"] == "Employees") * int(np.random.randint(400, 800))
    cust_metric = sum(1 for r in records if r["category"] == "Customers") * int(np.random.randint(5000, 15000))

    return domain, records, emp_metric, cust_metric

# 8. Render Logic
if query:
    target_domain, all_records, emp_total, cust_total = generate_threat_data(query)

    # Filter records
    filtered = [
        r for r in all_records
        if (not url_filter or url_filter.strip().lower() in r["url"].lower() or url_filter.strip().lower() in r["user"].lower())
        and (pwd_range[0] <= r["len"] <= pwd_range[1])
    ]

    # اگر کوئی ریکارڈ نہیں ملتا یا غلط ڈومین ہے تو میٹرکس 0 ہو جائیں گے
    if len(filtered) == 0:
        emp_display = 0
        cust_display = 0
        timeline_values = [0] * 12
    else:
        emp_display = emp_total
        cust_display = cust_total
        timeline_values = [15, 22, 30, 28, 45, 55, 60, 48, 72, 85, 90, 110]

    # Metrics Row
    col_m1, col_m2, col_m3 = st.columns([1.2, 1.2, 1])
    with col_m1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">👥 EMPLOYEES</div>
            <div class="metric-number">{emp_display:,}</div>
            <div class="metric-subtext">{"97% strong · 3% weak" if emp_display > 0 else "0% compromise"}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">👤 CUSTOMERS</div>
            <div class="metric-number">{cust_display:,}</div>
            <div class="metric-subtext">{"78% strong · 22% weak" if cust_display > 0 else "0% compromise"}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m3:
        st.markdown("""<div class="metric-card"><div class="metric-title">📈 BREACH TIMELINE</div>""", unsafe_allow_html=True)
        timeline_data = pd.DataFrame({"Incidents": timeline_values})
        st.line_chart(timeline_data, height=75)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if raw_json_toggle:
        st.json(filtered)

    # Tabs Display
    tab_all, tab_emp, tab_cust, tab_third = st.tabs(["All", "Employees", "Customers", "third_parties"])

    def render_tab_table(cat_filter):
        if cat_filter == "All":
            dataset = filtered
        else:
            dataset = [r for r in filtered if r["category"].lower() == cat_filter.lower()]

        if not dataset:
            st.info("No matching records found for this target/category.")
            return

        cols = st.columns([3.5, 2.5, 4, 2, 1.5, 1.5])
        cols[0].write("**Username / Email**")
        cols[1].write("**Password**")
        cols[2].write("**Target URL**")
        cols[3].write("**Category**")
        cols[4].write("**Added**")
        cols[5].write("**Action**")
        st.divider()

        for idx, item in enumerate(dataset):
            row = st.columns([3.5, 2.5, 4, 2, 1.5, 1.5])
            row[0].code(item["user"])

            is_unlocked = (idx < 3 and cat_filter == "All") or (item["key"] in st.session_state.unlocked_keys)

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
                btn_id = f"btn_{cat_filter}_{item['key']}_{idx}"
                if row[5].button("Unlock", key=btn_id):
                    if st.session_state.points > 0:
                        st.session_state.points -= 1
                        st.session_state.unlocked_keys.add(item["key"])
                        st.rerun()
                    else:
                        st.error("Out of points!")

    with tab_all:
        render_tab_table("All")
    with tab_emp:
        render_tab_table("Employees")
    with tab_cust:
        render_tab_table("Customers")
    with tab_third:
        render_tab_table("third_parties")

else:
    st.info("👆 Enter any valid worldwide domain (e.g. `google.com`, `shopify.com`, `apple.com`) or email to inspect.")
