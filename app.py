import streamlit as st
import pandas as pd
import requests
import dns.resolver

# 1. Page Configuration
st.set_page_config(page_title="MHZALY Threat Radar", layout="wide", page_icon="🛡️")

# 2. Dark Cyberpunk Styling
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

# 3. Session State for Custom Ingestion & Unlocks
if "custom_db" not in st.session_state:
    st.session_state.custom_db = []

if "points" not in st.session_state:
    st.session_state.points = 150

if "unlocked_keys" not in st.session_state:
    st.session_state.unlocked_keys = set()

# 4. Sidebar: Custom Data Uploader
with st.sidebar:
    st.subheader("📂 Ingest Local Breach Dumps")
    st.caption("Upload raw CSV or Text breach logs (Columns: user, password, url, category)")
    uploaded_file = st.file_uploader("Upload Dump File", type=["csv", "txt"])
    
    if uploaded_file is not None:
        try:
            df_upload = pd.read_csv(uploaded_file)
            st.session_state.custom_db = df_upload.to_dict(orient="records")
            st.success(f"Loaded {len(st.session_state.custom_db)} real records into local index.")
        except Exception as e:
            st.error(f"Error parsing file: {e}")

# 5. Header Section
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🛡️ MHZALY Threat Radar — THREAT INTEL TOOL")
with col_h2:
    st.markdown(f"<div style='text-align:right; margin-top:20px;'><span class='badge-points'>⚡ Daily Burn: <b>{st.session_state.points} points</b></span></div>", unsafe_allow_html=True)

# 6. Search Filters
search_mode = st.radio(
    "Search Mode Selector",
    ["Email Intelligence", "Domain Surface Recon", "Local Breach Logs Search"],
    horizontal=True
)

c_in1, c_in2 = st.columns([3, 2])
with c_in1:
    query = st.text_input("Target Query", value="", placeholder="Enter target (e.g. test@gmail.com, google.com, admin@target.com)...")

with c_in2:
    url_filter = st.text_input("URL / Keyword Filter", placeholder="Filter by domain or service keyword")

st.markdown("---")

# 7. Real Live API Functions
def query_real_email_breaches(email_str):
    email_clean = email_str.strip().lower()
    url = f"https://api.xposedornot.com/v1/check-email/{email_clean}"
    try:
        res = requests.get(url, timeout=7)
        if res.status_code == 200:
            data = res.json()
            breaches = data.get("breaches", [])
            return True, breaches
        elif res.status_code == 404:
            return False, []
        else:
            return None, []
    except Exception:
        return None, []

def resolve_domain_assets(domain_str):
    domain_clean = domain_str.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    records = []
    for r_type in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain_clean, r_type)
            for r in answers:
                records.append({
                    "Asset Domain": domain_clean,
                    "Record Type": r_type,
                    "Resolved Target / IP": str(r),
                    "Scope": "Public Surface"
                })
        except Exception:
            pass
    return domain_clean, records

# 8. Execution Logic
if query:
    if search_mode == "Email Intelligence":
        with st.spinner("Checking worldwide live breach databases..."):
            found, incidents = query_real_email_breaches(query)
            
            total_incidents = len(incidents) if found else 0
            
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f'<div class="metric-card"><div class="metric-title">TARGET</div><div class="metric-number" style="font-size:1.3rem;">{query}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="metric-card"><div class="metric-title">REAL BREACHES FOUND</div><div class="metric-number" style="color:{"#ef4444" if total_incidents > 0 else "#4ade80"};">{total_incidents}</div></div>', unsafe_allow_html=True)
            with c3:
                risk_lvl = "CRITICAL" if total_incidents > 0 else "CLEAN"
                st.markdown(f'<div class="metric-card"><div class="metric-title">RISK PROFILE</div><div class="metric-number" style="color:{"#ef4444" if total_incidents > 0 else "#4ade80"};">{risk_lvl}</div></div>', unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            
            if found and incidents:
                st.subheader("🚨 Disclosed Real Breach Incidents")
                breach_rows = []
                for b in incidents:
                    breach_rows.append({
                        "Identity Exposed": query,
                        "Breach Database / Dump Source": b,
                        "Exposure Status": "Exposed",
                        "Source Type": "Public Data Breach Feed"
                    })
                st.dataframe(pd.DataFrame(breach_rows), use_container_width=True, hide_index=True)
            elif not found:
                st.success(f"✅ No exposed breach records found for **{query}** across open intelligence sources.")
            else:
                st.warning("Intelligence lookup timed out or rate limited. Please retry.")

    elif search_mode == "Domain Surface Recon":
        with st.spinner("Resolving domain infrastructure..."):
            d_clean, assets = resolve_domain_assets(query)
            
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f'<div class="metric-card"><div class="metric-title">ACTIVE DOMAIN</div><div class="metric-number" style="font-size:1.4rem;">{d_clean}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="metric-card"><div class="metric-title">LIVE ASSETS RESOLVED</div><div class="metric-number">{len(assets)}</div></div>', unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.subheader("🌐 Discovered Live Infrastructure")
            if assets:
                st.dataframe(pd.DataFrame(assets), use_container_width=True, hide_index=True)
            else:
                st.warning("No records resolved for this domain name.")

    elif search_mode == "Local Breach Logs Search":
        if not st.session_state.custom_db:
            st.info("💡 Use the left sidebar to upload your real `.csv` or `.txt` breach log file.")
        else:
            q_clean = query.strip().lower()
            matched = [
                r for r in st.session_state.custom_db
                if any(q_clean in str(v).lower() for v in r.values())
                and (not url_filter or url_filter.lower() in str(r.get("url", "")).lower())
            ]
            
            st.subheader(f"📋 Matched Records from Uploaded Dataset ({len(matched)})")
            if matched:
                st.dataframe(pd.DataFrame(matched), use_container_width=True, hide_index=True)
            else:
                st.warning("No matching logs found in uploaded database.")
else:
    st.info("👆 Enter any worldwide email (e.g. `test@gmail.com`, `admin@adobe.com`) or domain name above to inspect.")
