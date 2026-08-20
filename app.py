import streamlit as st
import pandas as pd
import requests
import dns.resolver

st.set_page_config(page_title="MHZALY Threat Radar", layout="wide", page_icon="🛡️")

# Dark Mode UI
st.markdown("""
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #f3f4f6;
    }
    .metric-card {
        background-color: #111827;
        border: 1px solid #1f2937;
        padding: 16px;
        border-radius: 10px;
    }
    .metric-val {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-lbl {
        font-size: 0.8rem;
        color: #9ca3af;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ MHZALY Threat Radar — Global Threat & Breach Intelligence Engine")
st.caption("Investigate world-wide domains, exposed services, live email breach history, and threat signals.")

# Search Controls
col_type, col_query = st.columns([1, 3])
with col_type:
    search_type = st.radio("Search Mode", ["Email Breach Check", "Domain Recon"], horizontal=True)

with col_query:
    placeholder_text = "Enter any email (e.g. test@gmail.com, ceo@company.com)" if search_type == "Email Breach Check" else "Enter domain (e.g. google.com, umt.edu.pk, bbc.com)"
    query = st.text_input("Enter Search Target", placeholder=placeholder_text)

st.markdown("---")

# 1. Worldwide Real-Time Email Breach Checker (XposedOrNot Free Live API)
def check_live_email_breaches(email_str):
    email_clean = email_str.strip().lower()
    url = f"https://api.xposedornot.com/v1/check-email/{email_clean}"
    
    try:
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            breaches_list = data.get("breaches", [])
            # Format results
            results = []
            for b in breaches_list:
                results.append({
                    "Target Identity": email_clean,
                    "Breach Source / Incident": b,
                    "Exposed Data Type": "Credentials / Personal Identifiers",
                    "Status": "⚠️ Breached / Exposed",
                    "Severity": "High"
                })
            return True, results
        elif response.status_code == 404:
            return False, []
        else:
            return None, f"API Response Code: {response.status_code}"
    except Exception as e:
        return None, str(e)

# 2. Worldwide Domain Recon & Surface Analyzer
def check_domain_infrastructure(domain_str):
    domain_clean = domain_str.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    records = []
    
    # DNS Resolution
    for r_type in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain_clean, r_type)
            for rdata in answers:
                records.append({
                    "Domain": domain_clean,
                    "Record Type": r_type,
                    "Value / Target Host": str(rdata),
                    "Exposure Scope": "Public DNS"
                })
        except Exception:
            pass

    return domain_clean, records

# Main Rendering Logic
if query:
    if search_type == "Email Breach Check":
        with st.spinner("Querying worldwide breach databases..."):
            status, breaches = check_live_email_breaches(query)
            
            if status is True:
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown(f'<div class="metric-card"><div class="metric-lbl">TARGET EMAIL</div><div class="metric-val" style="font-size:1.2rem;">{query}</div></div>', unsafe_allow_html=True)
                with c2:
                    st.markdown(f'<div class="metric-card"><div class="metric-lbl">KNOWN BREACHES FOUND</div><div class="metric-val" style="color:#ef4444;">{len(breaches)}</div></div>', unsafe_allow_html=True)
                with c3:
                    st.markdown(f'<div class="metric-card"><div class="metric-lbl">RISK LEVEL</div><div class="metric-val" style="color:#ef4444;">CRITICAL</div></div>', unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.subheader("🚨 Incident Details & Compromised Sources")
                df = pd.DataFrame(breaches)
                st.dataframe(df, use_container_width=True, hide_index=True)
                
            elif status is False:
                st.success(f"✅ Good news! No publicly disclosed breach records found for **{query}**.")
            else:
                st.error(f"Error querying breach intelligence service: {breaches}")

    elif search_type == "Domain Recon":
        with st.spinner("Scanning worldwide infrastructure & DNS..."):
            domain, records = check_domain_infrastructure(query)
            
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f'<div class="metric-card"><div class="metric-lbl">TARGET DOMAIN</div><div class="metric-val" style="font-size:1.4rem;">{domain}</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="metric-card"><div class="metric-lbl">RESOLVED ASSETS</div><div class="metric-val">{len(records)}</div></div>', unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            st.subheader("🌐 Discovered Network Assets & Records")
            if records:
                st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True)
            else:
                st.warning("No records found. Please check domain name.")
else:
    st.info("👆 Enter any worldwide email (e.g., `elon@x.com`, `admin@adobe.com`) or domain name to run live checks.")
