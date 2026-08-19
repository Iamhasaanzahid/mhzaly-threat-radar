import streamlit as st
import pandas as pd
from database import init_db, search_breaches, get_stats

init_db()

st.set_page_config(page_title="Threat Intel Tool", layout="wide", page_icon="🌐")

st.markdown("""
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #f3f4f6;
    }
    .metric-box {
        background-color: #111827;
        border: 1px solid #1f2937;
        padding: 18px;
        border-radius: 10px;
        margin-bottom: 15px;
    }
    .metric-num {
        font-size: 1.8rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-lbl {
        font-size: 0.8rem;
        color: #9ca3af;
        letter-spacing: 0.05em;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🌐 SoloRadar — Threat Intel Tool")
st.markdown("Search across domains, leaked credentials, dark web dumps, and exposed assets.")

col_opt, col_srch = st.columns([1, 3])
with col_opt:
    search_type = st.radio("Search Filter", ["Domain", "Email / Username"], horizontal=True)
with col_srch:
    query = st.text_input("Enter Search Target", value="umt.edu.pk")

st.markdown("---")

if query:
    emp_count, cust_count = get_stats(query, search_type)
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-lbl">EMPLOYEES COMPROMISED</div>
            <div class="metric-num">{emp_count:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-lbl">CUSTOMERS EXPOSED</div>
            <div class="metric-num">{cust_count:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-lbl">TOTAL EXPOSURES</div>
            <div class="metric-num">{emp_count + cust_count:,}</div>
        </div>
        """, unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["📋 All Records", "💼 Employees", "👥 Customers"])

    def display_results(category):
        rows = search_breaches(query, search_type, category)
        if not rows:
            st.info("No matching records found.")
            return
        
        table_list = []
        for r in rows:
            table_list.append({
                "ID": r[0],
                "Username / Email": r[1],
                "Password": r[2] if r[7] == 0 else f"🔓 {r[3]}",
                "Target URL": r[4],
                "Category": r[5],
                "Added Date": r[6],
                "Status": "Unlocked" if r[7] == 1 else "Locked"
            })
        st.dataframe(pd.DataFrame(table_list), use_container_width=True, hide_index=True)

    with tab1:
        display_results("All")
    with tab2:
        display_results("Employees")
    with tab3:
        display_results("Customers")
