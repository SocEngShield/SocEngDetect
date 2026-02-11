"""
Social Engineering Detection Dashboard — v6.0.
Displays ONLY: RAG Confidence, Rule Confidence, Overall Confidence + calculation.
No evaluation. No emojis. No duplicate metrics.
"""

import streamlit as st
import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector


st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .status-box {
        padding: 1.5rem; border-radius: 0.5rem; text-align: center;
        margin: 1.5rem 0; font-size: 1.3rem; font-weight: bold;
    }
    .status-high {
        background: rgba(220,53,69,.12); border: 2px solid #dc3545; color: #dc3545;
    }
    .status-potential {
        background: rgba(255,193,7,.12); border: 2px solid #ffc107; color: #ffc107;
    }
    .status-low {
        background: rgba(100,149,237,.12); border: 2px solid #6495ed; color: #6495ed;
    }
    .status-safe {
        background: rgba(40,167,69,.12); border: 2px solid #28a745; color: #28a745;
    }
    #MainMenu, footer { visibility: hidden; }
    .stButton>button {
        width: 100%; border-radius: .5rem; padding: .75rem 1rem; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# -- Initialization --

@st.cache_resource(show_spinner=False)
def init():
    try:
        rag = get_detector()
        rag.add_patterns(SOCIAL_ENGINEERING_DATASET)
        return IntegratedSocialEngineeringDetector(), None
    except Exception as e:
        return None, str(e)


with st.spinner("Loading models..."):
    detector, err = init()

if err:
    st.error(f"Initialization error: {err}")
    st.stop()


# -- Header --

st.title("Social Engineering Detection System")
st.caption("RAG + NLP + Rule Engine  |  Weighted Ensemble (0.6 RAG / 0.4 Rules)")
st.markdown("---")


# -- Message Input --

st.subheader("Enter Message to Analyze")

msg = st.text_area(
    "Message Content",
    height=150,
    placeholder="Your bank account has been suspended. Verify immediately.",
)

if st.button("ANALYZE MESSAGE", type="primary", use_container_width=True):
    if not msg or len(msg.strip()) < 10:
        st.warning("Please enter at least 10 characters.")
    else:
        with st.spinner("Analyzing..."):
            time.sleep(0.2)
            r = detector.analyze_message(msg)

        attack = r["attack_detected"]
        cats = r["categories"]
        risk = r["risk_level"]
        rag_c = r["rag_confidence"]
        rule_c = r["rule_confidence"]
        overall = r["overall_confidence"]
        calc = r["confidence_calculation"]

        cat_label = " + ".join(cats) if cats else "None"

        # -- Status Banner --
        status_map = {
            "HIGH": ("HIGH RISK — THREAT DETECTED", "status-high"),
            "POTENTIAL": ("POTENTIAL THREAT DETECTED", "status-potential"),
            "LOW": ("LOW RISK — SUSPICIOUS INDICATORS", "status-low"),
            "SAFE": ("MESSAGE APPEARS SAFE", "status-safe"),
        }
        label, css = status_map.get(risk, ("UNKNOWN", "status-safe"))
        st.markdown(
            f"<div class='status-box {css}'>{label}</div>",
            unsafe_allow_html=True,
        )

        # -- Detection Result --
        st.markdown("---")
        st.subheader("Detection Result")

        if attack:
            st.error(
                f"**Social Engineering Attack Detected**\n\n"
                f"**Category:** {cat_label}\n\n"
                f"**Risk Level:** {risk}"
            )
        else:
            st.success(
                f"**Message Appears Safe**\n\n"
                f"**Safety Confidence:** {100 - overall:.2f}%"
            )

        # -- Confidence Breakdown (SINGLE LOCATION — not repeated) --
        st.markdown("---")
        st.subheader("Confidence Breakdown")

        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown("**RAG Model Confidence**")
            st.markdown("Probability message is not safe (semantic)")
            st.progress(min(rag_c / 100, 1.0))
            st.metric("RAG Confidence", f"{rag_c:.2f}%")

        with c2:
            st.markdown("**Rule-Based Confidence**")
            st.markdown("Probability message is not safe (keywords)")
            st.progress(min(rule_c / 100, 1.0))
            st.metric("Rule-Based Confidence", f"{rule_c:.2f}%")

        with c3:
            st.markdown("**Overall Combined Confidence**")
            st.markdown("Weighted ensemble result")
            st.progress(min(overall / 100, 1.0))
            st.metric("Overall Confidence", f"{overall:.2f}%")

        st.markdown("")
        st.markdown("**Calculation:**")
        st.code(calc, language="text")

        # -- Technical Details (category + risk only, NO confidence duplication) --
        with st.expander("Technical Details", expanded=False):
            st.markdown(
                f"**Detection Result:** {'Attack Detected' if attack else 'Legitimate'}\n\n"
                f"**Attack Category:** {cat_label}\n\n"
                f"**Risk Level:** {risk}"
            )

        # -- Security Recommendations --
        if attack:
            st.markdown("---")
            with st.expander("Security Recommendations", expanded=True):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(
                        "#### DO NOT\n"
                        "- Click any links in this message\n"
                        "- Download any attachments\n"
                        "- Share personal or financial information\n"
                        "- Respond to the sender\n"
                        "- Call any phone numbers provided"
                    )
                with c2:
                    st.markdown(
                        "#### DO\n"
                        "- Report to your IT security team\n"
                        "- Delete the message\n"
                        "- Verify through official channels\n"
                        "- Change passwords if you already responded\n"
                        "- Enable two-factor authentication"
                    )


# -- Sidebar --

with st.sidebar:
    st.markdown("## System Information")
    st.info(
        "**RAG** — Semantic detection (60% weight)\n\n"
        "**Rules** — Keyword signals (40% weight)\n\n"
        "**Ensemble** — Weighted fusion + severity floors"
    )
    st.markdown("---")
    st.markdown("## Risk Level Thresholds")
    st.markdown(
        "**HIGH** — 76-100%\n\n"
        "**POTENTIAL** — 56-75%\n\n"
        "**LOW** — 31-55%\n\n"
        "**SAFE** — 0-30%"
    )
    st.markdown("---")
    st.metric("Knowledge Base Patterns", len(SOCIAL_ENGINEERING_DATASET))


# -- Footer --

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:.8rem'>"
    "Social Engineering Detection System v6.0  |  "
    "All analysis is performed in real-time. No data is stored."
    "</div>",
    unsafe_allow_html=True,
)