"""
Social Engineering Detection Dashboard — v6.0.
"""

import streamlit as st
import sys
from pathlib import Path
import time
import plotly.graph_objects as go

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector
from security_logic.rule_engine import analyze_text


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
.status-high { background: rgba(220,53,69,.12); border: 2px solid #dc3545; color: #dc3545; }
.status-potential { background: rgba(255,193,7,.12); border: 2px solid #ffc107; color: #ffc107; }
.status-low { background: rgba(100,149,237,.12); border: 2px solid #6495ed; color: #6495ed; }
.status-safe { background: rgba(40,167,69,.12); border: 2px solid #28a745; color: #28a745; }
#MainMenu, footer { visibility: hidden; }
.stButton>button {
    width: 100%; border-radius: .5rem; padding: .75rem 1rem; font-weight: 600;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------
# FINAL RADAR LOGIC
# ---------------------------
def build_radar_data(rule_output, integrated_result):

    # normalized scores from rule_engine
    radar = dict(rule_output["radar_data"])

    # ML category guidance (light boost)
    ml_categories = [c.lower() for c in integrated_result.get("categories", [])]

    category_map = {
        "urgency": "urgency",
        "authority": "authority",
        "impersonation": "impersonation",
        "reward/lure": "reward_lure",
        "fear/threat": "fear_threat",
    }

    for cat in ml_categories:
        mapped = category_map.get(cat)
        if mapped and mapped in radar:
            radar[mapped] = min(radar[mapped] + 0.1, 1.0)

    return radar


def get_top_signals(radar_data):
    return sorted(radar_data.items(), key=lambda x: x[1], reverse=True)[:2]


def create_radar_chart(radar_data):
    categories = list(radar_data.keys())
    values = list(radar_data.values())

    categories += [categories[0]]
    values += [values[0]]

    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        line=dict(width=2, color="#00bcd4"),
        fillcolor="rgba(0, 188, 212, 0.2)",
        opacity=0.9,
        hovertemplate='%{theta}: %{r:.2f}<extra></extra>'
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1],
                tickvals=[0.2, 0.4, 0.6, 0.8, 1.0]
            )
        ),
        showlegend=False,
        margin=dict(l=20, r=20, t=20, b=20)
    )

    return fig


# ---------------------------
# INIT
# ---------------------------
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


# ---------------------------
# UI
# ---------------------------
st.title("Social Engineering Detection System")
st.caption("RAG + NLP + Rule Engine  |  Weighted Ensemble (0.6 RAG / 0.4 Rules)")
st.markdown("---")

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
            rule_output = analyze_text(msg)

        attack = r["attack_detected"]
        cats = r["categories"]
        risk = r["risk_level"]
        rag_c = r["rag_confidence"]
        rule_c = r["rule_confidence"]
        overall = r["overall_confidence"]
        calc = r["confidence_calculation"]

        cat_label = " + ".join(cats) if cats else "None"

        status_map = {
            "HIGH": ("HIGH RISK — THREAT DETECTED", "status-high"),
            "POTENTIAL": ("POTENTIAL THREAT DETECTED", "status-potential"),
            "LOW": ("LOW RISK — SUSPICIOUS INDICATORS", "status-low"),
            "SAFE": ("MESSAGE APPEARS SAFE", "status-safe"),
        }

        label, css = status_map.get(risk, ("UNKNOWN", "status-safe"))

        st.markdown(f"<div class='status-box {css}'>{label}</div>", unsafe_allow_html=True)

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

        # ---------------------------
        # FINAL RADAR
        # ---------------------------
        st.markdown("---")
        st.subheader("Social Engineering Signal Distribution")

        radar_data = build_radar_data(rule_output, r)
        fig = create_radar_chart(radar_data)
        st.plotly_chart(fig, use_container_width=True)

        top_signals = get_top_signals(radar_data)
        top_labels = ", ".join([f"{k} ({v:.2f})" for k, v in top_signals if v > 0])

        if top_labels:
            st.markdown(f"**Primary Signals Detected:** {top_labels}")

        # ---------------------------
        # CONFIDENCE
        # ---------------------------
        st.markdown("---")
        st.subheader("Confidence Breakdown")

        c1, c2, c3 = st.columns(3)

        with c1:
            st.markdown("**RAG Model Confidence**")
            st.progress(min(rag_c / 100, 1.0))
            st.metric("RAG Confidence", f"{rag_c:.2f}%")

        with c2:
            st.markdown("**Rule-Based Confidence**")
            st.progress(min(rule_c / 100, 1.0))
            st.metric("Rule-Based Confidence", f"{rule_c:.2f}%")

        with c3:
            st.markdown("**Overall Combined Confidence**")
            st.progress(min(overall / 100, 1.0))
            st.metric("Overall Confidence", f"{overall:.2f}%")

        st.markdown("")
        st.markdown("**Calculation:**")
        st.code(calc, language="text")

        with st.expander("Technical Details", expanded=False):
            st.markdown(
                f"**Detection Result:** {'Attack Detected' if attack else 'Legitimate'}\n\n"
                f"**Attack Category:** {cat_label}\n\n"
                f"**Risk Level:** {risk}"
            )


# ---------------------------
# SIDEBAR
# ---------------------------
with st.sidebar:
    st.markdown("## System Information")
    st.info(
        "**RAG** — Semantic detection (60%)\n\n"
        "**Rules** — Keyword signals (40%)\n\n"
        "**Radar** — Signal distribution visualization"
    )

    st.markdown("---")
    st.metric("Knowledge Base Patterns", len(SOCIAL_ENGINEERING_DATASET))


# ---------------------------
# FOOTER
# ---------------------------
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:.8rem'>"
    "Social Engineering Detection System v6.0  |  Real-time analysis"
    "</div>",
    unsafe_allow_html=True,
)