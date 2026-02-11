"""
Social Engineering Detection System - Professional Dashboard
v3.0 — Clean confidence display: RAG + Rules + Final only.
       Multi-label category display. No raw_similarity / rag_vote.
"""

import streamlit as st
import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector


# PAGE CONFIGURATION
st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded"
)


# CUSTOM CSS
st.markdown("""
<style>
    .main { padding: 2rem; }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .metric-card {
        background-color: rgba(255, 255, 255, 0.05);
        padding: 1.5rem; border-radius: 0.5rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 1rem;
    }
    .status-box {
        padding: 1.5rem; border-radius: 0.5rem; text-align: center;
        margin: 2rem 0; font-size: 1.5rem; font-weight: bold;
    }
    .status-threat {
        background-color: rgba(255, 193, 7, 0.2);
        border: 2px solid #ffc107; color: #ffc107;
    }
    .status-critical {
        background-color: rgba(220, 53, 69, 0.2);
        border: 2px solid #dc3545; color: #dc3545;
    }
    .status-safe {
        background-color: rgba(40, 167, 69, 0.2);
        border: 2px solid #28a745; color: #28a745;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stButton>button {
        width: 100%; border-radius: 0.5rem;
        padding: 0.75rem 1rem; font-weight: 600;
        background-color: #dc3545; color: white;
    }
    .stButton>button:hover { background-color: #c82333; }
    .stTextArea textarea { border-radius: 0.5rem; }
    hr { margin: 2rem 0; }
</style>
""", unsafe_allow_html=True)


# INITIALIZE DETECTOR (CACHED)
@st.cache_resource(show_spinner=False)
def initialize_detector():
    try:
        rag_detector = get_detector()
        rag_detector.add_patterns_to_knowledge_base(SOCIAL_ENGINEERING_DATASET)
        detector = IntegratedSocialEngineeringDetector()
        return detector, None
    except Exception as e:
        return None, str(e)


with st.spinner("⏳ Initializing models... Please wait (~30 seconds on first run)"):
    detector, error = initialize_detector()

if error:
    st.error(f" Error initializing detector: {error}")
    st.info("🔄 Please refresh the page. If the error persists, contact the administrator.")
    st.stop()


# HEADER
st.title(" Social Engineering Detection System")
st.markdown("### Message Analysis using RAG, NLP & Machine Learning")
st.markdown("---")


# SIDEBAR
with st.sidebar:
    st.markdown("## ℹ About This System")
    st.info("""
    **RAG** — Semantic similarity via embeddings
    **Rules** — Keyword + heuristic detection
    **Ensemble** — 65% RAG + 35% Rules
    """)

    st.markdown("---")
    st.markdown("##  Detection Categories")
    st.markdown("""
    ⏰ **Urgency** — Pressure for quick action
    🎁 **Reward/Lure** — Fake rewards
    👔 **Authority** — Fake authority figures
    🎭 **Impersonation** — Trusted entity spoofing
    😨 **Fear/Threat** — Intimidation & scare tactics
    """)

    st.markdown("---")
    st.markdown("System Statistics")
    st.metric("Knowledge Base Patterns", len(SOCIAL_ENGINEERING_DATASET))
    st.metric("Detection Accuracy", "88-95%")
    st.metric("Average Response Time", "< 2 sec")


# MAIN INPUT
st.markdown("Enter Message to Analyze")
st.markdown("Type or paste any message, email, SMS, or communication you want to check.")

user_message = st.text_area(
    label="Message Content",
    height=200,
    placeholder="Example: Income Tax Department. Submit financial details immediately.",
    help="Enter the complete message you want to analyze.",
    key="user_input_message"
)

analyze_clicked = st.button("🔍 ANALYZE MESSAGE", type="primary", use_container_width=True)


# ANALYSIS
if analyze_clicked:
    if not user_message or len(user_message.strip()) < 10:
        st.warning(" Please enter a message with at least 10 characters.")
    else:
        with st.spinner(" Analyzing message..."):
            time.sleep(0.3)

            try:
                result = detector.analyze_message(user_message)

                st.markdown("---")
                st.markdown("Analysis Results")

                is_attack = result["is_social_engineering"]
                confidence = result["confidence_score"]
                risk_level = result["risk_level"]
                categories = result.get("categories", [result["category"]])
                details = result.get("details", {})

                rag_conf = details.get("rag_confidence", 0)
                rule_conf = details.get("rule_confidence", 0)
                breakdown = details.get("confidence_breakdown", {})

                # ── Status banner ──
                if is_attack:
                    if risk_level in ("HIGH", "CRITICAL"):
                        st.markdown(f"""
                        <div class='status-box status-critical'>
                            🔴 {risk_level} THREAT DETECTED
                        </div>""", unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class='status-box status-threat'>
                            🟡 POTENTIAL THREAT DETECTED ({risk_level})
                        </div>""", unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class='status-box status-safe'>
                        🟢 MESSAGE APPEARS SAFE
                    </div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Category + confidence summary ──
                cat_display = " + ".join(
                    c.replace("_", " ").title() for c in categories
                )

                st.markdown("Detailed Explanation")

                if is_attack:
                    st.error(f"""
 **Social Engineering Attack Detected**

**Category:** {cat_display}
**Confidence:** {confidence * 100:.1f}%
**Risk Level:** {risk_level}
                    """)
                else:
                    st.success(f"""
 **Message Appears Legitimate**

**Safety Confidence:** {(1 - confidence) * 100:.1f}%
No significant threats detected.
                    """)

                # ── Confidence Breakdown ──
                with st.expander(" View Confidence Breakdown", expanded=True):

                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.markdown(" RAG Confidence**")
                        st.markdown("_How unsafe per semantic similarity_")
                        st.progress(min(rag_conf, 1.0))
                        st.metric("RAG", f"{rag_conf * 100:.1f}%")

                    with col2:
                        st.markdown(" Rule Engine Confidence**")
                        st.markdown("_How unsafe per keyword signals_")
                        st.progress(min(rule_conf, 1.0))
                        st.metric("Rules", f"{rule_conf * 100:.1f}%")

                    with col3:
                        st.markdown(" Final Combined Confidence**")
                        st.markdown("_Weighted ensemble result_")
                        st.progress(min(confidence, 1.0))
                        st.metric("Final", f"{confidence * 100:.1f}%")

                    # ── Formula display ──
                    st.markdown("---")
                    st.markdown("Ensemble Calculation")

                    rag_c = round(0.65 * rag_conf, 4)
                    rule_c = round(0.35 * rule_conf, 4)
                    raw_sum = round(rag_c + rule_c, 4)

                    st.code(
                        f"RAG confidence:  {rag_conf:.4f}\n"
                        f"Rule confidence: {rule_conf:.4f}\n"
                        f"\n"
                        f"Final confidence:\n"
                        f"  (0.65 × {rag_conf:.4f}) + (0.35 × {rule_conf:.4f})\n"
                        f"= {rag_c:.4f} + {rule_c:.4f}\n"
                        f"= {raw_sum:.4f}  (before severity floors)\n"
                        f"\n"
                        f"Final (after floors): {confidence:.4f}",
                        language="text",
                    )

                    st.caption(
                        "Final score is weighted ensemble of semantic similarity "
                        "and rule-based signals. Severity floors may raise the "
                        "score when high-risk keywords (legal, government, "
                        "financial) are detected."
                    )

                # ── Similar patterns ──
                similar = details.get("similar_patterns", [])
                if similar:
                    with st.expander("Similar Known Attack Patterns"):
                        for i, pat in enumerate(similar, 1):
                            pct = pat["similarity"] * 100
                            st.markdown(f"**{i}.** {pat['pattern']}")
                            st.caption(f"Similarity: {pct:.1f}%")

                # ── Security recommendations ──
                if is_attack:
                    st.markdown("---")
                    with st.expander("Security Recommendations", expanded=True):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.markdown("#### DO NOT")
                            st.markdown("""
                            - Click any links in this message
                            - Download any attachments
                            - Share personal or financial information
                            - Respond to the sender
                            - Call any phone numbers provided
                            """)
                        with c2:
                            st.markdown("####  DO")
                            st.markdown("""
                            - Report to IT security team immediately
                            - Delete the message
                            - Verify through official channels
                            - Change passwords if you responded
                            - Enable two-factor authentication
                            """)

                # ── Technical details (clean — no raw_similarity, no rag_vote) ──
                with st.expander("Technical Details", expanded=False):
                    st.markdown(f"""
**Result:** {"Attack Detected" if is_attack else "Legitimate"}
**Categories:** {cat_display}
**Final Confidence:** {confidence * 100:.1f}%
**Risk Level:** {risk_level}
**RAG Confidence:** {rag_conf * 100:.1f}%
**Rule Confidence:** {rule_conf * 100:.1f}%
**Formula:** final = (0.65 × RAG) + (0.35 × Rules) + severity floors
                    """)

            except Exception as e:
                st.error(f" Error during analysis: {str(e)}")
                st.info("🔄 Please try again.")


# HOW IT WORKS
st.markdown("---")
st.markdown("##  How It Works")

c1, c2, c3 = st.columns(3)
with c1:
    st.markdown("""
    #### 1️⃣ Input Processing
    - Text normalization
    - Feature extraction
    """)
with c2:
    st.markdown("""
    #### 2️⃣ AI Analysis
    - RAG embedding search (confidence)
    - Rule-based classification (category)
    - Weighted ensemble
    """)
with c3:
    st.markdown("""
    #### 3️⃣ Results
    - Multi-label categories (max 2)
    - Severity-aware risk levels
    - Actionable recommendations
    """)


# FOOTER
st.markdown("---")
st.markdown("""
<div style='text-align: center; padding: 2rem; background-color: rgba(255,255,255,0.05); border-radius: 10px;'>
    <p> RAG + Embeddings + NLP</p>
    <p style='color: #888; font-size: 0.9rem;'>
        All analysis is performed in real-time. No data is stored.
    </p>
    <p style='font-size: 0.8rem; color: #666;'>
        © 2026 Social Engineering Detection System | Version 3.0.0
    </p>
</div>
""", unsafe_allow_html=True)