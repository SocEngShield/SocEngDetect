"""
Social Engineering Detection Dashboard — v5.0 STRICT.
Displays ONLY: RAG Confidence, Rule Confidence, Overall Confidence + calculation.
Evaluation tab with sklearn metrics.
"""

import streamlit as st
import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector
from nlp_pipeline.evaluation import run_evaluation

# ── Page config ──
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
        margin: 1.5rem 0; font-size: 1.4rem; font-weight: bold;
    }
    .status-high {
        background: rgba(220,53,69,.15); border: 2px solid #dc3545; color: #dc3545;
    }
    .status-potential {
        background: rgba(255,193,7,.15); border: 2px solid #ffc107; color: #ffc107;
    }
    .status-low {
        background: rgba(100,149,237,.15); border: 2px solid #6495ed; color: #6495ed;
    }
    .status-safe {
        background: rgba(40,167,69,.15); border: 2px solid #28a745; color: #28a745;
    }
    #MainMenu, footer { visibility: hidden; }
    .stButton>button {
        width: 100%; border-radius: .5rem; padding: .75rem 1rem; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ── Init ──
@st.cache_resource(show_spinner=False)
def init():
    try:
        rag = get_detector()
        rag.add_patterns(SOCIAL_ENGINEERING_DATASET)
        return IntegratedSocialEngineeringDetector(), None
    except Exception as e:
        return None, str(e)

with st.spinner("⏳ Loading models (~30s first time)…"):
    detector, err = init()
if err:
    st.error(f"❌ {err}")
    st.stop()


# ── Header ──
st.title("🛡️ Social Engineering Detection System")
st.caption("RAG + NLP + Rule Engine — Weighted Ensemble (0.6 RAG / 0.4 Rules)")
st.markdown("---")

tab_analyze, tab_eval = st.tabs(["🔍 Analyze Message", "📊 Evaluation"])


# ═══════════════════════════════════════════════
#  TAB 1: ANALYZE
# ═══════════════════════════════════════════════

with tab_analyze:
    msg = st.text_area(
        "Enter message to analyze",
        height=150,
        placeholder="Your bank account has been suspended. Verify immediately.",
    )

    if st.button("🔍 ANALYZE", type="primary", use_container_width=True):
        if not msg or len(msg.strip()) < 10:
            st.warning("⚠️ Enter at least 10 characters.")
        else:
            with st.spinner("Analyzing…"):
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

            # ── Status banner ──
            status_map = {
                "HIGH": ("🔴 HIGH RISK — THREAT DETECTED", "status-high"),
                "POTENTIAL": ("🟡 POTENTIAL THREAT DETECTED", "status-potential"),
                "LOW": ("🔵 LOW RISK — SUSPICIOUS", "status-low"),
                "SAFE": ("🟢 MESSAGE APPEARS SAFE", "status-safe"),
            }
            label, css = status_map.get(risk, ("⚪ UNKNOWN", "status-safe"))
            st.markdown(
                f"<div class='status-box {css}'>{label}</div>",
                unsafe_allow_html=True,
            )

            # ── Detection Result ──
            if attack:
                st.error(
                    f"🚨 **Social Engineering Attack Detected**\n\n"
                    f"**Category:** {cat_label}\n\n"
                    f"**Confidence:** {overall:.2f}%\n\n"
                    f"**Risk Level:** {risk}"
                )
            else:
                st.success(
                    f"✅ **Message Appears Safe**\n\n"
                    f"**Safety Confidence:** {100 - overall:.2f}%"
                )

            # ── Confidence Breakdown (ONLY 3 metrics + formula) ──
            with st.expander("📐 Confidence Breakdown", expanded=attack):
                c1, c2, c3 = st.columns(3)

                with c1:
                    st.markdown("**🧠 RAG Model Confidence**")
                    st.progress(min(rag_c / 100, 1.0))
                    st.metric("RAG", f"{rag_c:.2f}%")

                with c2:
                    st.markdown("**📋 Rule-Based Confidence**")
                    st.progress(min(rule_c / 100, 1.0))
                    st.metric("Rules", f"{rule_c:.2f}%")

                with c3:
                    st.markdown("**⚖️ Overall Combined**")
                    st.progress(min(overall / 100, 1.0))
                    st.metric("Overall", f"{overall:.2f}%")

                st.markdown("---")
                st.markdown("**Calculation:**")
                st.code(calc, language="text")

            # ── Technical Details (ONLY required fields) ──
            with st.expander("⚙️ Technical Details"):
                st.markdown(
                    f"**Detection Result:** {'Attack Detected' if attack else 'Legitimate'}\n\n"
                    f"**Risk Level:** {risk}\n\n"
                    f"**Categories:** {cat_label}\n\n"
                    f"**RAG Confidence:** {rag_c:.2f}%\n\n"
                    f"**Rule-Based Confidence:** {rule_c:.2f}%\n\n"
                    f"**Overall Confidence:** {overall:.2f}%\n\n"
                    f"**Confidence Calculation:**"
                )
                st.code(calc, language="text")

            # ── Recommendations ──
            if attack:
                st.markdown("---")
                with st.expander("🛡️ Security Recommendations", expanded=True):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(
                            "#### ❌ DO NOT\n"
                            "- Click any links\n"
                            "- Download attachments\n"
                            "- Share personal/financial info\n"
                            "- Respond to the sender\n"
                            "- Call numbers provided"
                        )
                    with c2:
                        st.markdown(
                            "#### ✅ DO\n"
                            "- Report to IT security\n"
                            "- Delete the message\n"
                            "- Verify via official channels\n"
                            "- Change passwords if compromised\n"
                            "- Enable two-factor auth"
                        )


# ═══════════════════════════════════════════════
#  TAB 2: EVALUATION (sklearn metrics)
# ═══════════════════════════════════════════════

with tab_eval:
    st.markdown("### 📊 Model Evaluation")
    st.markdown(
        "Run the built-in 20-case labeled test suite to compute "
        "Accuracy, Precision, Recall, F1 Score, and Confusion Matrix."
    )

    if st.button("▶️ Run Evaluation", type="primary", use_container_width=True):
        with st.spinner("Evaluating 20 test cases…"):
            metrics = run_evaluation(detector)

        st.markdown("---")
        st.markdown("#### 📈 Metrics")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Accuracy", f"{metrics['accuracy']}%")
        c2.metric("Precision", f"{metrics['precision']}%")
        c3.metric("Recall", f"{metrics['recall']}%")
        c4.metric("F1 Score", f"{metrics['f1_score']}%")

        st.markdown("---")
        st.markdown("#### 🔢 Confusion Matrix")

        cm = metrics["confusion_matrix"]
        st.markdown(
            f"**Total Samples:** {metrics['total']}  \n"
            f"**Correct:** {metrics['correct']}  \n\n"
            f"| | Predicted Attack | Predicted Safe |\n"
            f"|---|---|---|\n"
            f"| **Actual Attack** | TP = {cm['TP']} | FN = {cm['FN']} |\n"
            f"| **Actual Safe** | FP = {cm['FP']} | TN = {cm['TN']} |"
        )

        st.markdown("---")
        st.markdown("#### 📋 Per-Case Results")

        for i, pc in enumerate(metrics["per_case"], 1):
            icon = "✅" if pc["correct"] else "❌"
            cats_str = ", ".join(pc["categories"]) if pc["categories"] else "—"
            st.markdown(
                f"{icon} **Case {i}:** {pc['text']}\n\n"
                f"&nbsp;&nbsp;&nbsp;&nbsp;"
                f"Expected: `{pc['expected']}` → Got: `{pc['predicted']}` "
                f"| Conf: `{pc['overall_confidence']:.2f}%` "
                f"| Risk: `{pc['risk_level']}` "
                f"| Categories: `{cats_str}`"
            )


# ── Sidebar ──
with st.sidebar:
    st.markdown("## ℹ️ System")
    st.info(
        "**RAG** — Semantic detection (60%)\n\n"
        "**Rules** — Keyword signals (40%)\n\n"
        "**Ensemble** — Weighted fusion + severity floors"
    )
    st.markdown("---")
    st.markdown("## 📊 Risk Levels")
    st.markdown(
        "🔴 **HIGH** — 76-100%\n\n"
        "🟡 **POTENTIAL** — 56-75%\n\n"
        "🔵 **LOW** — 31-55%\n\n"
        "🟢 **SAFE** — 0-30%"
    )
    st.markdown("---")
    st.metric("KB Patterns", len(SOCIAL_ENGINEERING_DATASET))


st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:.8rem'>"
    "© 2026 Social Engineering Detection System v5.0</div>",
    unsafe_allow_html=True,
)