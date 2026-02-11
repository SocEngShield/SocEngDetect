"""
Social Engineering Detection System — Dashboard v4.0.
Clean confidence display • Multi-label categories • Evaluation tab.
"""

import streamlit as st
import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector
from nlp_pipeline.evaluation import DetectionEvaluator


# ── Page config ──
st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ──
st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .status-box {
        padding: 1.5rem; border-radius: 0.5rem; text-align: center;
        margin: 1.5rem 0; font-size: 1.4rem; font-weight: bold;
    }
    .status-critical {
        background: rgba(220,53,69,.15); border: 2px solid #dc3545; color: #dc3545;
    }
    .status-threat {
        background: rgba(255,193,7,.15); border: 2px solid #ffc107; color: #ffc107;
    }
    .status-safe {
        background: rgba(40,167,69,.15); border: 2px solid #28a745; color: #28a745;
    }
    #MainMenu, footer { visibility: hidden; }
    .stButton>button {
        width: 100%; border-radius: .5rem; padding: .75rem 1rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ── Init ──
@st.cache_resource(show_spinner=False)
def init():
    try:
        rag = get_detector()
        rag.add_patterns_to_knowledge_base(SOCIAL_ENGINEERING_DATASET)
        det = IntegratedSocialEngineeringDetector()
        return det, None
    except Exception as e:
        return None, str(e)

with st.spinner("⏳ Loading models (~30 s first time)…"):
    detector, err = init()
if err:
    st.error(f"❌ {err}")
    st.stop()


# ── Header ──
st.title("🛡️ Social Engineering Detection System")
st.caption("RAG + NLP + Rule Engine — Weighted Ensemble")
st.markdown("---")

# ── Tabs ──
tab_analyze, tab_eval = st.tabs(["🔍 Analyze Message", "📊 Evaluation"])


# ═══════════════════════════════════════════════════════
#  TAB 1: ANALYZE
# ═══════════════════════════════════════════════════════

with tab_analyze:
    msg = st.text_area(
        "Enter message to analyze",
        height=150,
        placeholder="Income Tax Department. Submit financial details immediately.",
    )

    if st.button("🔍 ANALYZE", type="primary", use_container_width=True):
        if not msg or len(msg.strip()) < 10:
            st.warning("⚠️ Enter at least 10 characters.")
        else:
            with st.spinner("Analyzing…"):
                time.sleep(0.2)
                r = detector.analyze_message(msg)

            is_att = r["is_social_engineering"]
            conf = r["confidence_score"]
            risk = r["risk_level"]
            cats = r.get("categories", [r["category"]])
            det_d = r.get("details", {})
            rag_c = det_d.get("rag_confidence", 0)
            rule_c = det_d.get("rule_confidence", 0)
            bd = det_d.get("confidence_breakdown", {})
            expl = r.get("explanation", "")

            cat_label = " + ".join(c.replace("_", " ").title() for c in cats)

            # ── Status banner ──
            if is_att and risk in ("HIGH", "CRITICAL"):
                st.markdown(f"""<div class='status-box status-critical'>
                    🔴 {risk} THREAT DETECTED</div>""", unsafe_allow_html=True)
            elif is_att:
                st.markdown(f"""<div class='status-box status-threat'>
                    🟡 POTENTIAL THREAT ({risk})</div>""", unsafe_allow_html=True)
            else:
                st.markdown("""<div class='status-box status-safe'>
                    🟢 MESSAGE APPEARS SAFE</div>""", unsafe_allow_html=True)

            # ── Result summary ──
            if is_att:
                st.error(
                    f"🚨 **Social Engineering Attack Detected**\n\n"
                    f"**Category:** {cat_label}\n\n"
                    f"**Confidence:** {conf * 100:.1f}%\n\n"
                    f"**Risk Level:** {risk}"
                )
            else:
                st.success(
                    f"✅ **Message Appears Legitimate**\n\n"
                    f"**Safety:** {(1 - conf) * 100:.1f}% confidence"
                )

            # ── Explainability ──
            if expl and is_att:
                with st.expander("💡 Why was this flagged?", expanded=True):
                    st.markdown(expl)

            # ── Confidence Breakdown ──
            with st.expander("📐 Confidence Breakdown", expanded=is_att):

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.markdown("**🧠 RAG Confidence**")
                    st.progress(min(rag_c, 1.0))
                    st.metric("RAG", f"{rag_c * 100:.1f}%")
                with c2:
                    st.markdown("**📋 Rule Engine**")
                    st.progress(min(rule_c, 1.0))
                    st.metric("Rules", f"{rule_c * 100:.1f}%")
                with c3:
                    st.markdown("**⚖️ Final Combined**")
                    st.progress(min(conf, 1.0))
                    st.metric("Final", f"{conf * 100:.1f}%")

                st.markdown("---")

                rag_part = round(0.65 * rag_c, 4)
                rule_part = round(0.35 * rule_c, 4)
                raw_sum = round(rag_part + rule_part, 4)

                st.code(
                    f"RAG Confidence:  {rag_c:.4f}\n"
                    f"Rule Confidence: {rule_c:.4f}\n\n"
                    f"Final = (0.65 × {rag_c:.4f}) + (0.35 × {rule_c:.4f})\n"
                    f"      = {rag_part:.4f} + {rule_part:.4f}\n"
                    f"      = {raw_sum:.4f}  (before severity floors)\n\n"
                    f"Final (after floors): {conf:.4f} → {conf*100:.1f}%",
                    language="text",
                )

                st.caption(
                    "Final score is a weighted ensemble of semantic similarity "
                    "(RAG) and rule-based keyword signals. Severity floors "
                    "ensure high-risk messages (government, financial, legal) "
                    "are never classified as SAFE."
                )

            # ── Similar patterns ──
            pats = det_d.get("similar_patterns", [])
            if pats:
                with st.expander("🔗 Similar Known Patterns"):
                    for i, p in enumerate(pats, 1):
                        st.markdown(f"**{i}.** {p['pattern']}")
                        st.caption(f"Similarity: {p['similarity']*100:.1f}%")

            # ── Recommendations ──
            if is_att:
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

            # ── Technical details (CLEAN — no raw_similarity, no rag_vote) ──
            with st.expander("⚙️ Technical Details"):
                st.markdown(
                    f"**Result:** {'Attack' if is_att else 'Legitimate'}\n\n"
                    f"**Categories:** {cat_label}\n\n"
                    f"**Final Confidence:** {conf*100:.1f}%\n\n"
                    f"**Risk Level:** {risk}\n\n"
                    f"**RAG Confidence:** {rag_c*100:.1f}%\n\n"
                    f"**Rule Confidence:** {rule_c*100:.1f}%\n\n"
                    f"**Formula:** `final = (0.65 × RAG) + (0.35 × Rules) + severity floors`"
                )


# ═══════════════════════════════════════════════════════
#  TAB 2: EVALUATION
# ═══════════════════════════════════════════════════════

with tab_eval:
    st.markdown("### 📊 System Evaluation")
    st.markdown(
        "Run the built-in 20-case test suite to measure "
        "accuracy, precision, recall, and F1 score."
    )

    if st.button("▶️ Run Evaluation", type="primary", use_container_width=True):
        with st.spinner("Evaluating 20 test cases…"):
            evaluator = DetectionEvaluator(detector)
            metrics = evaluator.evaluate()

        # Summary metrics
        st.markdown("---")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Accuracy", f"{metrics['accuracy']}%")
        c2.metric("Precision", f"{metrics['precision']:.2f}")
        c3.metric("Recall", f"{metrics['recall']:.2f}")
        c4.metric("F1 Score", f"{metrics['f1_score']:.2f}")

        st.markdown(
            f"**Total:** {metrics['total_samples']} &nbsp;|&nbsp; "
            f"**Correct:** {metrics['correct']} &nbsp;|&nbsp; "
            f"**TP:** {metrics['confusion']['true_positive']} &nbsp;|&nbsp; "
            f"**FP:** {metrics['confusion']['false_positive']} &nbsp;|&nbsp; "
            f"**FN:** {metrics['confusion']['false_negative']} &nbsp;|&nbsp; "
            f"**TN:** {metrics['confusion']['true_negative']}"
        )

        # Per-case details
        st.markdown("---")
        st.markdown("#### Per-Case Results")

        for i, pc in enumerate(metrics["per_case"], 1):
            icon = "✅" if pc["correct"] else "❌"
            exp_label = "ATTACK" if pc["expected_attack"] else "SAFE"
            got_label = "ATTACK" if pc["predicted_attack"] else "SAFE"
            cats_str = ", ".join(pc["predicted_categories"])

            st.markdown(
                f"{icon} **Case {i}:** {pc['text']}\n\n"
                f"&nbsp;&nbsp;&nbsp;&nbsp;"
                f"Expected: `{exp_label}` → Got: `{got_label}` "
                f"| Conf: `{pc['confidence']:.2f}` "
                f"| Risk: `{pc['risk_level']}` "
                f"| Categories: `{cats_str}`"
            )

        # Full text report
        with st.expander("📄 Full Text Report"):
            report = evaluator.format_report(metrics)
            st.code(report, language="text")


# ── Sidebar ──
with st.sidebar:
    st.markdown("## ℹ️ About")
    st.info(
        "**RAG** — Semantic similarity (65%)\n\n"
        "**Rules** — Keyword signals (35%)\n\n"
        "**Ensemble** — Weighted combination + severity floors"
    )
    st.markdown("---")
    st.markdown("## Categories")
    st.markdown(
        "😨 Fear/Threat\n\n"
        "🎭 Impersonation\n\n"
        "👔 Authority\n\n"
        "⏰ Urgency\n\n"
        "🎁 Reward Lure"
    )
    st.markdown("---")
    st.metric("KB Patterns", len(SOCIAL_ENGINEERING_DATASET))


# ── Footer ──
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:.8rem'>"
    "© 2026 Social Engineering Detection System v4.0 — "
    "All analysis is real-time. No data stored.</div>",
    unsafe_allow_html=True,
)