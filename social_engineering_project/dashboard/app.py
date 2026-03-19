"""
Social Engineering Detection Dashboard — v6.0.
Displays ONLY: RAG Confidence, Rule Confidence, Overall Confidence + calculation.
No evaluation. No emojis. No duplicate metrics.
"""

import streamlit as st
import sys
from pathlib import Path
import time
import re

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector


def filter_similar_patterns(similar_patterns, max_items=3):
    if not similar_patterns:
        return []

    def similarity_value(item):
        raw = float(item.get("similarity", 0.0))
        return raw * 100.0 if raw <= 1.0 else raw

    ordered = sorted(similar_patterns, key=similarity_value, reverse=True)

    selected = []
    for item in ordered:
        text = item.get("text", "").strip()
        if not text:
            continue

        cand_tokens = set(re.findall(r"[a-z0-9]+", text.lower()))
        is_duplicate = False
        for chosen in selected:
            chosen_tokens = set(re.findall(r"[a-z0-9]+", chosen["text"].lower()))
            if not cand_tokens or not chosen_tokens:
                continue
            jacc = len(cand_tokens & chosen_tokens) / max(1, len(cand_tokens | chosen_tokens))
            if jacc >= 0.82:
                is_duplicate = True
                break

        if is_duplicate:
            continue

        selected.append(item)
        if len(selected) == max_items:
            break

    if len(selected) >= 2:
        return selected[:max_items]
    return selected


st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .result-box {
        padding: 1rem 1.25rem;
        border-radius: 0.6rem;
        margin: 1.2rem 0 1.2rem 0;
        border: 1px solid rgba(0, 0, 0, 0.08);
    }
    .result-high {
        background: #ffe5e5;
        border-color: #ef9a9a;
        color: #1f1f1f;
    }
    .result-potential {
        background: #fff4e5;
        border-color: #ffcc80;
        color: #1f1f1f;
    }
    .result-low {
        background: #fffbe5;
        border-color: #ffe082;
        color: #111111;
    }
    .result-safe {
        background: #e6ffe6;
        border-color: #a5d6a7;
        color: #1f1f1f;
    }
    .result-message {
        font-size: 1rem;
        font-weight: 700;
        margin-bottom: 0.35rem;
    }
    .result-line {
        font-size: 0.95rem;
        line-height: 1.4;
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
        why_flagged = r.get("why_flagged", [])
        similar_patterns = filter_similar_patterns(r.get("similar_attack_patterns", []), max_items=3)
        dos = r.get("dos", [])
        donts = r.get("donts", [])

        cat_label = " + ".join(cats) if cats else "None"

        # -- Result Box --
        style_map = {
            "HIGH": ("result-high", "HIGH"),
            "POTENTIAL": ("result-potential", "POTENTIAL"),
            "LOW": ("result-low", "LOW"),
            "SAFE": ("result-safe", "SAFE"),
        }
        css, risk_title = style_map.get(risk, ("result-safe", "Safe"))
        threat_message_map = {
            "HIGH": "High threat detected",
            "POTENTIAL": "Potential threat detected",
            "LOW": "Low risk detected",
            "SAFE": "No significant threat detected",
        }
        status_message = threat_message_map.get(risk, "No significant threat detected")

        st.markdown(
            (
                f"<div class='result-box {css}'>"
                f"<div class='result-message'>{status_message}</div>"
                f"<div class='result-line'><b>Category:</b> {cat_label}</div>"
                f"<div class='result-line'><b>Risk Level:</b> {risk_title}</div>"
                f"</div>"
            ),
            unsafe_allow_html=True,
        )

        # -- Explanation --
        st.markdown("---")
        st.subheader("Why This Message Was Flagged")
        concise_explanations = []
        seen_explanations = set()
        skip_prefixes = (
            "rag category signal",
            "top similarity is",
            "this matches known patterns",
        )
        for item in why_flagged:
            norm = item.strip()
            key = norm.lower()
            if not norm or key in seen_explanations:
                continue
            if any(key.startswith(p) for p in skip_prefixes):
                continue
            seen_explanations.add(key)
            concise_explanations.append(norm)
            if len(concise_explanations) == 4:
                break

        if concise_explanations:
            for item in concise_explanations:
                st.markdown(f"- {item}")
        else:
            st.markdown("- No strong risk indicators were triggered for this message.")

        st.markdown("---")
        st.subheader("Similar Attack Patterns")
        if similar_patterns:
            for p in similar_patterns:
                raw_similarity = float(p.get("similarity", 0.0))
                similarity_pct = round(raw_similarity * 100, 2) if raw_similarity <= 1 else round(raw_similarity, 2)
                st.markdown(
                    f"- {p['text']} (Similarity: {similarity_pct:.2f}%)"
                )
        else:
            st.markdown("- No strong similar attack patterns were retrieved.")

        st.markdown("---")
        d1, d2 = st.columns(2)
        with d1:
            st.subheader("What You Should Do")
            for tip in dos:
                st.markdown(f"- {tip}")

        with d2:
            st.subheader("What You Should Avoid")
            for tip in donts:
                st.markdown(f"- {tip}")

        


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
    st.markdown("**Knowledge Base Patterns - 322**")


# -- Footer --

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:.8rem'>"
    "Social Engineering Detection System v6.0  |  "
    "All analysis is performed in real-time. No data is stored."
    "</div>",
    unsafe_allow_html=True,
)