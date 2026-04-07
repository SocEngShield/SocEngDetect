"""
Social Engineering Detection Dashboard — v6.0.
Displays ONLY: RAG Confidence, Rule Confidence, Overall Confidence + calculation.
Bar chart added with ML + Rule fusion.
"""

import streamlit as st
import sys
from pathlib import Path
import time
import re
import json
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector

# REQUIRED IMPORTS
from security_logic.rule_engine import analyze_text
from security_logic.signal_fusion import fuse_signals
from bar_chart import create_bar_chart, get_top_signals
from simulator import generate_attack_message
from utils.export import get_json_data, get_csv_data, get_pdf_data

# API IMPORTS (optional features)
try:
    from utils.api_config import get_api_status, API_ENABLED
    from utils.api_integrations import check_url_external
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    API_ENABLED = False


# ---------------------------
# UTILS
# ---------------------------

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


def format_score(score):
    rounded = round(float(score), 2)
    text = f"{rounded:.2f}".rstrip("0").rstrip(".")
    return f"{text}%"


def shorten_text(text, max_len=140):
    clean = " ".join(str(text).split())
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3].rstrip() + "..."


# ---------------------------
# PAGE CONFIG
# ---------------------------

st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    .verdict-box {
        width: min(900px, 90%);
        margin: 1rem auto 1.2rem auto;
        padding: 1.25rem 1rem;
        border-radius: 0.7rem;
        border: 2px solid transparent;
        text-align: center;
    }
    .verdict-text {
        font-size: 1.7rem;
        font-weight: 800;
        letter-spacing: 0.02em;
        margin: 0 0 0.55rem 0;
    }
    .verdict-meta {
        font-size: 1rem;
        line-height: 1.5;
        margin: 0.1rem 0;
        text-align: center;
    }
    .verdict-high {
        background: #ffe5e5;
        border-color: #d32f2f;
        color: #1f1f1f;
    }
    .verdict-potential {
        background: #fff4e5;
        border-color: #ef6c00;
        color: #1f1f1f;
    }
    .verdict-low {
        background: #e6f0ff;
        border-color: #1e88e5;
        color: #1f1f1f;
    }
    .verdict-safe {
        background: #e6ffe6;
        border-color: #2e7d32;
        color: #1f1f1f;
    }
    .score-title {
        font-size: 0.95rem;
        font-weight: 600;
        margin-bottom: 0.25rem;
    }
    .score-value {
        font-size: 1.1rem;
        font-weight: 700;
        margin-bottom: 0.45rem;
    }
    .bar-track {
        width: 100%;
        height: 0.5rem;
        background: #eceff3;
        border-radius: 999px;
        overflow: hidden;
    }
    .bar-fill {
        height: 100%;
        border-radius: 999px;
    }
    .bar-rag { background: #bcd8ff; }
    .bar-rule { background: #ffd8b0; }
    .bar-final { background: #c9eccd; }
    #MainMenu, footer { visibility: hidden; }
    .stButton>button {
        width: 100%; border-radius: .5rem; padding: .75rem 1rem; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


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
# HEADER
# ---------------------------

st.title("Social Engineering Detection System")
st.caption("RAG + NLP + Rule Engine  |  Weighted Ensemble (0.6 RAG / 0.4 Rules)")
st.markdown("---")


# ---------------------------
# SIDEBAR: SETTINGS
# ---------------------------



# ---------------------------
# SESSION STATE INIT
# ---------------------------

if "simulated_message" not in st.session_state:
    st.session_state.simulated_message = ""


# ---------------------------
# ATTACK SIMULATION MODE
# ---------------------------

with st.expander("Attack Simulation Mode", expanded=False):
    selected_tactics = st.multiselect(
        "Select manipulation tactics:",
        ["fear", "urgency", "reward", "authority", "impersonation"],
        default=[],
        key="sim_tactics",
    )

    if st.button("Generate Simulated Attack", key="sim_generate"):
        if selected_tactics:
            generated = generate_attack_message(selected_tactics)
            st.session_state.simulated_message = generated
            st.code(generated, language=None)
            st.success("Message generated. Click ANALYZE to test detection.")
        else:
            st.warning("Select at least one tactic.")


# ---------------------------
# INPUT
# ---------------------------

st.subheader("Enter Message to Analyze")

msg = st.text_area(
    "Message Content",
    value=st.session_state.simulated_message,
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

            # Fuse rule signals with ML detection
            fused_output = fuse_signals(
                rule_output,
                r["rag_confidence"],
                r.get("categories", [])
            )
            
            # Optional: External API URL check
            external_api_result = None
            if st.session_state.get("use_external_api", False) and API_AVAILABLE:
                urls = r.get("context", {}).get("url", {}).get("urls", [])
                if urls:
                    with st.spinner("Checking URLs with external APIs..."):
                        external_api_result = check_url_external(urls[0])

        attack = r["attack_detected"]
        cats = r["categories"]
        cat_label = " + ".join(cats) if cats else "None"
        risk = str(r.get("risk_level", "SAFE")).strip().upper()
        rag_score = float(r["rag_confidence"])
        rule_score = float(r["rule_confidence"])
        final_score = float(r["overall_confidence"])
        score_calc = r["confidence_calculation"]
        why_flagged = r.get("why_flagged", [])
        top_k_results = r.get("similar_attack_patterns", [])
        similar_patterns = filter_similar_patterns(top_k_results, max_items=3)
        dos = r.get("dos", [])
        donts = r.get("donts", [])

        # Store for export
        st.session_state["last_analysis"] = {
            "message": msg,
            "risk_level": risk,
            "attack_type": r.get("attack_type", ""),
            "categories": cats,
            "rag_confidence": rag_score,
            "rule_confidence": rule_score,
            "overall_confidence": final_score,
            "signal_breakdown": fused_output.get("per_signal_breakdown", {}),
            "fusion_meta": fused_output.get("fusion_meta", {}),
            "context": r.get("context", {}),
            "why_flagged": r.get("why_flagged", []),
            "similar_attack_patterns": filter_similar_patterns(top_k_results, max_items=3),
        }

        # ---------------------------
        # STATUS BOX
        # ---------------------------

        verdict_map = {
            "HIGH": ("HIGH THREAT DETECTED", "verdict-high", "HIGH"),
            "POTENTIAL": ("POTENTIAL THREAT DETECTED", "verdict-potential", "POTENTIAL"),
            "LOW": ("LOW RISK MESSAGE", "verdict-low", "LOW"),
            "SAFE": ("MESSAGE IS SAFE", "verdict-safe", "SAFE"),
        }
        verdict_text, verdict_css, risk_title = verdict_map.get(
            risk,
            ("MESSAGE IS SAFE", "verdict-safe", "SAFE"),
        )

        st.markdown(
            (
                f"<div class='verdict-box {verdict_css}'>"
                f"<div class='verdict-text'>{verdict_text}</div>"
                f"<div class='verdict-meta'><b>Risk Level:</b> {risk_title}</div>"
                f"<div class='verdict-meta'><b>Category:</b> {cat_label}</div>"
                f"</div>"
            ),
            unsafe_allow_html=True,
        )

        # F2: Attack Type Classification
        attack_type = r.get("attack_type")
        if attack_type:
            st.markdown(f"**Attack Type:** {attack_type}")

        # ---------------------------
        # CONFIDENCE
        # ---------------------------

        st.markdown("---")
        st.subheader("Confidence Analysis")

        s1, s2, s3 = st.columns(3)

        with s1:
            st.markdown("<div class='score-title'>RAG Score</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='score-value'>{format_score(rag_score)}</div>", unsafe_allow_html=True)
            st.markdown(
                (
                    "<div class='bar-track'>"
                    f"<div class='bar-fill bar-rag' style='width: {min(max(rag_score, 0.0), 100.0):.2f}%;'></div>"
                    "</div>"
                ),
                unsafe_allow_html=True,
            )

        with s2:
            st.markdown("<div class='score-title'>Rule-based Score</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='score-value'>{format_score(rule_score)}</div>", unsafe_allow_html=True)
            st.markdown(
                (
                    "<div class='bar-track'>"
                    f"<div class='bar-fill bar-rule' style='width: {min(max(rule_score, 0.0), 100.0):.2f}%;'></div>"
                    "</div>"
                ),
                unsafe_allow_html=True,
            )

        with s3:
            st.markdown("<div class='score-title'>Final Score</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='score-value'>{format_score(final_score)}</div>", unsafe_allow_html=True)
            st.markdown(
                (
                    "<div class='bar-track'>"
                    f"<div class='bar-fill bar-final' style='width: {min(max(final_score, 0.0), 100.0):.2f}%;'></div>"
                    "</div>"
                ),
                unsafe_allow_html=True,
            )

        st.markdown("")
        st.code(score_calc, language="text")

        # ---------------------------
        # EXTERNAL API RESULTS (moved up for visibility)
        # ---------------------------
        if external_api_result and external_api_result.get("enabled"):
            st.markdown("---")
            st.subheader("External Threat Intelligence")
            
            threat_score = external_api_result.get("threat_score", 0)
            summary = external_api_result.get("summary", "")
            
            if threat_score >= 0.5:
                st.error(f"**{summary}**")
            elif threat_score >= 0.25:
                st.warning(summary)
            else:
                st.success(summary)
            
            # Show individual source results
            with st.expander("API Details"):
                for source in external_api_result.get("sources", []):
                    source_name = source.get("source", "Unknown")
                    if source.get("error"):
                        st.markdown(f"- **{source_name}**: Error - {source['error']}")
                    elif source_name == "virustotal":
                        if source.get("malicious"):
                            st.markdown(f"- **VirusTotal**: MALICIOUS ({source.get('positives', 0)}/{source.get('total', 0)} vendors)")
                        else:
                            st.markdown(f"- **VirusTotal**: Clean")
                    elif source_name == "google_safebrowsing":
                        if not source.get("safe", True):
                            st.markdown(f"- **Google Safe Browsing**: THREATS: {', '.join(source.get('threats', []))}")
                        else:
                            st.markdown(f"- **Google Safe Browsing**: Safe")
                    elif source_name == "abuseipdb":
                        score = source.get("abuse_confidence_score", 0)
                        st.markdown(f"- **AbuseIPDB**: Abuse score {score}%")
                    elif source_name == "urlhaus":
                        if source.get("malicious"):
                            st.markdown(f"- **URLhaus**: MALWARE URL ({source.get('threat_type', 'unknown')})")
                        else:
                            st.markdown(f"- **URLhaus**: Not in malware database")

        # ============================
        # BAR CHART
        # ============================

        st.markdown("---")
        st.subheader("Signal Strength Analysis")

        fig = create_bar_chart(fused_output)
        st.plotly_chart(fig, use_container_width=True)

        top_signals = get_top_signals(fused_output, top_n=2)
        if top_signals:
            signal_summary = ", ".join([f"{name.replace('_', ' ').title()}" for name, _ in top_signals])
            st.caption(f"Primary signals: {signal_summary}")

        # Show signal breakdown details
        fusion_meta = fused_output.get("fusion_meta", {})
        if fusion_meta.get("agreements") or fusion_meta.get("ml_only") or fusion_meta.get("rule_only"):
            with st.expander("Signal Detection Breakdown", expanded=False):
                if fusion_meta.get("agreements"):
                    st.markdown("**ML + Rules Agreement** (boosted confidence):")
                    for sig in fusion_meta["agreements"]:
                        data = fused_output["per_signal_breakdown"].get(sig, {})
                        st.markdown(f"- {sig.replace('_', ' ').title()}: {data.get('score', 0):.2f}")

                if fusion_meta.get("ml_only"):
                    st.markdown("**ML Detection Only**:")
                    for sig in fusion_meta["ml_only"]:
                        data = fused_output["per_signal_breakdown"].get(sig, {})
                        st.markdown(f"- {sig.replace('_', ' ').title()}: {data.get('score', 0):.2f}")

                if fusion_meta.get("rule_only"):
                    st.markdown("**Rule Detection Only**:")
                    for sig in fusion_meta["rule_only"]:
                        data = fused_output["per_signal_breakdown"].get(sig, {})
                        st.markdown(f"- {sig.replace('_', ' ').title()}: {data.get('score', 0):.2f}")

        # ============================

        if risk != "SAFE":
            # ---------------------------
            # WHY FLAGGED
            # ---------------------------

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

            # ---------------------------
            # SIMILAR ATTACK PATTERNS
            # ---------------------------

            st.markdown("---")
            st.subheader("Similar Attack Patterns")
            if similar_patterns:
                for p in similar_patterns:
                    raw_similarity = float(p.get("similarity", 0.0))
                    similarity_pct = round(raw_similarity * 100, 2) if raw_similarity <= 1 else round(raw_similarity, 2)
                    preview = shorten_text(p.get("text", ""), max_len=140)
                    st.markdown(
                        f"- {preview} (Similarity: {similarity_pct:.2f}%)"
                    )
            else:
                st.markdown("- No strong similar attack patterns were retrieved.")

            # ---------------------------
            # DO'S AND DON'TS
            # ---------------------------

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

        # Safe message indicators
        if risk == "SAFE":
            st.markdown("---")
            st.subheader("Why This Message Appears Safe")

            safe_indicators = []

            # Check which signals are inactive
            breakdown = fused_output.get("per_signal_breakdown", {})
            inactive_signals = [name for name, data in breakdown.items() if data.get("score", 0) < 0.15]

            if "urgency" in inactive_signals:
                safe_indicators.append("No urgent or time-pressure language detected")
            if "fear_threat" in inactive_signals:
                safe_indicators.append("No threatening or fear-inducing content")
            if "impersonation" in inactive_signals:
                safe_indicators.append("No suspicious identity claims")
            if "authority" in inactive_signals:
                safe_indicators.append("No coercive authority language")
            if "reward_lure" in inactive_signals:
                safe_indicators.append("No suspicious reward or prize claims")

            # Additional safe indicators based on low overall confidence
            if rag_score < 25:
                safe_indicators.append("Low semantic similarity to known attack patterns")
            if rule_score < 25:
                safe_indicators.append("No significant behavioral red flags")

            if safe_indicators:
                for indicator in safe_indicators[:5]:
                    st.markdown(f"- {indicator}")
            else:
                st.markdown("- Message passed all safety checks")


# ---------------------------
# SIDEBAR
# ---------------------------

with st.sidebar:
    # Custom CSS for sidebar styling
    st.markdown("""
    <style>
    /* Toggle styling - larger and more prominent */
    div[data-testid="stToggle"] {
        background-color: #1a1a2e;
        padding: 16px 20px;
        border-radius: 10px;
        border: 2px solid #3d5a80;
        margin: 12px 0;
    }
    div[data-testid="stToggle"] label {
        font-size: 1.15rem !important;
        font-weight: 600 !important;
    }
    div[data-testid="stToggle"] label > div {
        transform: scale(1.3);
    }
    /* Status indicator styling */
    .api-status-ok { color: #4ade80; font-weight: 600; }
    .api-status-off { color: #f87171; font-weight: 600; }
    .sidebar-section { 
        background: #1a1a2e; 
        padding: 12px 16px; 
        border-radius: 8px; 
        margin: 8px 0;
        border-left: 3px solid #3d5a80;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("## Settings")
    
    # =====================
    # SECTION 1: Privacy & API Toggle
    # =====================
    if API_AVAILABLE:
        api_status = get_api_status()
        
        use_external_api = st.toggle(
            "Enable External API Checks",
            value=False,
            help="Query threat intelligence APIs for URL verification"
        )
        st.session_state["use_external_api"] = use_external_api
        
        # Dynamic privacy status based on toggle
        if use_external_api:
            st.warning("**External Mode** — URLs sent to threat intelligence APIs")
        else:
            st.success("**Privacy Mode Active** — All analysis runs locally")
        
        # API Status Display (only when enabled)
        if use_external_api:
            st.markdown("#### API Status")
            
            vt_ok = api_status["virustotal"]["configured"]
            gsb_ok = api_status["google_safebrowsing"]["configured"]
            aip_ok = api_status["abuseipdb"]["configured"]
            
            # Color-coded status using HTML
            vt_color = "#4ade80" if vt_ok else "#f87171"
            gsb_color = "#4ade80" if gsb_ok else "#f87171"
            aip_color = "#4ade80" if aip_ok else "#f87171"
            uh_color = "#4ade80"  # URLhaus is always available (free, no key)
            
            st.markdown(f"""
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.9rem;">
                <span><span style="color: {vt_color}; font-size: 1.2em;">●</span> VirusTotal</span>
                <span><span style="color: {gsb_color}; font-size: 1.2em;">●</span> SafeBrowsing</span>
                <span><span style="color: {aip_color}; font-size: 1.2em;">●</span> AbuseIPDB</span>
                <span><span style="color: {uh_color}; font-size: 1.2em;">●</span> URLhaus</span>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.session_state["use_external_api"] = False
        st.success("**Privacy Mode Active** — All analysis runs locally")
        st.caption("API module not available")
    
    st.markdown("---")
    
    # =====================
    # SECTION 2: System Information
    # =====================
    with st.expander("System Information", expanded=False):
        st.markdown("""
        **Detection Engine**
        - RAG/ML: Semantic analysis (60%)
        - Rules: Pattern matching (40%)
        - Ensemble: Weighted fusion
        
        **Risk Thresholds**
        - HIGH: 75-100%
        - POTENTIAL: 50-74%
        - LOW: 25-49%
        - SAFE: 0-24%
        """)
        st.markdown(f"**Knowledge Base:** {len(SOCIAL_ENGINEERING_DATASET)} patterns")
    
    # =====================
    # SECTION 3: Export (only if analysis exists)
    # =====================
    if "last_analysis" in st.session_state:
        st.markdown("---")
        st.markdown("#### Export Report")

        analysis = st.session_state["last_analysis"]
        original_msg = analysis.get("message", "")
        
        # Get external_api_result if it exists in session
        ext_api = st.session_state.get("external_api_result", None)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "message": original_msg[:200],
            "risk_level": analysis.get("risk_level"),
            "attack_type": analysis.get("attack_type", ""),
            "categories": analysis.get("categories"),
            "overall_confidence": analysis.get("overall_confidence"),
            "confidence": {
                "rag": analysis.get("rag_confidence"),
                "rule": analysis.get("rule_confidence"),
                "overall": analysis.get("overall_confidence"),
            },
            "signals": {
                name: {
                    "score": data.get("score"),
                    "strength": data.get("strength"),
                    "ml_boosted": data.get("ml_boosted", False),
                }
                for name, data in analysis.get("signal_breakdown", {}).items()
            },
            "context": analysis.get("context", {}),
            "fusion_metadata": analysis.get("fusion_meta", {}),
            "why_flagged": analysis.get("why_flagged", []),
            "similar_attack_patterns": analysis.get("similar_attack_patterns", []),
            "external_api": ext_api,
        }

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        json_data = get_json_data(report)
        csv_data = get_csv_data(report)
        pdf_data = get_pdf_data(report, original_msg)

        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.download_button(
                label="JSON",
                data=json_data,
                file_name=f"report_{timestamp}.json",
                mime="application/json",
            )
        
        with col2:
            st.download_button(
                label="CSV",
                data=csv_data,
                file_name=f"report_{timestamp}.csv",
                mime="text/csv",
            )
        
        with col3:
            st.download_button(
                label="PDF",
                data=pdf_data,
                file_name=f"report_{timestamp}.pdf",
                mime="application/pdf",
            )
