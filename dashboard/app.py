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

def filter_similar_patterns(similar_patterns, max_items=5, min_similarity=25.0):
    """Filter similar patterns to remove duplicates and low-similarity matches."""
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
        
        # Skip patterns below minimum similarity threshold
        sim_val = similarity_value(item)
        if sim_val < min_similarity:
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


def highlight_suspicious_phrases(text: str, signals: dict) -> str:
    """Highlight suspicious phrases in text based on detected signals."""
    highlighted = text
    
    # Expanded patterns for each signal type - more comprehensive coverage
    highlight_patterns = {
        "urgency": [
            r"(urgent(?:ly)?|immediate(?:ly)?|right now|act now|within \d+ (?:hour|minute|day|second)s?)",
            r"(expires?|expir(?:ing|ation)|deadline|limited time|hurry|asap|don't delay|don't wait)",
            r"(final warning|final notice|last chance|time(?:-| )sensitive|respond (?:now|today|immediately))",
            r"(must (?:act|respond|verify|confirm)|required (?:now|immediately)|action required)",
            r"(running out|ends (?:today|soon|tonight)|only \d+ (?:left|remaining|hours?|days?)|quick)",
            r"(do it now|immediately|attention|promptly|without delay|crucial|critical time)",
        ],
        "fear_threat": [
            r"(suspended|terminated|legal action|court|police|arrest|frozen|blocked|deactivated)",
            r"(hacked|compromised|breach(?:ed)?|investigation|prosecution|warning|alert)",
            r"(unauthorized|suspicious (?:activity|login|access)|security (?:alert|warning|issue))",
            r"(permanent(?:ly)?|will be (?:closed|locked|deleted|terminated)|restrict(?:ed|ion))",
            r"(consequences|penalty|penalties|violation|violated|failure to comply)",
        ],
        "reward_lure": [
            r"(won|winner|prize|reward|congratulations|lottery|gift card|free|cashback)",
            r"(refund|claim|bonus|selected|lucky|exclusive (?:offer|deal|access))",
            r"(limited (?:offer|deal)|special (?:offer|promotion)|discount|savings)",
            r"(\$\d+|\d+\s*(?:dollars|usd|gbp|euro)|\d+%\s*off|complimentary)",
        ],
        "authority": [
            r"(ceo|cfo|cto|director|manager|executive|president|vice president|vp)",
            r"(it department|security team|admin(?:istrator)?|official|government|federal)",
            r"(irs|fbi|cia|dhs|tax (?:authority|office)|police department)",
            r"(microsoft|apple|google|amazon|paypal|netflix|bank of|wells fargo|chase)",
            r"(hr department|human resources|compliance|legal department|internal)",
        ],
        "impersonation": [
            r"(verify your|confirm your|update your|validate your|authenticate your)",
            r"(click (?:here|below|this link)|log\s*in|sign\s*in|access your)",
            r"(account|password|credentials|security (?:check|code)|identity verification)",
            r"(ssn|social security|credit card|bank (?:account|details)|routing number)",
            r"(reset your|recover your|unlock your|secure your)",
        ],
    }
    
    # Map signal names to CSS classes
    css_classes = {
        "urgency": "highlight-urgent",
        "fear_threat": "highlight-threat",
        "reward_lure": "highlight-reward",
        "authority": "highlight-authority",
        "impersonation": "highlight-impersonation",
    }
    
    # Only highlight active signals
    for signal_name, signal_data in signals.items():
        if signal_data.get("is_active", False) and signal_name in highlight_patterns:
            css_class = css_classes.get(signal_name, "")
            for pattern in highlight_patterns[signal_name]:
                highlighted = re.sub(
                    pattern,
                    f'<span class="{css_class}">\\1</span>',
                    highlighted,
                    flags=re.IGNORECASE
                )
    
    return highlighted


def create_signal_card_html(signal_name: str, score: float, is_active: bool, ml_boosted: bool = False) -> str:
    """Create a styled signal card with icon and animated bar."""
    # Signal icons and colors
    signal_config = {
        "urgency": {"icon": "[U]", "bg": "rgba(255,152,0,0.2)", "label": "Urgency"},
        "fear_threat": {"icon": "[!]", "bg": "rgba(244,67,54,0.2)", "label": "Fear/Threat"},
        "reward_lure": {"icon": "[R]", "bg": "rgba(156,39,176,0.2)", "label": "Reward/Lure"},
        "authority": {"icon": "[A]", "bg": "rgba(33,150,243,0.2)", "label": "Authority"},
        "impersonation": {"icon": "[I]", "bg": "rgba(0,150,136,0.2)", "label": "Impersonation"},
    }
    
    config = signal_config.get(signal_name, {"icon": "[S]", "bg": "rgba(128,128,128,0.2)", "label": signal_name})
    
    # Determine strength class
    if score >= 0.6:
        strength_class = "signal-high"
    elif score >= 0.35:
        strength_class = "signal-medium"
    else:
        strength_class = "signal-low"
    
    # ML boost indicator
    boost_badge = '<span style="font-size: 0.7rem; color: #64b5f6; margin-left: 0.3rem;">+ML</span>' if ml_boosted else ''
    
    pct = min(score * 100, 100)
    
    return f'''
    <div class="signal-card">
        <div class="signal-header">
            <div class="signal-icon" style="background: {config['bg']};">{config['icon']}</div>
            <span class="signal-name">{config['label']}{boost_badge}</span>
            <span class="signal-score">{pct:.0f}%</span>
        </div>
        <div class="signal-bar-track">
            <div class="signal-bar-fill {strength_class}" style="width: {pct}%;"></div>
        </div>
    </div>
    '''


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
    /* ===== GLOBAL THEME ===== */
    :root {
        --primary: #ef4444; /* Red theme */
        --primary-light: #fca5a5;
        --accent: #dc2626;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --safe: #10b981;
        --bg-dark: #000000; /* Dashboard as black */
        --bg-card: #121212;
        --text-primary: #f8fafc;
        --text-muted: #cbd5e1;
        --border-radius: 8px;
        --shadow: 0 4px 15px rgba(0,0,0,0.4);
        --glass-bg: #111111; /* Dark shade for cards */
        --glass-border: #222222;
    }
    
    /* Base layout */
    .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 1200px; }
    .stApp { background-color: var(--bg-dark); }
    
    /* ===== CLEAN MINIMAL CARDS ===== */
    .glass-card {
        background: var(--glass-bg);
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius);
        padding: 1.25rem;
        margin: 0.75rem 0;
        box-shadow: var(--shadow);
    }
    
    /* ===== VERDICT BOX ===== */
    .verdict-box {
        width: 100%;
        padding: 1.5rem 2rem;
        border-radius: var(--border-radius);
        text-align: center;
        border-left: 5px solid;
        transition: all 0.3s ease;
    }
    .verdict-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .verdict-text {
        font-size: 1.6rem;
        font-weight: 800;
        margin: 0 0 0.5rem 0;
        letter-spacing: 0.03em;
    }
    .verdict-meta {
        font-size: 0.95rem;
        margin: 0.25rem 0;
        color: #e2e8f0;
    }
    .verdict-high {
        background: rgba(127, 29, 29, 0.4);
        border-color: #ef4444;
        color: #fca5a5;
    }
    .verdict-high .verdict-text { color: #f87171; }
    .verdict-potential {
        background: rgba(120, 53, 15, 0.4);
        border-color: #f59e0b;
        color: #fcd34d;
    }
    .verdict-potential .verdict-text { color: #fbbf24; }
    .verdict-low {
        background: rgba(30, 58, 138, 0.4);
        border-color: #3b82f6;
        color: #93c5fd;
    }
    .verdict-low .verdict-text { color: #60a5fa; }
    .verdict-safe {
        background: rgba(6, 78, 59, 0.4);
        border-color: #10b981;
        color: #6ee7b7;
    }
    .verdict-safe .verdict-text { color: #34d399; }
    
    /* ===== RISK INDICATOR (shifted right) ===== */
    .risk-indicator {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 1.5rem;
        padding: 1.5rem;
        background: var(--glass-bg);
        border-radius: var(--border-radius);
        border: 1px solid var(--glass-border);
        box-shadow: var(--shadow);
        transition: all 0.3s ease;
    }
    .risk-indicator:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 15px rgba(0,0,0,0.5);
        border-color: #475569;
    }

    .risk-score {
        font-size: 2.5rem;
        font-weight: 800;
        line-height: 1;
    }
    .risk-label {
        font-size: 0.85rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.1em;
    }
    .risk-bar {
        flex: 1;
        max-width: 200px;
    }
    .risk-bar-track {
        height: 8px;
        background: rgba(255,255,255,0.1);
        border-radius: 4px;
        overflow: hidden;
    }
    .risk-bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .risk-high { background: linear-gradient(90deg, #f87171, #ef4444); }
    .risk-potential { background: linear-gradient(90deg, #fbbf24, #f59e0b); }
    .risk-low { background: linear-gradient(90deg, #60a5fa, #3b82f6); }
    .risk-safe { background: linear-gradient(90deg, #34d399, #10b981); }
    
    /* ===== SIGNAL CARDS ===== */
    .signal-card {
        background: var(--glass-bg);
        border: 1px solid var(--glass-border);
        border-radius: 10px;
        padding: 0.85rem 1rem;
        margin: 0.4rem 0;
    }
    .signal-header {
        display: flex;
        align-items: center;
        gap: 0.6rem;
        margin-bottom: 0.4rem;
    }
    .signal-icon {
        width: 28px;
        height: 28px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.85rem;
        font-weight: 700;
    }
    .signal-name { font-weight: 600; font-size: 0.9rem; }
    .signal-score { margin-left: auto; font-weight: 700; font-size: 0.95rem; }
    .signal-bar-track {
        width: 100%;
        height: 6px;
        background: rgba(255,255,255,0.1);
        border-radius: 3px;
        overflow: hidden;
    }
    .signal-bar-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .signal-high { background: linear-gradient(90deg, #f87171, #ef4444); }
    .signal-medium { background: linear-gradient(90deg, #fbbf24, #f59e0b); }
    .signal-low { background: linear-gradient(90deg, #34d399, #10b981); }
    
    /* ===== HIGHLIGHTED TEXT ===== */
    .analyzed-text-box {
        background: #111827; /* Darker distinct background */
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius);
        padding: 1.25rem;
        font-size: 1rem;
        line-height: 1.7;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);
    }
    .highlight-urgent { 
        border-bottom: 2px dashed #fbbf24;
        color: #fde68a;
        font-weight: 500;
    }
    .highlight-threat { 
        border-bottom: 2px dashed #f87171;
        color: #fecaca;
        font-weight: 500;
    }
    .highlight-reward { 
        border-bottom: 2px dashed #a78bfa;
        color: #ddd6fe;
        font-weight: 500;
    }
    .highlight-authority { 
        border-bottom: 2px dashed #60a5fa;
        color: #bfdbfe;
        font-weight: 500;
    }
    .highlight-impersonation { 
        border-bottom: 2px dashed #2dd4bf;
        color: #a7f3d0;
        font-weight: 500;
    }
    
    /* ===== SCORE BARS ===== */
    .score-section {
        background: var(--glass-bg);
        border-radius: var(--border-radius);
        padding: 1rem 1.25rem;
        margin: 0.5rem 0;
        border: 1px solid var(--glass-border);
        transition: all 0.3s ease;
    }
    .score-section:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 15px rgba(0,0,0,0.5);
        border-color: #475569;
    }
    .score-title { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.25rem; }
    .score-value { font-size: 1.25rem; font-weight: 700; margin-bottom: 0.4rem; }
    .bar-track {
        width: 100%;
        height: 6px;
        background: rgba(255,255,255,0.1);
        border-radius: 3px;
        overflow: hidden;
    }
    .bar-fill { height: 100%; border-radius: 3px; transition: width 0.6s ease; }
    .bar-rag { background: linear-gradient(90deg, #60a5fa, #3b82f6); }
    .bar-rule { background: linear-gradient(90deg, #fbbf24, #f59e0b); }
    .bar-final { background: linear-gradient(90deg, #34d399, #10b981); }
    
    /* ===== PATTERN CARDS ===== */
    .pattern-card {
        background: var(--glass-bg);
        border: 1px solid var(--glass-border);
        border-radius: 8px;
        padding: 0.85rem 1rem;
        margin: 0.5rem 0;
    }
    .pattern-similarity {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .sim-high { background: rgba(16,185,129,0.2); color: #34d399; }
    .sim-medium { background: rgba(245,158,11,0.2); color: #fbbf24; }
    .sim-low { background: rgba(148,163,184,0.2); color: #94a3b8; }
    
    /* ===== COMPARISON CARDS ===== */
    .compare-card {
        background: var(--glass-bg);
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius);
        padding: 1.25rem;
        height: 100%;
    }
    .compare-header {
        font-size: 0.85rem;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--glass-border);
    }
    
    /* ===== BUTTONS ===== */
    #MainMenu, footer { visibility: hidden; }
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        padding: 0.8rem 1.5rem;
        font-weight: 600;
        font-size: 0.95rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        transition: all 0.3s ease;
        background: #1e1e1e; /* Dark button bg */
        color: #f8fafc;
        border: 1px solid #333333;
    }
    .stButton>button[kind="primary"] {
        background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
        box-shadow: 0 4px 10px rgba(239, 68, 68, 0.2);
    }
    .stButton>button:hover { 
        transform: translateY(-2px); 
        box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
        background: #991b1b;
        color: #ffffff;
    }
    
    /* ===== EXPANDER STYLING ===== */
    .streamlit-expanderHeader { background: var(--glass-bg); border-radius: 8px; }
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
# HEADER (Clean minimal title)
# ---------------------------

st.title("Social Engineering Detection")
st.caption("RAG + NLP + Rule Engine | Weighted Ensemble (0.6 RAG / 0.4 Rules) | Privacy-First")


# ---------------------------
# SIDEBAR: SETTINGS
# ---------------------------



# ---------------------------
# SESSION STATE INIT
# ---------------------------

if "simulated_message" not in st.session_state:
    st.session_state.simulated_message = ""
if "comparison_mode" not in st.session_state:
    st.session_state.comparison_mode = False


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

# Comparison mode toggle
comp_cols = st.columns([4, 1])
with comp_cols[1]:
    comparison_mode = st.toggle("Compare", key="comparison_mode", help="Compare two messages side-by-side")

if comparison_mode:
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Message A**")
        msg_a = st.text_area(
            "Message A Content",
            value=st.session_state.simulated_message,
            height=120,
            placeholder="First message to analyze...",
            label_visibility="collapsed"
        )
    with col_b:
        st.markdown("**Message B**")
        msg_b = st.text_area(
            "Message B Content",
            height=120,
            placeholder="Second message to compare...",
            label_visibility="collapsed"
        )
    msg = msg_a  # Primary message for backward compatibility
    
    if st.button("COMPARE MESSAGES", type="primary", use_container_width=True):
        if (not msg_a or len(msg_a.strip()) < 10) or (not msg_b or len(msg_b.strip()) < 10):
            st.warning("Please enter at least 10 characters in both messages.")
        else:
            with st.spinner("Analyzing both messages..."):
                time.sleep(0.2)
                
                # Analyze Message A
                r_a = detector.analyze_message(msg_a)
                rule_a = analyze_text(msg_a)
                fused_a = fuse_signals(rule_a, r_a["rag_confidence"], r_a.get("categories", []))
                
                # Analyze Message B
                r_b = detector.analyze_message(msg_b)
                rule_b = analyze_text(msg_b)
                fused_b = fuse_signals(rule_b, r_b["rag_confidence"], r_b.get("categories", []))
            
            # Display comparison results
            st.markdown("---")
            st.markdown("<h2 style='text-align: center; margin-bottom: 30px;'> Analysis Comparison</h2>", unsafe_allow_html=True)
            
            comp_col_a, comp_spacer, comp_col_b = st.columns([1, 0.1, 1])
            
            # === MESSAGE A RESULTS ===
            with comp_col_a:
                st.markdown('<div class="compare-header">Message A</div>', unsafe_allow_html=True)
                risk_a = str(r_a.get("risk_level", "SAFE")).strip().upper()
                score_a = float(r_a["overall_confidence"])
                rag_a = float(r_a["rag_confidence"])
                rule_score_a = float(r_a["rule_confidence"])
                risk_color_a = {"SAFE": "safe", "LOW": "low", "POTENTIAL": "potential", "HIGH": "high"}.get(risk_a, "safe")
                cats_a = r_a.get("categories", [])
                cat_label_a = " + ".join(cats_a) if cats_a else "None"
                
                # Verdict box
                st.markdown(f'''
                <div class="verdict-box verdict-{risk_color_a}">
                    <div class="verdict-text">{risk_a} RISK</div>
                    <div class="verdict-meta"><b>Score:</b> {score_a:.1f}%</div>
                    <div class="verdict-meta"><b>Category:</b> {cat_label_a}</div>
                </div>
                ''', unsafe_allow_html=True)
                
                # Confidence scores
                st.markdown(f'''
                <div class="score-section">
                    <div class="score-title">RAG Score</div>
                    <div class="score-value">{rag_a:.1f}%</div>
                    <div class="bar-track"><div class="bar-fill bar-rag" style="width: {min(rag_a, 100):.1f}%;"></div></div>
                </div>
                <div class="score-section">
                    <div class="score-title">Rule Score</div>
                    <div class="score-value">{rule_score_a:.1f}%</div>
                    <div class="bar-track"><div class="bar-fill bar-rule" style="width: {min(rule_score_a, 100):.1f}%;"></div></div>
                </div>
                ''', unsafe_allow_html=True)
                
                # Analyzed text with highlights
                breakdown_a = fused_a.get("per_signal_breakdown", {})
                st.markdown("**Analyzed Text:**")
                if risk_a in ["HIGH", "POTENTIAL"]:
                    highlighted_a = highlight_suspicious_phrases(msg_a, breakdown_a)
                    st.markdown(f'<div class="analyzed-text-box">{highlighted_a}</div>', unsafe_allow_html=True)
                else:
                    # Reserve visual space so both comparison charts stay aligned.
                    st.markdown('<div class="analyzed-text-box">&nbsp;</div>', unsafe_allow_html=True)
                
                # Bar chart
                st.markdown("**Signal Analysis:**")
                fig_a = create_bar_chart(fused_a)
                st.plotly_chart(fig_a, use_container_width=True, key="chart_a")
            
            with comp_col_b:
                st.markdown('<div class="compare-header">Message B</div>', unsafe_allow_html=True)
                risk_b = str(r_b.get("risk_level", "SAFE")).strip().upper()
                score_b = float(r_b["overall_confidence"])
                rag_b = float(r_b["rag_confidence"])
                rule_score_b = float(r_b["rule_confidence"])
                risk_color_b = {"SAFE": "safe", "LOW": "low", "POTENTIAL": "potential", "HIGH": "high"}.get(risk_b, "safe")
                cats_b = r_b.get("categories", [])
                cat_label_b = " + ".join(cats_b) if cats_b else "None"
                
                # Verdict box
                st.markdown(f'''
                <div class="verdict-box verdict-{risk_color_b}">
                    <div class="verdict-text">{risk_b} RISK</div>
                    <div class="verdict-meta"><b>Score:</b> {score_b:.1f}%</div>
                    <div class="verdict-meta"><b>Category:</b> {cat_label_b}</div>
                </div>
                ''', unsafe_allow_html=True)
                
                # Confidence scores
                st.markdown(f'''
                <div class="score-section">
                    <div class="score-title">RAG Score</div>
                    <div class="score-value">{rag_b:.1f}%</div>
                    <div class="bar-track"><div class="bar-fill bar-rag" style="width: {min(rag_b, 100):.1f}%;"></div></div>
                </div>
                <div class="score-section">
                    <div class="score-title">Rule Score</div>
                    <div class="score-value">{rule_score_b:.1f}%</div>
                    <div class="bar-track"><div class="bar-fill bar-rule" style="width: {min(rule_score_b, 100):.1f}%;"></div></div>
                </div>
                ''', unsafe_allow_html=True)
                
                # Analyzed text with highlights
                breakdown_b = fused_b.get("per_signal_breakdown", {})
                st.markdown("**Analyzed Text:**")
                if risk_b in ["HIGH", "POTENTIAL"]:
                    highlighted_b = highlight_suspicious_phrases(msg_b, breakdown_b)
                    st.markdown(f'<div class="analyzed-text-box">{highlighted_b}</div>', unsafe_allow_html=True)
                else:
                    # Reserve visual space so both comparison charts stay aligned.
                    st.markdown('<div class="analyzed-text-box">&nbsp;</div>', unsafe_allow_html=True)
                
                # Bar chart
                st.markdown("**Signal Analysis:**")
                fig_b = create_bar_chart(fused_b)
                st.plotly_chart(fig_b, use_container_width=True, key="chart_b")
            
            # Comparison summary
            st.markdown("---")
            st.subheader("Comparison Summary")
            diff = abs(score_a - score_b)
            
            sum_col1, sum_col2, sum_col3 = st.columns(3)
            with sum_col1:
                st.metric("Message A", f"{score_a:.1f}%", delta=None)
            with sum_col2:
                st.metric("Message B", f"{score_b:.1f}%", delta=None)
            with sum_col3:
                st.metric("Difference", f"{diff:.1f}%", delta=None)
            
            if diff < 5:
                st.info("Both messages have similar risk levels")
            elif score_a > score_b:
                st.warning(f"Message A is more suspicious (+{diff:.1f}%)")
            else:
                st.warning(f"Message B is more suspicious (+{diff:.1f}%)")
            
            # --- External Threat Intelligence in Comparison Mode ---
            urls_a = r_a.get("context", {}).get("url", {}).get("urls", [])
            urls_b = r_b.get("context", {}).get("url", {}).get("urls", [])
            
            if (urls_a or urls_b) and st.session_state.get("use_external_api", False) and API_AVAILABLE:
                st.markdown("<h3 style='text-align: center; margin-top: 50px; margin-bottom: 25px;'>External Threat Intelligence Results</h3>", unsafe_allow_html=True)
                t_col1, t_spacer, t_col2 = st.columns([1, 0.1, 1])
                
                with t_col1:
                    if urls_a:
                        with st.status("Detonating Message A URLs...", expanded=True) as status_a:
                            ext_a = check_url_external(urls_a[0])
                            threat_a = ext_a.get("threat_score", 0)
                            summary_a = ext_a.get("summary", "No intelligence available")
                            recommend_a = ext_a.get("recommendation", "Exercise caution")
                            engines_a = ext_a.get("details", {}).get("malicious", 0)
                            
                            color_a = "#ff4b4b" if threat_a >= 0.5 else "#ffa500" if threat_a >= 0.25 else "#28a745"
                            status_label_a = "DANGEROUS" if threat_a >= 0.5 else "SUSPICIOUS" if threat_a >= 0.25 else "CLEAN"
                            
                            st.markdown(f"""
                                <div style="background: rgba(20,20,30,0.6); padding: 20px; border-radius: 8px; border-left: 5px solid {color_a};">
                                    <div style="color: {color_a}; font-weight: bold; font-size: 0.8em; margin-bottom: 5px;">EXT_INTEL_A // {status_label_a}</div>
                                    <div style="font-size: 1.1em; color: white; margin-bottom: 10px;">{summary_a}</div>
                                    <div style="font-size: 0.9em; color: #888; border-top: 1px solid #333; padding-top: 10px;">
                                        <b>Detections:</b> {engines_a} security engines flagged this<br>
                                        <b>Recommendation:</b> {recommend_a}
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)
                            status_a.update(label="Message A Intel Complete", state="complete")
                    else:
                        st.caption("No URLs detected in Message A")
                        
                with t_col2:
                    if urls_b:
                        with st.status("Detonating Message B URLs...", expanded=True) as status_b:
                            ext_b = check_url_external(urls_b[0])
                            threat_b = ext_b.get("threat_score", 0)
                            summary_b = ext_b.get("summary", "No intelligence available")
                            recommend_b = ext_b.get("recommendation", "Exercise caution")
                            engines_b = ext_b.get("details", {}).get("malicious", 0)
                            
                            color_b = "#ff4b4b" if threat_b >= 0.5 else "#ffa500" if threat_b >= 0.25 else "#28a745"
                            status_label_b = "DANGEROUS" if threat_b >= 0.5 else "SUSPICIOUS" if threat_b >= 0.25 else "CLEAN"
                            
                            st.markdown(f"""
                                <div style="background: rgba(20,20,30,0.6); padding: 20px; border-radius: 8px; border-left: 5px solid {color_b};">
                                    <div style="color: {color_b}; font-weight: bold; font-size: 0.8em; margin-bottom: 5px;">EXT_INTEL_B // {status_label_b}</div>
                                    <div style="font-size: 1.1em; color: white; margin-bottom: 10px;">{summary_b}</div>
                                    <div style="font-size: 0.9em; color: #888; border-top: 1px solid #333; padding-top: 10px;">
                                        <b>Detections:</b> {engines_b} security engines flagged this<br>
                                        <b>Recommendation:</b> {recommend_b}
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)
                            status_b.update(label="Message B Intel Complete", state="complete")
                    else:
                        st.caption("No URLs detected in Message B")

            # Save for export
            comp_summary_text = (
                f"COMPARISON MODE RESULTS:\n"
                f"Message A Risk Score: {score_a:.1f}% | Verdict: {risk_a}\n"
                f"Message B Risk Score: {score_b:.1f}% | Verdict: {risk_b}\n"
                f"Score Difference: {diff:.1f}%\n"
                f"------\n\n"
                f"MESSAGE A (Analysis Result: {risk_a}):\n{msg_a}\n\n"
                f"MESSAGE B (Analysis Result: {risk_b}):\n{msg_b}"
            )
            
            st.session_state["last_analysis"] = {
                "message": comp_summary_text,
                "full_message": comp_summary_text,
                "risk_level": risk_a if score_a > score_b else risk_b,
                "attack_type": r_a.get("attack_type", "") if score_a > score_b else r_b.get("attack_type", ""),
                "categories": list(set(r_a.get("categories", []) + r_b.get("categories", []))),
                "rag_confidence": max(rag_a, rag_b),
                "rule_confidence": max(rule_score_a, rule_score_b),
                "overall_confidence": max(score_a, score_b),
                "signal_breakdown": fused_a.get("per_signal_breakdown", {}) if score_a > score_b else fused_b.get("per_signal_breakdown", {}),
                "fusion_meta": fused_a.get("fusion_meta", {}) if score_a > score_b else fused_b.get("fusion_meta", {}),
                "context": r_a.get("context", {}) if score_a > score_b else r_b.get("context", {}),
                "why_flagged": r_a.get("why_flagged", []) + r_b.get("why_flagged", []),
                "similar_attack_patterns": (r_a.get("similar_attack_patterns", []) if score_a >= score_b else r_b.get("similar_attack_patterns", []))[:5],
            }

else:
    msg = st.text_area(
        "Message Content",
        value=st.session_state.simulated_message,
        height=150,
        placeholder="Your bank account has been suspended. Verify immediately.",
    )

# Only show analyze button when not in comparison mode
if not comparison_mode and st.button("ANALYZE MESSAGE", type="primary", use_container_width=True):
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
        similar_patterns = filter_similar_patterns(top_k_results, max_items=5)
        dos = r.get("dos", [])
        donts = r.get("donts", [])

        # Store for export
        st.session_state["last_analysis"] = {
            "message": msg,
            "full_message": msg,
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
            "similar_attack_patterns": filter_similar_patterns(top_k_results, max_items=5),
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

        # Display verdict box (full width, no gauge)
        risk_bar_class = {"HIGH": "risk-high", "POTENTIAL": "risk-potential", "LOW": "risk-low", "SAFE": "risk-safe"}.get(risk, "risk-safe")
        risk_color = {"HIGH": "#f87171", "POTENTIAL": "#fbbf24", "LOW": "#60a5fa", "SAFE": "#34d399"}.get(risk, "#34d399")
        
        st.markdown(
            f'''<div style="display: flex; gap: 1rem; margin: 1rem 0; align-items: stretch; width: 100%;">
                <div class="verdict-box {verdict_css}" style="flex: 1; margin: 0; display: flex; flex-direction: column; justify-content: center;">
                    <div class="verdict-text">{verdict_text}</div>
                    <div class="verdict-meta"><b>Risk Level:</b> {risk_title} | <b>Score:</b> {final_score:.1f}%</div>
                    <div class="verdict-meta"><b>Category:</b> {cat_label}</div>
                </div>
                <div class="risk-indicator" style="flex: 1; margin: 0; width: auto; max-width: none;">
                    <div>
                        <div class="risk-score" style="color: {risk_color};">{final_score:.0f}%</div>
                        <div class="risk-label">Threat Score</div>
                    </div>
                    <div class="risk-bar" style="flex: 1; max-width: auto; min-width: 150px;">
                        <div class="risk-bar-track">
                            <div class="risk-bar-fill {risk_bar_class}" style="width: {min(final_score, 100):.1f}%;"></div>
                        </div>
                    </div>
                </div>
            </div>''',
            unsafe_allow_html=True,
        )

        # F2: Attack Type Classification
        attack_type = r.get("attack_type")
        if attack_type:
            st.markdown(f"**Attack Type:** {attack_type}")

        # Highlighted message display (show suspicious phrases)
        if attack or risk in ["HIGH", "POTENTIAL"]:
            st.markdown("---")
            st.markdown("**Analyzed Text** — suspicious phrases highlighted:")
            breakdown = fused_output.get("per_signal_breakdown", {})
            highlighted_msg = highlight_suspicious_phrases(msg, breakdown)
            st.markdown(
                f'<div class="analyzed-text-box">{highlighted_msg}</div>',
                unsafe_allow_html=True
            )

        # ---------------------------
        # CONFIDENCE
        # ---------------------------

        st.markdown("---")
        st.subheader("Confidence Analysis")

        s1, s2, s3 = st.columns(3)

        with s1:
            st.markdown(f'''
            <div class="score-section">
                <div class="score-title">RAG Score</div>
                <div class="score-value">{format_score(rag_score)}</div>
                <div class="bar-track"><div class="bar-fill bar-rag" style="width: {min(max(rag_score, 0.0), 100.0):.1f}%;"></div></div>
            </div>''', unsafe_allow_html=True)

        with s2:
            st.markdown(f'''
            <div class="score-section">
                <div class="score-title">Rule-based Score</div>
                <div class="score-value">{format_score(rule_score)}</div>
                <div class="bar-track"><div class="bar-fill bar-rule" style="width: {min(max(rule_score, 0.0), 100.0):.1f}%;"></div></div>
            </div>''', unsafe_allow_html=True)

        with s3:
            st.markdown(f'''
            <div class="score-section">
                <div class="score-title">Final Score</div>
                <div class="score-value">{format_score(final_score)}</div>
                <div class="bar-track"><div class="bar-fill bar-final" style="width: {min(max(final_score, 0.0), 100.0):.1f}%;"></div></div>
            </div>''', unsafe_allow_html=True)

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
                        country = source.get("country_code", "")
                        isp = source.get("isp", "")
                        reports = source.get("total_reports", 0)
                        st.markdown(f"- **AbuseIPDB**: Abuse confidence {score}%")
                        if country or isp:
                            st.markdown(f"  - Location: {country} | ISP: {isp}")
                        if reports > 0:
                            st.markdown(f"  - Total abuse reports: {reports}")

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
                    preview = shorten_text(p.get("text", ""), max_len=160)
                    category = p.get("category", "unknown").replace("_", " ").title()
                    
                    # Determine similarity class
                    if similarity_pct >= 60:
                        sim_class = "sim-high"
                    elif similarity_pct >= 40:
                        sim_class = "sim-medium"
                    else:
                        sim_class = "sim-low"
                    
                    st.markdown(
                        f'''<div class="pattern-card">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                                <span style="font-size: 0.75rem; color: #a0a0a0;">{category}</span>
                                <span class="pattern-similarity {sim_class}">{similarity_pct:.1f}% match</span>
                            </div>
                            <div style="font-size: 0.9rem;">{preview}</div>
                        </div>''',
                        unsafe_allow_html=True
                    )
            else:
                st.markdown("- No strong similar attack patterns were retrieved.")

            # ---------------------------
            # DO'S AND DON'TS
            # ---------------------------

            st.markdown("---")
            st.subheader("Incident Response Protocol")
            
            req_actions = "".join([f"<li style='margin-bottom: 0.5rem;'>{tip}</li>" for tip in dos])
            prohib_actions = "".join([f"<li style='margin-bottom: 0.5rem;'>{tip}</li>" for tip in donts])
            
            st.markdown(f'''
            <div style="display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 1rem;">
                <div style="flex: 1; min-width: 250px; background: var(--glass-bg); border-left: 4px solid #10b981; border-radius: 8px; padding: 1.25rem; box-shadow: var(--shadow);">
                    <h4 style="color: #6ee7b7; margin-top: 0; font-size: 1.1rem; margin-bottom: 1rem;">Required Actions</h4>
                    <ul style="margin: 0; padding-left: 1.2rem; color: var(--text-primary); line-height: 1.6;">
                        {req_actions}
                    </ul>
                </div>
                <div style="flex: 1; min-width: 250px; background: var(--glass-bg); border-left: 4px solid #ef4444; border-radius: 8px; padding: 1.25rem; box-shadow: var(--shadow);">
                    <h4 style="color: #fca5a5; margin-top: 0; font-size: 1.1rem; margin-bottom: 1rem;">Prohibited Actions</h4>
                    <ul style="margin: 0; padding-left: 1.2rem; color: var(--text-primary); line-height: 1.6;">
                        {prohib_actions}
                    </ul>
                </div>
            </div>
            ''', unsafe_allow_html=True)

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
    /* Sidebar base */
    section[data-testid="stSidebar"] {
        background-color: #1a1a1a !important; /* Lighter shade of black / Dark grey for sidebar */
        border-right: 1px solid #333333;
    }
    /* Toggle styling - increased size by 50% */
    div[data-testid="stToggle"] {
        background: #262626;
        padding: 16px 20px;
        border-radius: 10px;
        border: 1px solid #444444;
        margin: 25px 0 !important;
        transform: scale(1.5) !important;
        transform-origin: left center !important;
    }
    div[data-testid="stToggle"] label {
        font-size: 1.1rem !important;
        font-weight: 600 !important;
    }
    /* Status colors */
    .api-status-ok { color: #34d399; font-weight: 600; }
    .api-status-off { color: #f87171; font-weight: 600; }
    .sidebar-info {
        background: rgba(30, 41, 59, 0.6);
        padding: 12px 16px;
        border-radius: 8px;
        margin: 8px 0;
        border-left: 3px solid #3b82f6;
        font-size: 0.9rem;
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.markdown("### Settings")
    
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
            
            st.markdown(f"""
            <div style="display: grid; grid-template-columns: 1fr; gap: 6px; font-size: 0.9rem;">
                <span><span style="color: {vt_color}; font-size: 1.2em;">●</span> VirusTotal</span>
                <span><span style="color: {gsb_color}; font-size: 1.2em;">●</span> Google Safe Browsing</span>
                <span><span style="color: {aip_color}; font-size: 1.2em;">●</span> AbuseIPDB</span>
            </div>
            """, unsafe_allow_html=True)

            if not any([vt_ok, gsb_ok, aip_ok]):
                st.caption("No API keys detected right now. Check .env key names and re-run analysis after saving.")
    else:
        st.session_state["use_external_api"] = False
        st.success("**Privacy Mode Active** — All analysis runs locally")
        st.caption("API module not available")
    
    st.markdown("---")
    
    # =====================
    # SECTION 2: System Information (always expanded)
    # =====================
    st.markdown("#### System Information")
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
        original_msg = (
            analysis.get("full_message")
            or analysis.get("message")
            or analysis.get("context", {}).get("text", {}).get("original", "")
        )
        
        # Get external_api_result if it exists in session
        ext_api = st.session_state.get("external_api_result", None)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "message": original_msg[:200],
            "full_message": original_msg,
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
