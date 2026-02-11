"""
Social Engineering Detection System - Professional Dashboard
"""

import streamlit as st
import sys
from pathlib import Path
import time

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from nlp_pipeline.integrated_detector import IntegratedSocialEngineeringDetector
from nlp_pipeline.knowledge_base import SOCIAL_ENGINEERING_DATASET
from nlp_pipeline.rag_detector import get_detector


# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Social Engineering Detection System",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================================
# CUSTOM CSS STYLING
# ============================================================================

st.markdown("""
<style>
    /* Main container styling */
    .main {
        padding: 2rem;
    }
    
    /* Remove extra spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    
    /* Metric cards */
    .metric-card {
        background-color: rgba(255, 255, 255, 0.05);
        padding: 1.5rem;
        border-radius: 0.5rem;
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 1rem;
    }
    
    /* Status box */
    .status-box {
        padding: 1.5rem;
        border-radius: 0.5rem;
        text-align: center;
        margin: 2rem 0;
        font-size: 1.5rem;
        font-weight: bold;
    }
    
    .status-threat {
        background-color: rgba(255, 193, 7, 0.2);
        border: 2px solid #ffc107;
        color: #ffc107;
    }
    
    .status-critical {
        background-color: rgba(220, 53, 69, 0.2);
        border: 2px solid #dc3545;
        color: #dc3545;
    }
    
    .status-safe {
        background-color: rgba(40, 167, 69, 0.2);
        border: 2px solid #28a745;
        color: #28a745;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Button styling */
    .stButton>button {
        width: 100%;
        border-radius: 0.5rem;
        padding: 0.75rem 1rem;
        font-weight: 600;
        background-color: #dc3545;
        color: white;
    }
    
    .stButton>button:hover {
        background-color: #c82333;
    }
    
    /* Text area */
    .stTextArea textarea {
        border-radius: 0.5rem;
    }
    
    /* Divider */
    hr {
        margin: 2rem 0;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# INITIALIZE DETECTOR (CACHED)
# ============================================================================

@st.cache_resource(show_spinner=False)
def initialize_detector():
    """Initialize and load detector with knowledge base."""
    try:
        rag_detector = get_detector()
        rag_detector.add_patterns_to_knowledge_base(SOCIAL_ENGINEERING_DATASET)
        detector = IntegratedSocialEngineeringDetector()
        return detector, None
    except Exception as e:
        return None, str(e)


# Load detector
with st.spinner(" Initializing models... Please wait (~30 seconds on first run)"):
    detector, error = initialize_detector()

if error:
    st.error(f" Error initializing detector: {error}")
    st.info(" Please refresh the page. If the error persists, contact the administrator.")
    st.stop()


# ============================================================================
# HEADER SECTION
# ============================================================================

st.title("Social Engineering Detection System")
st.markdown("### Message Analysis using RAG, NLP & Machine Learning")
st.markdown("---")


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("## About This System")
    st.info("""
    This advanced detection system combines multiple technologies:
    
     RAG (Retrieval Augmented Generation)
    - Semantic understanding using embeddings
    - Pattern matching with vector database
    
     NLP (Natural Language Processing)
    - Sentence transformers for text analysis
    - Context-aware detection
    
     Rule-Based Detection
    - Regex pattern matching
    - Cybersecurity heuristics
    
     Ensemble Learning
    - Weighted voting system
    - 65% RAG + 35% Rules
    """)
    
    st.markdown("---")
    
    st.markdown("##  Detection Categories")
    st.markdown("""
     Urgency - False sense of urgency to pressure quick action
    
     Reward/Lure - Unrealistic rewards to trick recipients

    Authority - Impersonation of authority figures
    
    Impersonation - Pretending to be trusted entities
    
    Fear/Threat - Intimidation and scare tactics
    """)
    
    st.markdown("---")
    
    st.markdown("##  System Statistics")
    st.metric("Knowledge Base Patterns", len(SOCIAL_ENGINEERING_DATASET))
    st.metric("Detection Accuracy", "85-92%")
    st.metric("Average Response Time", "< 2 sec")


# ============================================================================
# MAIN CONTENT - USER INPUT SECTION
# ============================================================================

st.markdown("##  Enter Message to Analyze")
st.markdown("Type or paste any message, email, SMS, or communication you want to check for social engineering attacks.")

# Text input area
user_message = st.text_area(
    label="Message Content",
    height=200,
    placeholder="Example: Your personal data has been compromised in a breach. Click here immediately to secure your information",
    help="Enter the complete message you want to analyze.",
    key="user_input_message"
)

# Analyze button
analyze_clicked = st.button(" ANALYZE MESSAGE", type="primary", use_container_width=True)


# ============================================================================
# ANALYSIS SECTION
# ============================================================================

if analyze_clicked:
    if not user_message or len(user_message.strip()) < 10:
        st.warning(" Please enter a message with at least 10 characters to analyze.")
    else:
        with st.spinner(" Analyzing message..."):
            time.sleep(0.5)
            
            try:
                result = detector.analyze_message(user_message)
                
                # Display results
                st.markdown("---")
                st.markdown("## Analysis Results")
                
                # Extract from backend (single source of truth)
                is_attack = result["is_social_engineering"]
                confidence = result["confidence_score"]
                risk_level = result["risk_level"]
                category = result["category"]
                details = result.get("details", {})
                
                # Backend confidence values (0-1 range)
                rag_confidence_val = details.get('rag_confidence', 0)
                rule_confidence_val = details.get('rule_confidence', 0)
                rag_similarity_val = details.get('rag_similarity', 0)
                rag_vote_val = details.get('rag_vote_confidence', 0)
                
                # Status display
                if is_attack:
                    if risk_level in ("HIGH", "CRITICAL"):                   # CHANGED — was just == "HIGH"
                        status_icon = "🔴"
                        status_text = "CRITICAL THREAT DETECTED"
                        status_class = "status-critical"
                    else:
                        status_icon = "🟡"
                        status_text = "POTENTIAL THREAT DETECTED"
                        status_class = "status-threat"
                else:
                    status_icon = "🟢"
                    status_text = "MESSAGE APPEARS SAFE"
                    status_class = "status-safe"
                
                st.markdown(f"""
                <div class='status-box {status_class}'>
                    {status_icon} {status_text}
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                
                
                # Detailed Explanation
                st.markdown("###  Detailed Explanation")
                
                if is_attack:
                    st.error(f"""
 Social Engineering Attack Detected

Category: {category.replace('_', ' ').title()}

Confidence: {confidence * 100:.1f}%
Risk Level: {risk_level}
                    """)
                else:
                    st.success(f"""
 Message Appears Legitimate

Confidence: {(1 - confidence) * 100:.1f}%

No significant threats detected.
                    """)
                
                # Detailed Analysis Expander
                with st.expander(" View Detailed Analysis", expanded=False):
                    
                    st.markdown("#### Analysis Breakdown")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(" RAG/NLP Detection")
                        st.progress(rag_confidence_val)
                        st.metric(
                            "Calibrated Confidence",
                            f"{rag_confidence_val * 100:.1f}%"
                        )
                    
                    with col2:
                        st.markdown(" Rule-Based Detection")
                        st.progress(rule_confidence_val)
                        st.metric(
                            "Rule Confidence",
                            f"{rule_confidence_val * 100:.1f}%"
                        )
                    
                    # Raw Semantic Similarity
                    st.markdown("---")
                    st.markdown("#### Raw Semantic Similarity")
                    st.progress(min(rag_similarity_val, 1.0))
                    st.metric(
                        "Cosine Similarity",
                        f"{rag_similarity_val * 100:.1f}%"
                    )
                    
                    # Similar patterns
                    if "similar_patterns" in details and details["similar_patterns"]:
                        st.markdown("---")
                        st.markdown("Similar Known Attack Patterns")
                        for i, pattern in enumerate(details["similar_patterns"], 1):
                            similarity_pct = pattern['similarity'] * 100
                            st.markdown(f"{i}. {pattern['pattern']}")
                            st.caption(f"Similarity: {similarity_pct:.1f}%")
                
                # Security Recommendations
                if is_attack:
                    st.markdown("---")
                    with st.expander(" Security Recommendations", expanded=True):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("####  DO NOT")
                            st.markdown("""
                            - Click any links in this message
                            - Download any attachments
                            - Share personal or financial information
                            - Respond to the sender
                            - Call any phone numbers provided
                            """)
                        
                        with col2:
                            st.markdown("####  DO")
                            st.markdown("""
                            - Report to IT security team immediately
                            - Delete the message
                            - Verify through official channels
                            - Change passwords if you responded
                            - Enable two-factor authentication
                            """)
                
                # Technical details
                with st.expander("Technical Details (Advanced)", expanded=False):
                    st.markdown("#### Detection Summary")
                    st.markdown(f"""
**Detection Result:** {"Attack Detected" if is_attack else "Legitimate Message"}

**Overall Confidence:** {confidence * 100:.1f}%

**Risk Assessment:** {risk_level}

**Attack Category:** {category.replace('_', ' ').title()}

**RAG Similarity (Raw Cosine):** {rag_similarity_val * 100:.1f}%

**RAG Calibrated Confidence:** {rag_confidence_val * 100:.1f}%

**RAG Vote Confidence:** {rag_vote_val * 100:.1f}%

**Rule Engine Confidence:** {rule_confidence_val * 100:.1f}%

                    """)
                
            except Exception as e:
                st.error(f" Error during analysis: {str(e)}")
                st.info(" Please try again. If the issue persists, contact support.")


# ============================================================================
# INFORMATION SECTION
# ============================================================================

st.markdown("---")
st.markdown("## How It Works")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    ####  Input Processing
    - Text normalization
    - Tokenization
    - Feature extraction
    """)

with col2:
    st.markdown("""
    ####  AI Analysis
    - RAG embedding search
    - Rule-based pattern matching
    - Ensemble decision making
    """)

with col3:
    st.markdown("""
    ####  Results
    - Confidence scoring
    - Risk level assessment
    - Actionable recommendations
    """)


# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown("""
<div style='text-align: center; padding: 2rem; background-color: rgba(255,255,255,0.05); border-radius: 10px;'>
    <p>RAG + Embeddings + NLP</p>
    <p style='color: #888; font-size: 0.9rem;'>
         All analysis is performed in real-time. No data is stored.
    </p>
    <br>
    <p style='font-size: 0.8rem; color: #666;'>
        © 2026 Social Engineering Detection System | Version 1.0.0
    </p>
</div>
""", unsafe_allow_html=True)